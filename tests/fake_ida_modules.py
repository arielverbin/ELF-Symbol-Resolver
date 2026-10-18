"""
Stand-ins for IDA's Python modules, as far as elfresolver uses them, over a
FakeBinary: the database a fake IDA has open (see fakes.py).

install() puts them in sys.modules, so elfresolver's IDA side imports and runs
as it does inside IDA; open() opens a binary in them. The binary is laid out
as IDA would show an ELF:

    .plt     its PLT stubs: thunks of their imports, in `extern`
    .text    its functions
    .rodata  its strings, each a string literal
    .data    its globals, each an initialized data item
    extern   an import for each PLT stub, where IDA puts them

Each symbol is one item, so one head: a function's calls and references all go
from its entry.
"""
from __future__ import annotations
import inspect
import sys
import time
import types
from dataclasses import dataclass, field
from pathlib import Path
from fakes import FakeBinary

_EXTERN = 0x7F000000  # where the imports go: far from any address a test picks
_SEGMENTS = {"Function": ".text", "PLTEntry": ".plt", "String": ".rodata", "GlobalVar": ".data"}

# An item's flags, as get_flags() gives them (for the is_* and has_* functions to read).
_CODE, _DATA, _STRLIT, _VALUE, _XREF = 1, 2, 4, 8, 16


@dataclass(frozen=True)
class Segment:
    """A segment, as ida_segment shows one."""
    name: str
    type: int
    start_ea: int
    end_ea: int

    def size(self) -> int:
        return self.end_ea - self.start_ea


@dataclass(frozen=True)
class Func:
    """A function, as ida_funcs shows one."""
    start_ea: int
    end_ea: int
    flags: int


@dataclass(frozen=True)
class Xref:
    """A cross-reference, as idautils shows one."""
    frm: int
    to: int
    type: int


@dataclass(frozen=True)
class _Item:
    start: int
    size: int
    flags: int
    name: str
    segment: str


@dataclass
class FakeIDA:
    """IDA's API, with `binary` open in it. Its constants are IDA's, its functions those IDA's modules have."""
    binary: FakeBinary
    idb_path: Path | None = None
    xrefs_to_asked: list[int] = field(default_factory=list)  # every address XrefsTo() was asked about, in order

    BADADDR = 0xFFFFFFFFFFFFFFFF
    SEG_XTRN, SEG_CODE, SEG_DATA = 1, 2, 3
    FUNC_THUNK = 0x80
    fl_CF, fl_CN, fl_JF, fl_JN, fl_F = 16, 17, 18, 19, 21
    dr_O = 1
    segment_t = Segment

    def __post_init__(self) -> None:
        self._items: dict[int, _Item] = {}
        self._thunk_targets: dict[int, int] = {}
        for address, symbol in sorted(self.binary.symbols.items()):
            segment = _SEGMENTS[symbol.kind]
            if symbol.kind == "PLTEntry":
                self._thunk_targets[address] = target = _EXTERN + 8 * len(self._thunk_targets)
                self._add(_Item(target, 8, 0, symbol.name or "", "extern"))
                self._add(_Item(address, symbol.size, _CODE | _VALUE, f".{symbol.name}", segment))
            elif symbol.kind == "String":
                self._add(_Item(address, symbol.size, _DATA | _STRLIT | _VALUE, "", segment))
            else:
                flags = _CODE | _VALUE if symbol.kind == "Function" else _DATA | _VALUE
                self._add(_Item(address, symbol.size, flags, symbol.name or "", segment))
        self._xrefs = [Xref(caller, callee, self.fl_CN) for caller, callee in self.binary.calls]
        self._xrefs += [Xref(source, target, self.dr_O) for source, target in self.binary.references]
        self._segments = [self._segment_of(name) for name in dict.fromkeys(item.segment for item in self._items.values())]
        self._bytes = {segment.name: self._bytes_of(segment) for segment in self._segments}

    # ida_auto, ida_loader, ida_nalt, idc, ida_pro: the database as a whole, which a broken one still has

    def auto_wait(self) -> bool:
        return True

    def get_imagebase(self) -> int:
        return self.binary.image_base

    def get_idb_path(self) -> str:
        return str(self.idb_path)

    def save_database(self, path: str, flags: int) -> bool:
        Path(path).write_text(self.binary.to_json())
        return True

    def qexit(self, code: int) -> None:
        raise SystemExit(code)

    # ida_ida

    def inf_get_procname(self) -> str:
        return "metapc"

    def inf_is_64bit(self) -> bool:
        return True

    # ida_segment

    def getseg(self, ea: int) -> Segment | None:
        return next((segment for segment in self._segments if segment.start_ea <= ea < segment.end_ea), None)

    def get_segm_name(self, segment: Segment) -> str:
        return segment.name

    def get_segm_qty(self) -> int:
        return len(self._segments)

    def getnseg(self, index: int) -> Segment:
        return self._segments[index]

    # ida_bytes

    def get_flags(self, ea: int) -> int:
        item = self._items.get(ea)
        referred = any(xref.to == ea for xref in self._xrefs)
        return (item.flags & ~_VALUE if item is not None else 0) | (_XREF if referred else 0)  # as IDA 9's: no byte value

    def is_data(self, flags: int) -> bool:
        return bool(flags & _DATA)

    def is_unknown(self, flags: int) -> bool:
        return not flags & (_CODE | _DATA)

    def is_strlit(self, flags: int) -> bool:
        return bool(flags & _STRLIT)

    def has_xref(self, flags: int) -> bool:
        return bool(flags & _XREF)

    def get_item_head(self, ea: int) -> int:
        item = self._item_at(ea)
        return item.start if item is not None else ea

    def get_item_end(self, ea: int) -> int:
        item = self._item_at(ea)
        return item.start + item.size if item is not None else ea + 1

    def get_item_size(self, ea: int) -> int:
        item = self._item_at(ea)
        return item.size if item is not None else 1

    def is_loaded(self, ea: int) -> bool:
        segment, item = self.getseg(ea), self._item_at(ea)
        return segment is not None and segment.type != self.SEG_XTRN and (item is None or bool(item.flags & _VALUE))

    def get_bytes(self, ea: int, size: int) -> bytes | None:
        segment = self.getseg(ea)
        if segment is None or segment.name not in self._bytes:
            return None
        offset = ea - segment.start_ea
        return bytes(self._bytes[segment.name][offset:offset + size])

    # ida_funcs

    def get_func(self, ea: int) -> Func | None:
        item = self._item_at(ea)
        if item is None or item.segment not in (".text", ".plt"):
            return None
        return Func(item.start, item.start + item.size, self.FUNC_THUNK if item.segment == ".plt" else 0)

    def get_func_name(self, ea: int) -> str:
        function = self.get_func(ea)
        return self._items[function.start_ea].name if function is not None else ""

    def calc_func_size(self, function: Func) -> int:
        return function.end_ea - function.start_ea

    def calc_thunk_func_target(self, function: Func) -> tuple[int, int]:
        return self._thunk_targets.get(function.start_ea, self.BADADDR), self.BADADDR

    # ida_name

    def get_name(self, ea: int) -> str:
        item = self._items.get(ea)
        return item.name if item is not None else ""

    def demangle_name(self, name: str, flags: int) -> str | None:
        return None

    # idautils

    def Functions(self) -> list[int]:
        return sorted(item.start for item in self._items.values() if item.segment in (".text", ".plt"))

    def Chunks(self, entry: int) -> list[tuple[int, int]]:
        function = self.get_func(entry)
        return [(function.start_ea, function.end_ea)] if function is not None else []

    def Names(self) -> list[tuple[int, str]]:
        return sorted((address, item.name) for address, item in self._items.items() if item.name)

    def Heads(self, start: int, end: int) -> list[int]:
        return sorted(head for head in self._items if start <= head < end)

    def XrefsFrom(self, ea: int) -> list[Xref]:
        self._look_up()
        return [xref for xref in self._xrefs if xref.frm == ea]

    def XrefsTo(self, ea: int) -> list[Xref]:
        self._look_up()
        self.xrefs_to_asked.append(ea)
        return [xref for xref in self._xrefs if xref.to == ea]

    def DataRefsFrom(self, ea: int) -> list[int]:
        self._look_up()
        return [xref.to for xref in self._xrefs if xref.frm == ea and xref.type == self.dr_O]

    def DataRefsTo(self, ea: int) -> list[int]:
        self._look_up()
        return [xref.frm for xref in self._xrefs if xref.to == ea and xref.type == self.dr_O]

    def _look_up(self) -> None:
        """A lookup of cross-references: each takes the binary's `delay`, and a broken binary's raises."""
        if self.binary.broken:
            raise RuntimeError("The fake database is broken")
        time.sleep(self.binary.delay)

    def _add(self, item: _Item) -> None:
        self._items[item.start] = item

    def _item_at(self, ea: int) -> _Item | None:
        """The item `ea` lies in."""
        return next((item for item in self._items.values() if item.start <= ea < item.start + item.size), None)

    def _segment_of(self, name: str) -> Segment:
        items = [item for item in self._items.values() if item.segment == name]
        kind = {".text": self.SEG_CODE, ".plt": self.SEG_CODE, "extern": self.SEG_XTRN}.get(name, self.SEG_DATA)
        return Segment(name, kind, min(item.start for item in items), max(item.start + item.size for item in items))

    def _bytes_of(self, segment: Segment) -> bytearray:
        """The segment's content: its strings' text, and zeros elsewhere."""
        content = bytearray(segment.size())
        for address, symbol in self.binary.symbols.items():
            if symbol.kind == "String" and segment.start_ea <= address < segment.end_ea:
                text = (symbol.name or "").encode()
                content[address - segment.start_ea:address - segment.start_ea + len(text)] = text
        return content


_MODULES = {
    "ida_auto": ["auto_wait"],
    "ida_bytes": [
        "get_flags", "is_data", "is_unknown", "is_strlit", "has_xref",
        "get_item_head", "get_item_end", "get_item_size", "is_loaded", "get_bytes",
    ],
    "ida_funcs": ["get_func", "get_func_name", "calc_func_size", "calc_thunk_func_target", "FUNC_THUNK"],
    "ida_ida": ["inf_get_procname", "inf_is_64bit"],
    "ida_idaapi": ["BADADDR"],
    "ida_loader": ["save_database"],
    "ida_nalt": ["get_imagebase"],
    "ida_name": ["get_name", "demangle_name"],
    "ida_pro": ["qexit"],
    "ida_segment": ["getseg", "get_segm_name", "get_segm_qty", "getnseg", "segment_t", "SEG_CODE", "SEG_DATA", "SEG_XTRN"],
    "ida_xref": ["fl_CF", "fl_CN", "fl_JF", "fl_JN", "fl_F", "dr_O"],
    "idautils": ["Functions", "Chunks", "Heads", "Names", "XrefsFrom", "XrefsTo", "DataRefsFrom", "DataRefsTo"],
    "idc": ["get_idb_path"],
}

_opened: FakeIDA | None = None


def install() -> None:
    """Put the stand-in modules in sys.modules: a constant is there at once, a function asks the database open when called."""
    for module_name, names in _MODULES.items():
        module = types.ModuleType(module_name, f"A stand-in for IDA's {module_name} (see fake_ida_modules.py)")
        for name in names:
            value = getattr(FakeIDA, name)
            setattr(module, name, _calling(name) if inspect.isfunction(value) else value)
        sys.modules[module_name] = module


def open(binary: FakeBinary, idb_path: Path | None = None) -> FakeIDA:
    """Open `binary` in the stand-in modules, as a fresh IDA would: with nothing elfresolver cached of another one."""
    global _opened
    _opened = FakeIDA(binary, idb_path)
    for name, module in list(sys.modules.items()):
        if name.startswith("elfresolver.ida."):
            for value in vars(module).values():
                cached = [getattr(value, attribute, None) for attribute in vars(value)] if isinstance(value, type) else [value]
                for function in cached:  # a module's functions, and its classes' (a static method's, as its class gives it)
                    if callable(clear := getattr(function, "cache_clear", None)):
                        clear()
    return _opened


def _calling(name: str):
    def call(*arguments):
        if _opened is None:
            raise RuntimeError("No fake database is open: see fake_ida_modules.open()")
        return getattr(_opened, name)(*arguments)
    call.__name__ = name
    return call
