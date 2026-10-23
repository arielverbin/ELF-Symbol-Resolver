from __future__ import annotations
import bisect
import functools
import re
from dataclasses import dataclass, replace
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_ida # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.ida.symbols.string import IDAString
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.symbols import VTable

_CLASS_TYPE = re.compile(r"[0-9NSZ]")  # how a class's mangled type starts: its name's length, or N (nested), S (std::), Z (local)
_MOST_OFFSETS = 8                      # vcall and vbase offsets before a table's offset to top, at most


@dataclass(frozen=True)
class _VTable:
    """A class's vtable, parsed: its primary table, then a secondary table for each base past the first."""
    start: int                       # its first word: the primary table's vcall and vbase offsets, or its offset to top
    end: int                         # past its last table's last slot
    name: SymName                    # '_ZTV' and its class's mangled type
    typeinfo: int                    # 0 without RTTI
    address_points: tuple[int, ...]  # where objects point: into the primary table, then into each secondary table

    @property
    def size(self) -> int:
        return self.end - self.start


class IDAVTable(IDASymbol, kind=VTable):
    """
    A C++ class's vtable (Itanium ABI): a primary table, then a secondary table for each
    base past the first (multiple inheritance). Each table is

        [vcall and vbase offsets] [offset to top] [typeinfo] [slot] [slot] ...
        ^ for virtual inheritances                           ^ where objects point

    The primary's offset to top is 0, a secondary's below 0. A slot holds a virtual
    function's pointer, or 0 for an abstract class's destructor. The typeinfo's second
    word points at the class's mangled name (i.e. "N3net7HandlerE").
    """

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to any of its words (a constructor, to where objects point)."""
        members = (
            address for start in self.matches for address in range(start, self._vtables()[start].end)
            if ida_bytes.has_xref(ida_bytes.get_flags(address))
        )
        return self._data_refs(idautils.DataRefsTo, members)

    def references_from(self) -> Iterator[int]:
        """Every address the matches point at: their virtual functions, and their typeinfo."""
        words = (word for start in self.matches for word in idautils.Heads(start, self._vtables()[start].end))
        return self._data_refs(idautils.DataRefsFrom, words)

    @classmethod
    def all(cls) -> Iterable[int]:
        return cls._vtables().keys()

    @classmethod
    def filter_from(cls, addresses: Iterable[int]) -> Iterator[int]:
        starts = list(cls._vtables())
        for address in addresses:
            index = bisect.bisect_right(starts, address) - 1
            if index >= 0 and address < cls._vtables()[starts[index]].end:
                yield starts[index]

    @classmethod
    def names_of(cls, start: int, /) -> tuple[str, ...]:
        """The forms of its name (mangled, and 'vtable for net::Handler'), and its class's: 'net::Handler'."""
        name = cls._vtables()[start].name
        return (*name.forms, name.demangled.removeprefix("vtable for ")) if name.demangled else name.forms

    @classmethod
    def display_name(cls, start: int, /) -> str | None:
        name = cls._vtables()[start].name
        return name.demangled or name.linked

    @classmethod
    def size_of(cls, start: int, /) -> int:
        return cls._vtables()[start].size

    @staticmethod
    @functools.cache  # one IDA has one database open
    def _vtables() -> dict[int, _VTable]:
        """Every vtable, by its start, in address order (see _VTableParser)."""
        return _VTableParser().parse_all()


@dataclass(frozen=True)
class _VTableHeader:
    """
    Where a vtable starts, before its end is known: its first word, where objects point
    into its primary table (past its offset to top and typeinfo), its typeinfo (0 without
    RTTI), and its name ('_ZTV' and its class's mangled type, or the symbol's at its start).
    """
    start: int
    address_point: int
    typeinfo: int
    name: SymName


class _VTableParser:
    """
    Reads the vtables (see IDAVTable) out of the database IDA has open, a pointer-sized
    word at a time: first where each starts (see _headers), then how far each goes (see _parse).
    """

    def __init__(self) -> None:
        self.word = 8 if ida_ida.inf_is_64bit() else 4

    def parse_all(self) -> dict[int, _VTable]:
        """Every vtable with a slot, by its start, in address order: each parsed up to the next one's start at most."""
        headers = sorted(self._headers(), key=lambda header: header.start)
        bounds = [*(header.start for header in headers[1:]), None]
        vtables = (self._parse(header, bound) for header, bound in zip(headers, bounds))
        return {vtable.start: vtable for vtable in vtables if vtable is not None}

    def _headers(self) -> Iterable[_VTableHeader]:
        """
        Every vtable's header: each primary table RTTI leads to (see _rtti_headers); moved
        back, and renamed, where a symbol starts the vtable past vcall and vbase offsets (a
        shared object exports '_ZTV...' and '_ZTC...' ones, and IDA names those whose RTTI
        it parsed); and one for each symbol starting a table without RTTI.
        """
        headers = self._rtti_headers()
        for address, linked in idautils.Names():
            if not linked.startswith(("_ZTV", "_ZTC")) or Region.of(address) is not Region.VARIABLES:
                continue
            name = SymName(linked)
            top = self._offset_to_top_after(address, headers)
            if top is None:
                headers[address] = _VTableHeader(address, address + 2 * self.word, self._read(address + self.word), name)
            elif address <= headers[top].start:
                demangles = name.demangled is not None  # unlike the 'name_0' IDA gives a name already taken
                headers[top] = replace(headers[top], start=address, name=name if demangles else headers[top].name)
        return headers.values()

    def _rtti_headers(self) -> dict[int, _VTableHeader]:
        """Every primary table pointing at a typeinfo (see _typeinfos), by its offset to top: a 0 pointing at nothing."""
        headers = {}
        for typeinfo, mangled in self._typeinfos().items():
            for slot in idautils.DataRefsTo(typeinfo):
                top = slot - self.word
                if Region.of(slot) is Region.VARIABLES and self._read(top) == 0 and not self._points(top):
                    headers[top] = _VTableHeader(top, slot + self.word, typeinfo, SymName(f"_ZTV{mangled}"))
        return headers

    def _typeinfos(self) -> dict[int, str]:
        """
        Every class's typeinfo, by its address, with the class's mangled type: a word before
        a word where variables live pointing at the type's name, a literal that demangles as one.
        """
        typeinfos = {}
        for address, text in IDAString.literals().items():
            mangled = text.removeprefix("*")  # GCC's mark of a type local to its file
            if not _CLASS_TYPE.match(mangled):
                continue
            sources = [source for source in idautils.DataRefsTo(address) if Region.of(source) is Region.VARIABLES]
            if sources and SymName(f"_ZTS{mangled}").demangled is not None:
                typeinfos.update((source - self.word, mangled) for source in sources)
        return typeinfos

    def _offset_to_top_after(self, address: int, headers: dict[int, _VTableHeader]) -> int | None:
        """The offset to top of the table in `headers` starting at `address`, past its vcall and vbase offsets (words pointing at nothing)."""
        for word in range(address, address + _MOST_OFFSETS * self.word, self.word):
            if word in headers:
                return word
            if self._points(word):
                return None
        return None

    def _parse(self, header: _VTableHeader, bound: int | None) -> _VTable | None:
        """
        The vtable `header` starts: its primary table's slots, then each secondary table's
        after them, up to `bound` at most. None if it has no slot. Its primary table alone
        may have none: a construction vtable holds 0s for the destructors it never calls.
        """
        end = self._slots_end(header.address_point, bound)
        address_points = [header.address_point]
        while (address_point := self._secondary_at(end, header.typeinfo, bound)) is not None:
            slots_end = self._slots_end(address_point, bound)
            if slots_end == address_point:
                break
            address_points.append(address_point)
            end = slots_end
        return _VTable(header.start, end, header.name, header.typeinfo, tuple(address_points)) if end > header.address_point else None

    def _secondary_at(self, address: int, typeinfo: int, bound: int | None) -> int | None:
        """
        Where objects point in the secondary table starting at `address`: past its vcall and
        vbase offsets (words pointing at nothing), its offset to top (below 0), and `typeinfo`.
        None if no secondary table of the vtable starts there.
        """
        for top in range(address, address + _MOST_OFFSETS * self.word, self.word):
            if self._past(top + 2 * self.word, bound) or self._points(top):
                return None
            if self._read(top) >= 1 << 8 * self.word - 1 and self._read(top + self.word) == typeinfo:
                return top + 2 * self.word
        return None

    def _slots_end(self, address_point: int, bound: int | None) -> int:
        """
        Where the slots starting at `address_point` end, at `bound` at most. Nothing refers
        to a slot: where something refers into a table past where objects point, another
        object starts.
        """
        end = address_point
        while not self._past(end + self.word, bound) and (end == address_point or not self._referred_to(end)):
            if self._points_at_function(self._read(end)):
                end += self.word
            elif (past := self._destructors_end(end, bound)) is not None:
                end = past
            else:
                break
        return end

    def _destructors_end(self, address: int, bound: int | None) -> int | None:
        """
        Where the 0s starting at `address` end, if they are an abstract class's destructors:
        one or two, then a slot, or another object (at `bound`, or a word something refers to).
        """
        past = address
        while not self._past(past + self.word, bound) and past - address < 2 * self.word and self._read(past) == 0:
            past += self.word
        if past == address:
            return None
        if past == bound or self._referred_to(past) or self._points_at_function(self._read(past)):
            return past
        return None

    def _points_at_function(self, value: int) -> bool:
        """True for a virtual function's pointer: to an own function's entry (or one past it: Thumb), or to an import (__cxa_pure_virtual)."""
        region = Region.of(value)
        return region in (Region.PLT, Region.EXTERN) or region is Region.OWN_CODE and IDAFunction.function_of(value) in (value, value & ~1)

    def _points(self, address: int) -> bool:
        """True if the word at `address` points at something, as IDA sees it."""
        return next(iter(idautils.DataRefsFrom(address)), None) is not None

    def _referred_to(self, address: int) -> bool:
        """True if something refers to `address`."""
        return ida_bytes.has_xref(ida_bytes.get_flags(address))

    @staticmethod
    def _past(address: int, bound: int | None) -> bool:
        """True if `address` lies past `bound` (None: no bound)."""
        return bound is not None and address > bound

    def _read(self, address: int) -> int:
        """The word at `address`, unsigned."""
        return ida_bytes.get_qword(address) if self.word == 8 else ida_bytes.get_dword(address)
