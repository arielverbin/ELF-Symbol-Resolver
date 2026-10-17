from __future__ import annotations
import functools
from dataclasses import dataclass
from typing import Iterable, Iterator
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_name # type: ignore
import ida_segment # type: ignore
import idautils # type: ignore
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.ida.symbols.symbol import name_forms, without_version
from elfresolver.messages import ResolvedSymbol


class IDAPLTEntry(IDAFunction):
    """The PLT stub of an imported function, named by the import's demangled name: in full, or without its parameter list."""

    def all(self) -> Iterable[int]:
        return _imports().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := self.entry_of(address)) in _imports():
                yield entry

    def names_of(self, stub: int) -> tuple[str, ...]:
        imported = _imports()[stub]
        return name_forms(imported.name, imported.demangled)

    def describe(self, stub: int) -> ResolvedSymbol:
        imported = _imports()[stub]
        return self.found(stub, imported.demangled or imported.name, ida_funcs.calc_func_size(ida_funcs.get_func(stub)))

    def body(self, stub: int) -> Iterable[int]:
        """Nothing: a stub's jump to its import is no call to follow, nor a reference."""
        return ()


@dataclass(frozen=True)
class _Import:
    """The import a PLT stub jumps to: its name as linked (with no version), and demangled, if it is mangled."""
    name: str
    demangled: str | None


@functools.cache  # one IDA has one database open
def _imports() -> dict[int, _Import]:
    """The import of every PLT stub, by the stub's address."""
    imports = {}
    for stub in (entry for entry in idautils.Functions() if IDAPLTEntry.in_plt(entry)):
        if (target := _import_of(stub)) is not None:
            name = without_version(ida_name.get_name(target))
            imports[stub] = _Import(name, ida_name.demangle_name(name, 0))
    return imports


def _import_of(stub: int) -> int | None:
    """Where the import a PLT stub jumps to is, in IDA's extern segment; None if it jumps elsewhere."""
    target, _ = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(stub))
    if target == ida_idaapi.BADADDR:
        # A stub IDA doesn't see as a thunk: follow its jump's GOT slot to the import instead.
        slots = (slot for head in idautils.Heads(stub, ida_funcs.get_func(stub).end_ea) for slot in idautils.DataRefsFrom(head))
        target = next((pointee for slot in slots for pointee in idautils.DataRefsFrom(slot)), ida_idaapi.BADADDR)
    return target if _in_extern(target) else None


def _in_extern(address: int) -> bool:
    """True inside IDA's extern segment, where it puts the imports."""
    segment = ida_segment.getseg(address)
    return segment is not None and segment.type == ida_segment.SEG_XTRN
