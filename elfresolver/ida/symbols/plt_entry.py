from __future__ import annotations
import functools
from dataclasses import dataclass
from typing import Iterable, Iterator
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.protocol.messages import ResolvedSymbol


@dataclass(frozen=True)
class _Import:
    """The import a PLT stub jumps to: where IDA put it, and its name."""
    address: int
    name: SymName


class IDAPLTEntry(IDAFunction):
    """The PLT stub of an imported function, named by the import's demangled name: in full, or without its parameter list."""

    def calls_from(self) -> Iterator[int]:
        """Nothing: a stub only jumps to its import, which is no function of the binary's own."""
        return iter(())

    def references_to(self) -> Iterator[int]:
        """
        Every address referring to one of the matches: to its stub, or to its import
        (PIC code taking an import's address loads it from the GOT, whose slot points at the import).
        """
        return self._data_refs(idautils.DataRefsTo, (address for stub in self.resolve() for address in (stub, self._imports()[stub].address)))

    def references_from(self) -> Iterator[int]:
        """Nothing: a stub only loads its import's GOT slot."""
        return iter(())

    def all(self) -> Iterable[int]:
        return self._imports().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := self.function_of(address)) in self._imports():
                yield entry

    def names_of(self, stub: int) -> tuple[str, ...]:
        return self._imports()[stub].name.forms

    def describe(self, stub: int) -> ResolvedSymbol:
        name = self._imports()[stub].name
        return self.found(stub, name.demangled or name.linked, ida_funcs.calc_func_size(ida_funcs.get_func(stub)))

    @staticmethod
    @functools.cache  # one IDA has one database open
    def _imports() -> dict[int, _Import]:
        """
        The import of every PLT stub, by the stub's address: what it jumps to, in IDA's
        extern segment. A stub IDA doesn't see as a thunk is followed through its jump's
        GOT slot; one jumping elsewhere is no import's.
        """
        imports = {}
        for stub in (entry for entry in idautils.Functions() if Region.of(entry) is Region.PLT):
            function = ida_funcs.get_func(stub)
            target, _ = ida_funcs.calc_thunk_func_target(function)
            if target == ida_idaapi.BADADDR:
                slots = (slot for head in idautils.Heads(stub, function.end_ea) for slot in idautils.DataRefsFrom(head))
                target = next((pointee for slot in slots for pointee in idautils.DataRefsFrom(slot)), ida_idaapi.BADADDR)
            if Region.of(target) is Region.EXTERN:
                linked = ida_name.get_name(target).partition("@")[0]  # without its version: 'recvfrom@GLIBC_2.2.5'
                imports[stub] = _Import(target, SymName(linked.removeprefix("__imp_")))  # IDA's ARM import names have it
        return imports
