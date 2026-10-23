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
from elfresolver.symbols import PLTEntry


@dataclass(frozen=True)
class _Import:
    """The import a PLT stub jumps to: where IDA put it, and its name."""
    address: int
    name: SymName


class IDAPLTEntry(IDAFunction, kind=PLTEntry):
    """The PLT stub of an imported function, named by the import's demangled name: in full, or without its parameter list."""

    @classmethod
    def calls_from(cls, entries: Iterable[int]) -> Iterator[int]:
        """Nothing: a stub only jumps to its import, which is no function of the binary's own."""
        return iter(())

    def references_to(self) -> Iterator[int]:
        """
        Every address referring to one of the matches: to its stub, or to its import
        (PIC code taking an import's address loads it from the GOT, whose slot points at the import).
        """
        return self._data_refs(idautils.DataRefsTo, (address for stub in self.matches for address in (stub, self._imports()[stub].address)))

    def references_from(self) -> Iterator[int]:
        """Nothing: a stub only loads its import's GOT slot."""
        return iter(())

    @classmethod
    def all(cls) -> Iterable[int]:
        return cls._imports().keys()

    @classmethod
    def filter_from(cls, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := cls.function_of(address)) in cls._imports():
                yield entry

    @classmethod
    def names_of(cls, stub: int, /) -> tuple[str, ...]:
        return cls._imports()[stub].name.forms

    @classmethod
    def display_name(cls, stub: int, /) -> str | None:
        name = cls._imports()[stub].name
        return name.demangled or name.linked

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
