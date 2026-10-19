from __future__ import annotations
import bisect
import functools
from dataclasses import dataclass
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_ida # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.ida.symbols.string import IDAString
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import VTable


@dataclass(frozen=True)
class _Table:
    """A vtable group: where it ends (past its secondary tables), and its name ('_ZTV' and its class's mangled type)."""
    end: int
    name: SymName


class IDAVTable(IDASymbol, kind=VTable):
    """
    A C++ class's virtual table (Itanium ABI): offset to top (0), typeinfo, its virtual
    functions' pointers; then each secondary table's (multiple inheritance): a negative
    offset to top, the same typeinfo, and pointers. Objects point past the typeinfo.
    """

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to any of its words (a constructor, to where objects point)."""
        members = (
            address for start in self.resolve() for address in range(start, self._vtables()[start].end)
            if ida_bytes.has_xref(ida_bytes.get_flags(address))
        )
        return self._data_refs(idautils.DataRefsTo, members)

    def references_from(self) -> Iterator[int]:
        """Every address the matches point at: their virtual functions, and their typeinfo."""
        return self._data_refs(idautils.DataRefsFrom, (address for start in self.resolve() for address in range(start, self._vtables()[start].end)))

    def all(self) -> Iterable[int]:
        return self._vtables().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        starts = list(self._vtables())
        for address in addresses:
            index = bisect.bisect_right(starts, address) - 1
            if index >= 0 and address < self._vtables()[starts[index]].end:
                yield starts[index]

    def names_of(self, start: int) -> tuple[str, ...]:
        """The forms of its name (mangled, and 'vtable for net::Handler'), and its class's: 'net::Handler'."""
        name = self._vtables()[start].name
        return (*name.forms, name.demangled.removeprefix("vtable for ")) if name.demangled else name.forms

    def describe(self, start: int) -> ResolvedSymbol:
        table = self._vtables()[start]
        return self.found(start, table.name.demangled or table.name.linked, table.end - start)

    @staticmethod
    @functools.cache  # one IDA has one database open
    def _vtables() -> dict[int, _Table]:
        """
        Every vtable group, by its start, in address order. Each is found through its class's
        RTTI: a typeinfo name (a literal that demangles as one) is pointed at from its
        typeinfo's second word, and the typeinfo from the second word of each vtable whose
        first is 0. A vtable a symbol names ('_ZTV...', as a shared object exports) is
        one too, with RTTI or without.
        """
        word = 8 if ida_ida.inf_is_64bit() else 4
        starts: dict[int, tuple[int, str]] = {}  # each vtable's start: its typeinfo's address, and its '_ZTV' name
        for address, text in IDAString.literals().items():
            if SymName(f"_ZTS{text.removeprefix('*')}").demangled is None:  # '*': GCC's mark of a type local to its file
                continue
            for typeinfo in (source - word for source in idautils.DataRefsTo(address) if Region.of(source) is Region.VARIABLES):
                for slot in idautils.DataRefsTo(typeinfo):
                    start = slot - word
                    if Region.of(slot) is Region.VARIABLES and IDAVTable._word(start) == 0 and not list(idautils.DataRefsFrom(start)):
                        starts[start] = (typeinfo, f"_ZTV{text.removeprefix('*')}")
        for address, name in idautils.Names():
            if name.startswith("_ZTV") and Region.of(address) is Region.VARIABLES:
                starts.setdefault(address, (IDAVTable._word(address + word), name))

        vtables = {}
        for start, (typeinfo, name) in sorted(starts.items()):
            end = start + 2 * word  # past the offset to top and the typeinfo: where objects point
            while True:
                # The next word that isn't 0, past at most two: an abstract class's table has a 0 for each destructor.
                pointer = next((address for address in range(end, end + 3 * word, word) if IDAVTable._word(address) != 0), end)
                target = IDAVTable._word(pointer)
                points_at_function = (
                    Region.of(target) in (Region.PLT, Region.EXTERN)  # an import's, as __cxa_pure_virtual
                    or Region.of(target) is Region.OWN_CODE and IDAFunction.function_of(target) in (target, target & ~1)
                )
                referred_to = any(  # something refers into the table only where objects point: anywhere else, another object starts
                    ida_bytes.has_xref(ida_bytes.get_flags(address)) and IDAVTable._word(address - word) != typeinfo
                    for address in range(end, pointer + word, word)
                )
                if points_at_function and not referred_to:
                    end = pointer + word
                elif pointer == end and target >= 1 << 8 * word - 1 and IDAVTable._word(end + word) == typeinfo:
                    end += 2 * word  # a secondary table's negative offset to top, and the typeinfo again
                else:
                    break
            if end > start + 2 * word:
                vtables[start] = _Table(end, SymName(name))
        return vtables

    @staticmethod
    def _word(address: int) -> int:
        """The pointer-sized word at `address`, unsigned."""
        return ida_bytes.get_qword(address) if ida_ida.inf_is_64bit() else ida_bytes.get_dword(address)
