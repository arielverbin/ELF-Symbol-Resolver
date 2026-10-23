from __future__ import annotations
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import GlobalVar


class IDAGlobalVar(IDASymbol, kind=GlobalVar):
    """A global variable: a data item where variables live, other than a string literal."""

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to any of its members, too."""
        members = (
            address for head in self.resolve() for address in range(head, ida_bytes.get_item_end(head))
            if ida_bytes.has_xref(ida_bytes.get_flags(address))
        )
        return self._data_refs(idautils.DataRefsTo, members)

    def references_from(self) -> Iterator[int]:
        """
        Every address the matches point at: an initialized variable may hold pointers, a .bss
        one holds none yet. IDA keeps an item's references from its head, whichever of its
        words holds the pointer.
        """
        initialized = (head for head in self.resolve() if ida_bytes.is_loaded(head))  # get_flags() has no FF_IVL to tell
        return self._data_refs(idautils.DataRefsFrom, initialized)

    def all(self) -> Iterator[int]:
        for segment in Region.VARIABLES.segments():
            yield from (head for head in idautils.Heads(segment.start_ea, segment.end_ea) if self._is_variable(head))
        # A global IDA left untyped, as one only code reaching through the GOT refers to, isn't a head: its name tells it.
        yield from (
            address for address, _ in idautils.Names()
            if Region.of(address) is Region.VARIABLES and ida_bytes.is_unknown(ida_bytes.get_flags(address))
        )

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            head = ida_bytes.get_item_head(address)
            if Region.of(head) is Region.VARIABLES and self._is_variable(head):
                yield head

    def describe(self, head: int, /) -> ResolvedSymbol:
        return self.found(head, ida_name.get_name(head) or None, ida_bytes.get_item_size(head))

    @staticmethod
    def _is_variable(head: int) -> bool:
        """
        True for the item at `head` (where variables live) if it is a variable's: data
        other than a string literal, or bytes IDA left untyped, as an object code only
        takes the address of. A switch's table of case addresses is none: data whose
        every pointer lands inside a function, never on its entry (nor one past it: a
        Thumb function's pointer).
        """
        flags = ida_bytes.get_flags(head)
        if ida_bytes.is_unknown(flags):
            return True
        if not ida_bytes.is_data(flags) or ida_bytes.is_strlit(flags):
            return False
        targets = list(idautils.DataRefsFrom(head))  # all of the item's (see references_from)
        return not targets or any(
            Region.of(target) is not Region.OWN_CODE or IDAFunction.function_of(target) in (target, target & ~1)  # (x86's may be odd)
            for target in targets
        )
