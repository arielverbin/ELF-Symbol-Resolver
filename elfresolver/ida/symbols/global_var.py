from __future__ import annotations
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import in_own_code, in_variables, variable_segments
from elfresolver.ida.symbols.function import is_entry
from elfresolver.ida.symbols.symbol import IDASymbol, data_refs_from, data_refs_to
from elfresolver.messages import ResolvedSymbol


class IDAGlobalVar(IDASymbol):
    """A global variable: a data item where variables live, other than a string literal."""

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to any of its members, too."""
        return data_refs_to(
            address for head in self.resolve() for address in _bytes_of(head)
            if ida_bytes.has_xref(ida_bytes.get_flags(address))
        )

    def references_from(self) -> Iterator[int]:
        """Every address the matches point at: an initialized variable may hold pointers, a .bss one holds none yet."""
        return data_refs_from(
            address for head in self.resolve() if ida_bytes.has_value(ida_bytes.get_flags(head))
            for address in _bytes_of(head)
        )

    def all(self) -> Iterator[int]:
        for segment in variable_segments():
            yield from (head for head in idautils.Heads(segment.start_ea, segment.end_ea) if _is_variable(head))

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            head = ida_bytes.get_item_head(address)
            if in_variables(head) and _is_variable(head):
                yield head

    def describe(self, head: int) -> ResolvedSymbol:
        return self.found(head, ida_name.get_name(head) or None, ida_bytes.get_item_size(head))


def _bytes_of(head: int) -> range:
    return range(head, ida_bytes.get_item_end(head))


def _is_variable(head: int) -> bool:
    flags = ida_bytes.get_flags(head)
    return ida_bytes.is_data(flags) and not ida_bytes.is_strlit(flags) and not _is_jump_table(head)


def _is_jump_table(head: int) -> bool:
    """True for a switch's table of case addresses: data whose every reference lands inside a function, never on its entry."""
    targets = [target for address in _bytes_of(head) for target in idautils.DataRefsFrom(address)]
    return bool(targets) and all(in_own_code(target) and not is_entry(target) for target in targets)
