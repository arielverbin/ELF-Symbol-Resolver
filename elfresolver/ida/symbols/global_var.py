from __future__ import annotations
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_name # type: ignore
import ida_segment # type: ignore
import idautils # type: ignore
from elfresolver.ida.symbols.function import IDAFunction
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.messages import ResolvedSymbol

_VARIABLES = (".data", ".bss", ".rodata", ".sdata", ".sbss", ".tdata", ".tbss")  # name prefixes: .data.rel.ro too


class IDAGlobalVar(IDASymbol):
    """A global variable: a data item where variables live, other than a string literal."""

    def all(self) -> Iterator[int]:
        for segment in self.segments():
            yield from (head for head in idautils.Heads(segment.start_ea, segment.end_ea) if _is_variable(head))

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            head = ida_bytes.get_item_head(address)
            if _holds_variables(head) and _is_variable(head):
                yield head

    def describe(self, head: int) -> ResolvedSymbol:
        return self.found(head, ida_name.get_name(head) or None, ida_bytes.get_item_size(head))

    def body(self, head: int) -> Iterable[int]:
        """Every address of the variable that may hold a pointer: all of an initialized one, none of a .bss one."""
        if not ida_bytes.has_value(ida_bytes.get_flags(head)):
            return ()
        return range(head, ida_bytes.get_item_end(head))

    def referable(self, head: int) -> Iterator[int]:
        """Every address of the variable something refers to: referring to one of its members refers to it."""
        return (
            address for address in range(head, ida_bytes.get_item_end(head))
            if ida_bytes.has_xref(ida_bytes.get_flags(address))
        )

    @staticmethod
    def segments() -> Iterator[ida_segment.segment_t]:
        """Every segment global variables and string literals live in."""
        for index in range(ida_segment.get_segm_qty()):
            segment = ida_segment.getnseg(index)
            if ida_segment.get_segm_name(segment).startswith(_VARIABLES):
                yield segment


def _holds_variables(address: int) -> bool:
    return (IDASymbol.segment_name(address) or "").startswith(_VARIABLES)


def _is_variable(head: int) -> bool:
    flags = ida_bytes.get_flags(head)
    return ida_bytes.is_data(flags) and not ida_bytes.is_strlit(flags) and not _is_jump_table(head)


def _is_jump_table(head: int) -> bool:
    """True for a switch's table of case addresses: data whose every reference lands inside a function, never on its entry."""
    targets = [target for address in range(head, ida_bytes.get_item_end(head)) for target in idautils.DataRefsFrom(address)]
    return bool(targets) and all(IDASymbol.in_code(target) and not IDAFunction.is_entry(target) for target in targets)
