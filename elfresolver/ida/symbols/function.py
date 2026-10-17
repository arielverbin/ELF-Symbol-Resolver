from __future__ import annotations
from typing import Iterable, Iterator
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.messages import ResolvedSymbol

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles


class IDAFunction(IDASymbol):
    """A function of the binary's own code (an import's PLT stub is an IDAPLTEntry)."""

    def calls(self, callee: IDAFunction) -> Iterable[int]:
        """The functions calling `callee`: directly, by a tail jump, or through a local thunk."""
        return self.owners(_calls_to(callee.referables()))

    def called_by(self, caller: IDAFunction) -> Iterable[int]:
        """The functions `caller` calls or tail-jumps to, past any local thunks."""
        return self.owners(_calls_from(caller.bodies()))

    def all(self) -> Iterable[int]:
        return (entry for entry in idautils.Functions() if self.in_code(entry))

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := self.entry_of(address)) is not None and self.in_code(entry):
                yield entry

    def describe(self, entry: int) -> ResolvedSymbol:
        return self.found(entry, ida_funcs.get_func_name(entry), ida_funcs.calc_func_size(ida_funcs.get_func(entry)))

    def body(self, entry: int) -> Iterable[int]:
        """Every head of the function's chunks: its instructions, and the data inside it (an ARM literal pool)."""
        for start, end in idautils.Chunks(entry):
            yield from idautils.Heads(start, end)

    @staticmethod
    def entry_of(address: int) -> int | None:
        """The entry of the function `address` belongs to (in any of its chunks), if one does."""
        function = ida_funcs.get_func(address)
        return function.start_ea if function is not None else None

    @staticmethod
    def is_entry(address: int) -> bool:
        return IDAFunction.entry_of(address) == address


def _calls_from(addresses: Iterable[int]) -> Iterator[int]:
    """The functions the code at `addresses` calls or tail-jumps to, past any local thunks."""
    for address in addresses:
        for xref in idautils.XrefsFrom(address):
            if _is_call(xref):
                yield _past_thunks(xref.to)


def _calls_to(entries: Iterable[int]) -> Iterator[int]:
    """The code calling or tail-jumping to the functions at `entries`, directly or through a local thunk."""
    for entry in entries:
        for xref in idautils.XrefsTo(entry):
            if _is_call(xref):
                yield xref.frm
                if (thunk := _local_thunk_at(xref.frm)) is not None:
                    yield from _calls_to([thunk])


def _is_call(xref: idautils._xref) -> bool:
    """True for a call, and for a jump to another function's entry: a tail call (never for data, nor for flowing on)."""
    if xref.type in _CALLS:
        return True
    return xref.type in _JUMPS and IDAFunction.is_entry(xref.to) and IDAFunction.entry_of(xref.frm) != xref.to


def _past_thunks(address: int) -> int:
    """Where a call to `address` ends up: past the local thunks (`j_foo`) on the way."""
    for _ in range(_LONGEST_THUNK_CHAIN):
        if _local_thunk_at(address) != address:
            break
        target, _ = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(address))
        if target == ida_idaapi.BADADDR:
            break
        address = target
    return address


def _local_thunk_at(address: int) -> int | None:
    """The entry of the function `address` belongs to, if that is a thunk in the binary's own code (`j_foo`, not a PLT stub)."""
    function = ida_funcs.get_func(address)
    if function is None or not function.flags & ida_funcs.FUNC_THUNK or not IDASymbol.in_code(function.start_ea):
        return None
    return function.start_ea
