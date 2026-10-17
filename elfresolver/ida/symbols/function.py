from __future__ import annotations
from typing import Iterable, Iterator
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import in_own_code
from elfresolver.ida.symbols.symbol import IDASymbol, data_refs_from
from elfresolver.messages import ResolvedSymbol

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles


class IDAFunction(IDASymbol):
    """A function of the binary's own code (an import's PLT stub is an IDAPLTEntry)."""

    def calls(self, callee: IDAFunction) -> Iterable[int]:
        """The functions calling `callee`: directly, by a tail jump, or through a local thunk."""
        return self.owners(callee.calls_to())

    def called_by(self, caller: IDAFunction) -> Iterable[int]:
        """The functions `caller` calls or tail-jumps to, past any local thunks."""
        return self.owners(caller.calls_from())

    # What calls the matches, and what they call and refer to: from any of their instructions.

    def calls_to(self) -> Iterator[int]:
        """Every instruction calling one of the matches: directly, by a tail jump, or through a local thunk."""
        return _callers(self.resolve())

    def calls_from(self) -> Iterator[int]:
        """Every function the matches call or tail-jump to, past any local thunks."""
        return _callees(_heads_of(self.resolve()))

    def references_from(self) -> Iterator[int]:
        """Every address the matches refer to, from any of their instructions (or the data inside them: an ARM literal pool)."""
        return data_refs_from(_heads_of(self.resolve()))

    def all(self) -> Iterable[int]:
        return (entry for entry in idautils.Functions() if in_own_code(entry))

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := entry_of(address)) is not None and in_own_code(entry):
                yield entry

    def describe(self, entry: int) -> ResolvedSymbol:
        return self.found(entry, ida_funcs.get_func_name(entry), ida_funcs.calc_func_size(ida_funcs.get_func(entry)))


def entry_of(address: int) -> int | None:
    """The entry of the function `address` belongs to (in any of its chunks), if one does."""
    function = ida_funcs.get_func(address)
    return function.start_ea if function is not None else None


def is_entry(address: int) -> bool:
    return entry_of(address) == address


def _heads_of(entries: Iterable[int]) -> Iterator[int]:
    """Every head of the functions at `entries`, in all their chunks: their instructions, and the data inside them."""
    for entry in entries:
        for start, end in idautils.Chunks(entry):
            yield from idautils.Heads(start, end)


def _callers(entries: Iterable[int]) -> Iterator[int]:
    """The code calling or tail-jumping to the functions at `entries`, directly or through a local thunk."""
    for entry in entries:
        for xref in idautils.XrefsTo(entry):
            if _is_call(xref):
                yield xref.frm
                if (thunk := _local_thunk_at(xref.frm)) is not None:
                    yield from _callers([thunk])


def _callees(addresses: Iterable[int]) -> Iterator[int]:
    """The functions the code at `addresses` calls or tail-jumps to, past any local thunks."""
    for address in addresses:
        for xref in idautils.XrefsFrom(address):
            if _is_call(xref):
                yield _past_thunks(xref.to)


def _is_call(xref: idautils._xref) -> bool:
    """True for a call, and for a jump to another function's entry: a tail call (never for data, nor for flowing on)."""
    if xref.type in _CALLS:
        return True
    return xref.type in _JUMPS and is_entry(xref.to) and entry_of(xref.frm) != xref.to


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
    if function is None or not function.flags & ida_funcs.FUNC_THUNK or not in_own_code(function.start_ea):
        return None
    return function.start_ea
