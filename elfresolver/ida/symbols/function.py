from __future__ import annotations
import logging
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import in_own_code
from elfresolver.ida.symbols.symbol import IDASymbol, data_refs_from
from elfresolver.messages import ResolvedSymbol

logger = logging.getLogger(__name__)

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles
_PC_THUNK_REGISTERS = (0x04, 0x0C, 0x14, 0x1C, 0x2C, 0x34, 0x3C)  # ModRM bytes of `mov eax..edi, [esp]`


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


def separate_tail_called_functions() -> None:
    """
    Make a function of its own of every function IDA folded into its caller, as one
    of its chunks, because the caller only ever tail-jumps to it (aarch64 at -O2:
    read_request ends in `b parse_request`). Such a chunk is where the jump ending
    another chunk of the same function lands. Once separate, that jump is a tail call.
    """
    for entry in list(idautils.Functions()):
        chunks = list(idautils.Chunks(entry))
        if len(chunks) < 2:
            continue
        tails = {start for start, _ in chunks} - {entry}
        for start, end in chunks:
            if not (heads := list(idautils.Heads(start, end))):
                continue
            for xref in idautils.XrefsFrom(heads[-1]):
                if xref.type in _JUMPS and xref.to in tails and ida_funcs.remove_func_tail(ida_funcs.get_func(entry), xref.to):
                    ida_funcs.add_func(xref.to)
                    logger.debug("Made a function of %#x, which IDA had folded into %#x", xref.to, entry)


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
    """
    True for a call, and for a jump to another function's entry: a tail call. Never
    for data, nor for flowing on, nor for a call that only reads the program counter.
    """
    if _is_pc_thunk(xref.to):
        return False
    if xref.type in _CALLS:
        return True
    return xref.type in _JUMPS and is_entry(xref.to) and entry_of(xref.frm) != xref.to


def _is_pc_thunk(address: int) -> bool:
    """True for i686's PC thunk (`__x86.get_pc_thunk.bx`): `mov reg, [esp]; ret`, which PIC code calls for its own address."""
    code = ida_bytes.get_bytes(address, 4)
    return code is not None and code[0] == 0x8B and code[1] in _PC_THUNK_REGISTERS and code[2:] == b"\x24\xc3"


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
