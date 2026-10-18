from __future__ import annotations
import logging
from typing import Callable, Iterable, Iterator
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_ida # type: ignore
import ida_idaapi # type: ignore
import ida_segment # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
import idc # type: ignore
from elfresolver.ida.layout import in_own_code, in_plt
from elfresolver.ida.symbols.symbol import IDASymbol, data_refs_from, data_refs_to
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

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to its entry, or one past it (a Thumb function's pointer has its low bit set)."""
        return data_refs_to(address for entry in self.resolve() for address in dict.fromkeys([entry, entry | 1]))

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


def make_functions_of_thumb_pointers() -> None:
    """Let IDA explore skipped bytes due to Thumb code (32-bit ARM, where such a
    pointer is the address plus one). It solves an issue where IDA doesn't follow main's,
    which _start loads from the GOT: without this, main is no function, and neither is
    any function only main calls."""
    if ida_ida.inf_get_procname() != "ARM" or ida_ida.inf_is_64bit():
        return
    for segment in map(ida_segment.getnseg, range(ida_segment.get_segm_qty())):
        if segment.type in (ida_segment.SEG_CODE, ida_segment.SEG_XTRN):
            continue
        for head in idautils.Heads(segment.start_ea, segment.end_ea):
            for target in idautils.DataRefsFrom(head):
                entry = target - 1
                if target & 1 and in_own_code(entry) and ida_bytes.is_unknown(ida_bytes.get_flags(entry)):
                    idc.split_sreg_range(entry, "T", 1, idc.SR_user)
                    if ida_funcs.add_func(entry):
                        logger.debug("Made a Thumb function of %#x, which %#x points at", entry, head)


def separate_tail_called_functions() -> None:
    """Treat tail-called functions as separate functions instead of a chunk.

    Tail-called functions are called using an unconditional jump from another chunk,
    without pushing a return address - so a return on the tail-called function exists
    both the tail-called function and its caller together."""
    for entry in list(idautils.Functions()):
        chunks = list(idautils.Chunks(entry))
        for start, end in chunks:
            others = [chunk for chunk in chunks if chunk != (start, end)]
            in_others = lambda address, others=others: any(begin <= address < finish for begin, finish in others)
            if start == entry or not _tail_jumped_into(start, in_others) or _jumps_into(start, end, in_others):
                continue
            if ida_funcs.remove_func_tail(ida_funcs.get_func(entry), start):
                ida_funcs.add_func(start)
                logger.debug("Made a function of %#x, which IDA had folded into %#x", start, entry)


def _tail_jumped_into(start: int, source: Callable[[int], bool]) -> bool:
    """True if an unconditional jump (one nothing flows on from) from where `source` holds lands on `start`."""
    return any(
        xref.type in _JUMPS and source(xref.frm)
        and not any(flow.type == ida_xref.fl_F for flow in idautils.XrefsFrom(xref.frm))
        for xref in idautils.XrefsTo(start)
    )


def _jumps_into(start: int, end: int, target: Callable[[int], bool]) -> bool:
    """True if the code between `start` and `end` jumps to where `target` holds."""
    return any(xref.type in _JUMPS and target(xref.to) for head in idautils.Heads(start, end) for xref in idautils.XrefsFrom(head))


def _heads_of(entries: Iterable[int]) -> Iterator[int]:
    """Every head of the functions at `entries`, in all their chunks: their instructions, and the data inside them."""
    for entry in entries:
        for start, end in idautils.Chunks(entry):
            yield from idautils.Heads(start, end)


def _callers(entries: Iterable[int]) -> Iterator[int]:
    """The code calling or tail-jumping to the functions at `entries`, directly or through a thunk (see _thunk_at)."""
    for entry in entries:
        for xref in idautils.XrefsTo(entry):
            if _is_call(xref):
                yield xref.frm
                if (thunk := _thunk_at(xref.frm)) is not None:
                    yield from _callers([thunk])


def _callees(addresses: Iterable[int]) -> Iterator[int]:
    """The functions the code at `addresses` calls or tail-jumps to, past any thunks (see _thunk_at)."""
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
    """Where a call to `address` ends up: past the thunks on the way (see _thunk_at)."""
    for _ in range(_LONGEST_THUNK_CHAIN):
        if _thunk_at(address) != address:
            break
        target, _ = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(address))
        if target == ida_idaapi.BADADDR:
            break
        address = target
    return address


def _thunk_at(address: int) -> int | None:
    """
    The entry of the function `address` belongs to, if that is a thunk on the way:
    a local thunk (`j_foo`); the PLT stub a shared object calls its own exported
    functions through (a call to one may be interposed); or the Thumb entry an ARM
    PLT stub has before it, for Thumb code to tail-jump to. An import's own stub
    is none: it is the PLTEntry a call reaches.
    """
    function = ida_funcs.get_func(address)
    if function is None or not function.flags & ida_funcs.FUNC_THUNK:
        return None
    if in_own_code(function.start_ea):
        return function.start_ea
    target, _ = ida_funcs.calc_thunk_func_target(function)
    on_the_way = target != ida_idaapi.BADADDR and (in_own_code(target) or in_plt(target))
    return function.start_ea if on_the_way else None
