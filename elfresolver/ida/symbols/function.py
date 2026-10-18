from __future__ import annotations
import logging
from typing import Iterable, Iterator
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_ida # type: ignore
import ida_idaapi # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
import idc # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol

logger = logging.getLogger(__name__)

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles
_PC_THUNK_REGISTERS = (0x04, 0x0C, 0x14, 0x1C, 0x2C, 0x34, 0x3C)  # ModRM bytes of `mov eax..edi, [esp]`


class IDAFunction(IDASymbol):
    """A function of the binary's own code (an import's PLT stub is an IDAPLTEntry)."""

    def calls(self, callee: IDAFunction) -> Iterable[int]:
        """The functions calling `callee`: directly, by a tail jump, or through a thunk on the way."""
        return self.owners(callee.calls_to())

    def called_by(self, caller: IDAFunction) -> Iterable[int]:
        """The functions `caller` calls or tail-jumps to, past the thunks on the way."""
        return self.owners(caller.calls_from())

    # What calls the matches, and what they call and refer to: from any of their instructions.

    def calls_to(self) -> Iterator[int]:
        """Every instruction calling one of the matches: directly, by a tail jump, or through a thunk on the way (see _thunk_at)."""
        callees = list(self.resolve())
        while callees:
            for xref in idautils.XrefsTo(callees.pop()):
                if self._is_call(xref):
                    yield xref.frm
                    if (thunk := self._thunk_at(xref.frm)) is not None:
                        callees.append(thunk)  # what calls the thunk calls the callee too

    def calls_from(self) -> Iterator[int]:
        """Every function the matches call or tail-jump to, past the thunks on the way (see _thunk_at)."""
        for xref in (xref for head in self._iter_function_heads() for xref in idautils.XrefsFrom(head)):
            if not self._is_call(xref):
                continue
            callee = xref.to
            for _ in range(_LONGEST_THUNK_CHAIN):
                if self._thunk_at(callee) != callee:
                    break
                target, _ = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(callee))
                if target == ida_idaapi.BADADDR:
                    break
                callee = target
            yield callee

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to its entry, or one past it (a Thumb function's pointer has its low bit set)."""
        entries = (address for entry in self.resolve() for address in dict.fromkeys([entry, entry | 1]))
        return self._data_refs(idautils.DataRefsTo, entries)

    def references_from(self) -> Iterator[int]:
        """Every address the matches refer to, from any of their instructions (or the data inside them: an ARM literal pool)."""
        return self._data_refs(idautils.DataRefsFrom, self._iter_function_heads())

    def all(self) -> Iterable[int]:
        return (entry for entry in idautils.Functions() if Region.of(entry) is Region.OWN_CODE)

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := self.function_of(address)) is not None and Region.of(entry) is Region.OWN_CODE:
                yield entry

    def describe(self, entry: int) -> ResolvedSymbol:
        return self.found(entry, ida_funcs.get_func_name(entry), ida_funcs.calc_func_size(ida_funcs.get_func(entry)))

    def _iter_function_heads(self) -> Iterator[int]:
        """Every head of the matches, in all their chunks: their instructions, and the data inside them."""
        for entry in self.resolve():
            for start, end in idautils.Chunks(entry):
                yield from idautils.Heads(start, end)

    @staticmethod
    def function_of(address: int) -> int | None:
        """The entry of the function `address` belongs to (in any of its chunks), if one does."""
        function = ida_funcs.get_func(address)
        return function.start_ea if function is not None else None

    @staticmethod
    def _is_call(xref: idautils._xref) -> bool:
        """
        True for a call, and for a jump to another function's entry: a tail call. Never
        for data, nor for flowing on, nor for a call to i686's PC thunk
        (`__x86.get_pc_thunk.bx`: `mov reg, [esp]; ret`), which PIC code calls for its own address.
        """
        if xref.type not in _CALLS + _JUMPS:
            return False
        code = ida_bytes.get_bytes(xref.to, 4)
        if code is not None and code[0] == 0x8B and code[1] in _PC_THUNK_REGISTERS and code[2:] == b"\x24\xc3":
            return False
        if xref.type in _CALLS:
            return True
        return IDAFunction.function_of(xref.to) == xref.to and IDAFunction.function_of(xref.frm) != xref.to

    @staticmethod
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
        if Region.of(function.start_ea) is Region.OWN_CODE:
            return function.start_ea
        target, _ = ida_funcs.calc_thunk_func_target(function)
        return function.start_ea if Region.of(target) in (Region.OWN_CODE, Region.PLT) else None

    # Where IDA's auto-analysis falls short, once it's done.

    @staticmethod
    def make_functions_of_thumb_pointers() -> None:
        """Let IDA explore skipped bytes due to Thumb code (32-bit ARM, where such a
        pointer is the address plus one). It solves an issue where IDA doesn't follow main's,
        which _start loads from the GOT: without this, main is no function, and neither is
        any function only main calls."""
        if ida_ida.inf_get_procname() != "ARM" or ida_ida.inf_is_64bit():
            return
        for segment in (segment for region in (Region.GOT, Region.VARIABLES, Region.OTHER) for segment in region.segments()):
            for head in idautils.Heads(segment.start_ea, segment.end_ea):
                for target in idautils.DataRefsFrom(head):
                    entry = target - 1
                    if target & 1 and Region.of(entry) is Region.OWN_CODE and ida_bytes.is_unknown(ida_bytes.get_flags(entry)):
                        idc.split_sreg_range(entry, "T", 1, idc.SR_user)
                        if ida_funcs.add_func(entry):
                            logger.debug("Made a Thumb function of %#x, which %#x points at", entry, head)

    @staticmethod
    def separate_tail_called_functions() -> None:
        """Treat tail-called functions as separate functions instead of a chunk.

        Tail-called functions are called using an unconditional jump from another chunk,
        without pushing a return address - so a return on the tail-called function exists
        both the tail-called function and its caller together."""
        for entry in list(idautils.Functions()):
            chunks = list(idautils.Chunks(entry))
            for start, end in chunks:
                if start == entry:
                    continue
                others = [range(begin, finish) for begin, finish in chunks if begin != start]
                tail_jumped_into = any(
                    xref.type in _JUMPS and any(xref.frm in other for other in others)
                    and not any(flow.type == ida_xref.fl_F for flow in idautils.XrefsFrom(xref.frm))  # nothing flows on from it
                    for xref in idautils.XrefsTo(start)
                )
                if not tail_jumped_into or any(  # a cold path jumps back, as a branch enters it
                    xref.type in _JUMPS and any(xref.to in other for other in others)
                    for head in idautils.Heads(start, end) for xref in idautils.XrefsFrom(head)
                ):
                    continue
                if ida_funcs.remove_func_tail(ida_funcs.get_func(entry), start):
                    ida_funcs.add_func(start)
                    logger.debug("Made a function of %#x, which IDA had folded into %#x", start, entry)
