from __future__ import annotations
import logging
import time
import ida_auto # type: ignore
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_ida # type: ignore
import ida_segment # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
import idc # type: ignore
from elfresolver.ida.layout import Region

logger = logging.getLogger(__name__)

_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)


class AutoAnalysis:
    """IDA's auto-analysis of the database it has open, completed where it falls short of what resolving needs."""

    @classmethod
    def complete(cls) -> None:
        """Return once IDA's auto-analysis has finished: with a function wherever a pointer leads to one, and each function one of its own."""
        logger.info("Waiting for IDA's auto-analysis")
        started = time.monotonic()
        ida_auto.auto_wait()
        cls._make_functions_of_thumb_pointers()
        ida_auto.auto_wait()  # for the code those call
        cls._separate_tail_called_functions()
        ida_auto.auto_wait()  # for the functions that made
        logger.info("Auto-analysis finished in %.1fs", time.monotonic() - started)

    @staticmethod
    def _make_functions_of_thumb_pointers() -> None:
        """Let IDA explore skipped bytes due to Thumb code (32-bit ARM, where such a
        pointer is the address plus one). It solves an issue where IDA doesn't follow main's,
        which _start loads from the GOT: without this, main is no function, and neither is
        any function only main calls. IDA may have decoded the bytes as ARM code, or as
        data (main placed before _start): that is undone first, up to the next function."""
        if ida_ida.inf_get_procname() != "ARM" or ida_ida.inf_is_64bit():
            return
        for segment in (segment for region in (Region.GOT, Region.VARIABLES, Region.OTHER) for segment in region.segments()):
            for head in idautils.Heads(segment.start_ea, segment.end_ea):
                for target in idautils.DataRefsFrom(head):
                    entry = target - 1
                    if not target & 1 or Region.of(entry) is not Region.OWN_CODE or ida_funcs.get_func(entry) is not None:
                        continue
                    if not ida_bytes.is_unknown(ida_bytes.get_flags(entry)):
                        following = ida_funcs.get_next_func(entry)
                        end = following.start_ea if following is not None else ida_segment.getseg(entry).end_ea
                        ida_bytes.del_items(entry, ida_bytes.DELIT_SIMPLE, end - entry)
                    idc.split_sreg_range(entry, "T", 1, idc.SR_user)
                    if ida_funcs.add_func(entry):
                        logger.debug("Made a Thumb function of %#x, which %#x points at", entry, head)

    @staticmethod
    def _separate_tail_called_functions() -> None:
        """Treat tail-called functions as separate functions instead of a chunk.

        Tail-called functions are called using an unconditional jump from another chunk,
        without pushing a return address - so a return on the tail-called function exits
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


# USEFUL BUT NOT IN USE (I don't need full ARM support)
#
# @staticmethod
# @functools.cache  # one IDA has one database open
# def _built_in_parts(entry: int) -> frozenset[int]:
#     """
#     Every constant the function at `entry` builds on a register in parts, on ARM: a MOV
#     (aarch64's MOVZ or MOVN, ARM's MOVW), then MOVKs (16 bits each, at their shift) or a
#     MOVT (the top 16 bits), which optimized code schedules apart, where IDA doesn't join
#     them. A register holds its MOV's value until another instruction writes it, or a call may.
#     """
#     if ida_ida.inf_get_procname() != "ARM":
#         return frozenset()
#     built: dict[int, int] = {}  # by register: the value its moves put in it, while nothing else wrote it
#     constants = set()
#     instruction = ida_ua.insn_t()
#     for head in IDAFunction._iter_function_heads([entry]):
#         if not ida_ua.decode_insn(instruction, head):
#             continue  # data: a literal pool's word
#         register, immediate = instruction.ops[0], instruction.ops[1]
#         moves = register.type == ida_ua.o_reg and immediate.type == ida_ua.o_imm
#         if moves and instruction.itype == ida_allins.ARM_mov:
#             built[register.reg] = immediate.value
#         elif moves and instruction.itype in (ida_allins.ARM_movk, ida_allins.ARM_movt) and register.reg in built:
#             shift = immediate.specval if instruction.itype == ida_allins.ARM_movk else 16
#             built[register.reg] = built[register.reg] & ~(0xFFFF << shift) | immediate.value << shift
#             constants.add(built[register.reg])
#         elif ida_idp.is_call_insn(instruction):
#             built.clear()  # a call may change any register it needn't preserve
#         else:
#             feature = instruction.get_canon_feature()
#             for index, operand in enumerate(instruction.ops):
#                 if operand.type == ida_ua.o_void:
#                     break
#                 if operand.type == ida_ua.o_reg and ida_idp.has_cf_chg(feature, index):
#                     built.pop(operand.reg, None)
#     return frozenset(constants)
