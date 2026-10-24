from __future__ import annotations
import functools
import itertools
from typing import Callable, Iterable, Iterator
import ida_allins # type: ignore
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_ida # type: ignore
import ida_idaapi # type: ignore
import ida_idp # type: ignore
import ida_ua # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
from elfresolver.constraints import Count
from elfresolver.ida.layout import Region
from elfresolver.ida.resolution import SymbolResolution
from elfresolver.ida.structure import Structure
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.symbols import Function

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles
_PC_THUNK_REGISTERS = (0x04, 0x0C, 0x14, 0x1C, 0x2C, 0x34, 0x3C)  # ModRM bytes of `mov eax..edi, [esp]`


class IDAFunction(IDASymbol, kind=Function):
    """A function of the binary's own code (an import's PLT stub is an IDAPLTEntry)."""

    # The constraints only a function carries.

    @classmethod
    @SymbolResolution.constraint("calls")
    def calls(cls, callee: IDAFunction, max_depth: int | None) -> Iterable[int]:
        """The functions calling `callee` (see calls_to), or calling one that does, `max_depth` deep."""
        return cls.filter_from(cls._reached(callee.matches, callee.calls_to, max_depth))

    @classmethod
    @SymbolResolution.constraint("called_by")
    def called_by(cls, caller: IDAFunction, max_depth: int | None) -> Iterable[int]:
        """The functions `caller` calls (see calls_from), or that those call, `max_depth` deep."""
        return cls.filter_from(cls._reached(caller.matches, caller.calls_from, max_depth))

    @classmethod
    @SymbolResolution.constraint("uses_const", cost=2)
    def uses_const(cls, entry: int, value: int) -> bool:
        """
        True if the function at `entry` uses `value` (see _constants_of), as wide as any operand it
        fits: -1 is 0xFF in a byte, 0xFFFFFFFF in a dword. Or builds it in parts (see _built_in_parts):
        which only a function using one of its upper 16-bit parts can, as a MOVK's or MOVT's immediate.
        """
        forms = {value & (1 << 8 * width) - 1 for width in (1, 2, 4, 8) if -(1 << 8 * width - 1) <= value < 1 << 8 * width}
        constants = cls._constants_of(entry)
        if not forms.isdisjoint(constants):
            return True
        upper_parts = {form >> shift & 0xFFFF for form in forms for shift in (16, 32, 48) if form >> shift}
        return not upper_parts.isdisjoint(constants) and not forms.isdisjoint(_built_in_parts(entry))

    @classmethod
    @SymbolResolution.constraint("structured_with", cost=3)
    def structured_with(cls, entry: int, loops: Count | None, ifs: Count | None, switch_cases: Count | None) -> bool:
        """True if the function at `entry` decompiles to loops, ifs and switch cases in these counts (see Structure)."""
        structure = Structure.of(entry)
        return structure is not None and structure.has(loops, ifs, switch_cases)

    # What calls functions, and what they call and refer to: from any of their instructions.

    @classmethod
    def calls_to(cls, entries: Iterable[int]) -> Iterator[int]:
        """Every function calling one of those at `entries`: directly, by a tail jump, or through a thunk on the way (see _thunk_at)."""
        callees = list(entries)
        while callees:
            for xref in idautils.XrefsTo(callees.pop()):
                if cls._is_call(xref) and (caller := cls.function_of(xref.frm)) is not None:
                    yield caller
                    if (thunk := cls._thunk_at(xref.frm)) is not None:
                        callees.append(thunk)  # what calls the thunk calls the callee too

    @classmethod
    def calls_from(cls, entries: Iterable[int]) -> Iterator[int]:
        """Every function those at `entries` call or tail-jump to, past the thunks on the way (see _thunk_at)."""
        for xref in (xref for head in cls._iter_function_heads(entries) for xref in idautils.XrefsFrom(head)):
            if not cls._is_call(xref):
                continue
            callee = xref.to
            for _ in range(_LONGEST_THUNK_CHAIN):
                if cls._thunk_at(callee) != callee:
                    break
                target, _ = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(callee))
                if target == ida_idaapi.BADADDR:
                    break
                callee = target
            yield callee

    def references_to(self) -> Iterator[int]:
        """Every address referring to one of the matches: to its entry, or one past it (a Thumb function's pointer has its low bit set)."""
        entries = (address for entry in self.matches for address in dict.fromkeys([entry, entry | 1]))
        return self._data_refs(idautils.DataRefsTo, entries)

    def references_from(self) -> Iterator[int]:
        """Every address the matches refer to, from any of their instructions (or the data inside them: an ARM literal pool)."""
        return self._data_refs(idautils.DataRefsFrom, self._iter_function_heads(self.matches))

    # What this kind of symbol is.

    @classmethod
    def all(cls) -> Iterable[int]:
        return (entry for entry in idautils.Functions() if Region.of(entry) is Region.OWN_CODE)

    @classmethod
    def filter_from(cls, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := cls.function_of(address)) is not None and Region.of(entry) is Region.OWN_CODE:
                yield entry

    @classmethod
    def display_name(cls, entry: int, /) -> str | None:
        return ida_funcs.get_func_name(entry)

    @classmethod
    def size_of(cls, entry: int, /) -> int:
        return ida_funcs.calc_func_size(ida_funcs.get_func(entry))

    # Reading functions.

    @staticmethod
    def function_of(address: int) -> int | None:
        """The entry of the function `address` belongs to (in any of its chunks), if one does."""
        function = ida_funcs.get_func(address)
        return function.start_ea if function is not None else None

    @staticmethod
    def _iter_function_heads(entries: Iterable[int]) -> Iterator[int]:
        """Every head of the functions at `entries`, in all their chunks: their instructions, and the data inside them."""
        for entry in entries:
            for start, end in idautils.Chunks(entry):
                yield from idautils.Heads(start, end)

    @staticmethod
    def _reached(start: Iterable[int], step: Callable[[set[int]], Iterable[int]], max_depth: int | None) -> set[int]:
        """The functions `step` leads to from those at `start` (those they call, or are called by), in up to `max_depth` steps (None: any number)."""
        reached, frontier = set(), set(start)
        for _ in range(max_depth) if max_depth is not None else itertools.count():
            frontier = set(step(frontier)) - reached
            if not frontier:
                break
            reached |= frontier
        return reached

    @staticmethod
    @functools.cache  # one IDA has one database open
    def _constants_of(entry: int) -> frozenset[int]:
        """
        Every integer the function at `entry` uses, as wide as it uses it: its instructions'
        immediates and displacements (x86 adds 0xB as `lea rax, [rdi+0Bh]`; IDA joins
        aarch64's MOVZ/MOVK and ARM's MOVW/MOVT into one MOV where they're adjacent), and
        the words of its literal pools (data inside it, which its instructions load).
        """
        constants = set()
        for head in IDAFunction._iter_function_heads([entry]):
            flags = ida_bytes.get_flags(head)
            if ida_bytes.has_immd(flags) or ida_bytes.is_data(flags):
                constants.update(ida_ua.get_immvals(head, ida_bytes.OPND_ALL, flags))
        return frozenset(constants)

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


@functools.cache  # one IDA has one database open
def _built_in_parts(entry: int) -> frozenset[int]:
    """
    Every constant the function at `entry` builds on a register in parts, on ARM: a MOV
    (aarch64's MOVZ or MOVN, ARM's MOVW), then MOVKs (16 bits each, at their shift) or a
    MOVT (the top 16 bits), which optimized code schedules apart, where IDA doesn't join
    them. A register holds its MOV's value until another instruction writes it, or a call may.
    """
    if ida_ida.inf_get_procname() != "ARM":
        return frozenset()
    built: dict[int, int] = {}  # by register: the value its moves put in it, while nothing else wrote it
    constants = set()
    instruction = ida_ua.insn_t()
    for head in IDAFunction._iter_function_heads([entry]):
        if not ida_ua.decode_insn(instruction, head):
            continue  # data: a literal pool's word
        register, immediate = instruction.ops[0], instruction.ops[1]
        moves = register.type == ida_ua.o_reg and immediate.type == ida_ua.o_imm
        if moves and instruction.itype == ida_allins.ARM_mov:
            built[register.reg] = immediate.value
        elif moves and instruction.itype in (ida_allins.ARM_movk, ida_allins.ARM_movt) and register.reg in built:
            shift = immediate.specval if instruction.itype == ida_allins.ARM_movk else 16
            built[register.reg] = built[register.reg] & ~(0xFFFF << shift) | immediate.value << shift
            constants.add(built[register.reg])
        elif ida_idp.is_call_insn(instruction):
            built.clear()  # a call may change any register it needn't preserve
        else:
            feature = instruction.get_canon_feature()
            for index, operand in enumerate(instruction.ops):
                if operand.type == ida_ua.o_void:
                    break
                if operand.type == ida_ua.o_reg and ida_idp.has_cf_chg(feature, index):
                    # the opcode writes to operand.reg, lose track of its value
                    built.pop(operand.reg, None)
    return frozenset(constants)