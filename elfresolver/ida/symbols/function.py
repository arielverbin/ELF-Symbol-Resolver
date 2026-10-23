from __future__ import annotations
import functools
import itertools
from typing import Callable, Iterable, Iterator
import ida_bytes # type: ignore
import ida_funcs # type: ignore
import ida_idaapi # type: ignore
import ida_ua # type: ignore
import ida_xref # type: ignore
import idautils # type: ignore
from elfresolver.constraints import Count
from elfresolver.ida.layout import Region
from elfresolver.ida.structure import Structure
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import Function

_CALLS = (ida_xref.fl_CN, ida_xref.fl_CF)
_JUMPS = (ida_xref.fl_JN, ida_xref.fl_JF)
_LONGEST_THUNK_CHAIN = 8  # thunks of thunks followed, at most: never round in circles
_PC_THUNK_REGISTERS = (0x04, 0x0C, 0x14, 0x1C, 0x2C, 0x34, 0x3C)  # ModRM bytes of `mov eax..edi, [esp]`


class IDAFunction(IDASymbol, kind=Function):
    """A function of the binary's own code (an import's PLT stub is an IDAPLTEntry)."""

    # The constraints only a function carries.

    def calls(self, callee: IDAFunction, max_depth: int | None = 1) -> Iterable[int]:
        """The functions calling `callee` (see calls_to), or calling one that does, `max_depth` deep."""
        return self.owners(self._reached(callee.resolve(), callee.calls_to, max_depth))

    def called_by(self, caller: IDAFunction, max_depth: int | None = 1) -> Iterable[int]:
        """The functions `caller` calls (see calls_from), or that those call, `max_depth` deep."""
        return self.owners(self._reached(caller.resolve(), caller.calls_from, max_depth))

    @IDASymbol.heavy
    def uses_const(self, value: int, *, candidates: frozenset[int]) -> Iterator[int]:
        """The candidates using `value` (see _constants_of), as wide as any operand it fits: -1 is 0xFF in a byte, 0xFFFFFFFF in a dword."""
        forms = {value & (1 << 8 * width) - 1 for width in (1, 2, 4, 8) if -(1 << 8 * width - 1) <= value < 1 << 8 * width}
        return (entry for entry in self._each(candidates) if forms & self._constants_of(entry))

    @IDASymbol.heavy
    def structured_with(self, loops: Count | None, ifs: Count | None, switch_cases: Count | None, *, candidates: frozenset[int]) -> Iterator[int]:
        """The candidates whose decompiled code has loops, ifs and switch cases in these counts (see Structure)."""
        return (
            entry for entry in self._each(candidates)
            if (structure := Structure.of(entry)) is not None and structure.has(loops, ifs, switch_cases)
        )

    # What calls functions, and what they call and refer to: from any of their instructions.

    def calls_to(self, entries: Iterable[int]) -> Iterator[int]:
        """Every function calling one of those at `entries`: directly, by a tail jump, or through a thunk on the way (see _thunk_at)."""
        callees = list(entries)
        while callees:
            for xref in idautils.XrefsTo(callees.pop()):
                if self._is_call(xref) and (caller := self.function_of(xref.frm)) is not None:
                    yield caller
                    if (thunk := self._thunk_at(xref.frm)) is not None:
                        callees.append(thunk)  # what calls the thunk calls the callee too

    def calls_from(self, entries: Iterable[int]) -> Iterator[int]:
        """Every function those at `entries` call or tail-jump to, past the thunks on the way (see _thunk_at)."""
        for xref in (xref for head in self._iter_function_heads(entries) for xref in idautils.XrefsFrom(head)):
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
        return self._data_refs(idautils.DataRefsFrom, self._iter_function_heads(self.resolve()))

    # What this kind of symbol is.

    def all(self) -> Iterable[int]:
        return (entry for entry in idautils.Functions() if Region.of(entry) is Region.OWN_CODE)

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        for address in addresses:
            if (entry := self.function_of(address)) is not None and Region.of(entry) is Region.OWN_CODE:
                yield entry

    def describe(self, entry: int, /) -> ResolvedSymbol:
        return self.found(entry, ida_funcs.get_func_name(entry), ida_funcs.calc_func_size(ida_funcs.get_func(entry)))

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
        aarch64's MOVZ/MOVK and ARM's MOVW/MOVT into one MOV), and the words of its literal
        pools (data inside it, which its instructions load).
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
