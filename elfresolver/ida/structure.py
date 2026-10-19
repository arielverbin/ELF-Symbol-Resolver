from __future__ import annotations
import functools
import logging
from dataclasses import dataclass
import ida_hexrays # type: ignore
from elfresolver.constraints import Count

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Structure:
    """What a function's decompiled code is made of: its loops (for, while, do), ifs,and switch cases other than default."""
    loops: int
    ifs: int
    switch_cases: int

    @classmethod
    @functools.cache  # one IDA has one database open
    def of(cls, entry: int) -> Structure | None:
        """The structure of the function at `entry`, as Hex-Rays decompiles it; None if it can't."""
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("structured_with() needs the Hex-Rays decompiler, and this IDA has none for the binary's processor")
        try:
            decompiled = ida_hexrays.decompile(entry)
        except ida_hexrays.DecompilationFailure as failure:
            logger.debug("Hex-Rays couldn't decompile %#x: %s", entry, failure)
            return None
        if decompiled is None:
            return None
        counter = _StatementCounter()
        counter.apply_to(decompiled.body, None)
        return cls(counter.loops, counter.ifs, counter.switch_cases)

    def has(self, loops: Count | None, ifs: Count | None, switch_cases: Count | None) -> bool:
        """True if every count given holds: exactly n, or (at least, at most) with None for unbounded."""
        for count, actual in ((loops, self.loops), (ifs, self.ifs), (switch_cases, self.switch_cases)):
            low, high = (count, count) if isinstance(count, int) else count or (None, None)
            if low is not None and actual < low or high is not None and actual > high:
                return False
        return True


class _StatementCounter(ida_hexrays.ctree_visitor_t):
    """Counts the loops, ifs and switch cases of a function's decompiled statements, visiting them."""

    def __init__(self) -> None:
        super().__init__(ida_hexrays.CV_FAST)
        self.loops = self.ifs = self.switch_cases = 0

    def visit_insn(self, statement: ida_hexrays.cinsn_t) -> int:
        if statement.op in (ida_hexrays.cit_for, ida_hexrays.cit_while, ida_hexrays.cit_do):
            self.loops += 1
        elif statement.op == ida_hexrays.cit_if:
            self.ifs += 1
        elif statement.op == ida_hexrays.cit_switch:
            self.switch_cases += sum(1 for case in statement.cswitch.cases if len(case.values) > 0)  # the default case has none
        return 0  # visit on
