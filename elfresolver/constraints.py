from __future__ import annotations
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, ClassVar
from elfresolver.protocol.serializable import Serializable
if TYPE_CHECKING:
    from elfresolver.symbols import Function, Symbol

# NOTE: `method` must match a resolving method logic in the corresponding IDASymbol object

@dataclass(frozen=True)
class IDAConstraint(Serializable):
    """A constraint a Symbol method adds, shown as that method's call:
    `.calls(PLTEntry('recvfrom'))`. IDA's side meets it with a method of the same name."""
    method: ClassVar[str]

    def __str__(self) -> str:
        from elfresolver.symbols import Symbol  # symbols.py imports this module
        arguments = ", ".join(  # joined apart from the f-string below: quotes nested in one need Python 3.12
            f"{field.name}={argument.id if isinstance(argument, Symbol) else repr(argument)}"
            for field in fields(self) if (argument := getattr(self, field.name)) != field.default  # a default goes unsaid
        )
        return f".{self.method}({arguments})"


@dataclass(frozen=True)
class Matching(IDAConstraint):
    """The symbol's name (a string's text) has a match of the regular expression `pattern` in it."""
    pattern: str
    method: ClassVar[str] = "matching"


class _CallDepth:
    """A constraint over calls `max_depth` deep: 1 for a direct call, 2 for a call of a function making it, ... None for any depth."""
    max_depth: int | None

    def __post_init__(self) -> None:
        if self.max_depth is not None and (type(self.max_depth) is not int or self.max_depth < 1):
            raise ValueError(f"max_depth is a number of calls, from 1 (or None, for any): not {self.max_depth!r}")


@dataclass(frozen=True)
class Calls(_CallDepth, IDAConstraint):
    """The function calls `callee` (directly, by a tail jump, or through a thunk), or calls a function that does, `max_depth` deep."""
    callee: Function
    max_depth: int | None = 1
    method: ClassVar[str] = "calls"


@dataclass(frozen=True)
class CalledBy(_CallDepth, IDAConstraint):
    """The function is called by `caller`, or by a function `caller` calls, `max_depth` deep."""
    caller: Function
    max_depth: int | None = 1
    method: ClassVar[str] = "called_by"


@dataclass(frozen=True)
class References(IDAConstraint):
    """The symbol refers to `target`'s address: as code taking it, or as data holding a pointer to it."""
    target: Symbol
    method: ClassVar[str] = "references"


@dataclass(frozen=True)
class ReferencedBy(IDAConstraint):
    """`source` refers to the symbol's address."""
    source: Symbol
    method: ClassVar[str] = "referenced_by"


@dataclass(frozen=True)
class UsesConst(IDAConstraint):
    """The function uses the integer `value` in its code: as an instruction's immediate or displacement, or from a literal pool."""
    value: int
    method: ClassVar[str] = "uses_const"


Count = int | tuple[int | None, int | None]   # exactly n; or (at least, at most), None for unbounded


@dataclass(frozen=True)
class StructuredWith(IDAConstraint):
    """
    The function's decompiled code (Hex-Rays') has loops (for, while, do), ifs, and
    switch cases (other than default) in these counts. A count left None isn't checked.
    """
    loops: Count | None = None
    ifs: Count | None = None
    switch_cases: Count | None = None
    method: ClassVar[str] = "structured_with"

    def __post_init__(self) -> None:
        counts = {field.name: getattr(self, field.name) for field in fields(self)}
        if all(count is None for count in counts.values()):
            raise ValueError("structured_with() needs a count to check: loops, ifs or switch_cases")
        for name, count in counts.items():
            bounds = (count, count) if type(count) is int else count
            if count is not None and not (
                isinstance(bounds, tuple) and len(bounds) == 2
                and all(bound is None or type(bound) is int and bound >= 0 for bound in bounds)
            ):
                raise ValueError(f"{name} is a count (n), or bounds of one ((at least, at most), None for unbounded): not {count!r}")
