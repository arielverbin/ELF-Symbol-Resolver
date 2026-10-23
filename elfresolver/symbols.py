from __future__ import annotations
import re
from typing import Iterable, Mapping, Self, TypeVar
from elfresolver.constraints import CalledBy, Calls, Count, IDAConstraint, Matching, ReferencedBy, References, StructuredWith, UsesConst
from elfresolver.protocol.serializable import Serializable

_Kind = TypeVar("_Kind", bound="Symbol")


class Symbol(Serializable):
    """Something in the binary, described by the constraints it must satisfy."""

    def __init__(self, name: str | None = None) -> None:
        """A symbol named exactly `name`, in full, if one is given: an exact `.matching()`. Use `.matching(regex)` for patterns."""
        self.id = hex(id(self))  # how its repr, and the logs, name it: on IDA's side too (see from_fields)
        self._constraints: tuple[IDAConstraint, ...] = (
            (Matching(rf"\A{re.escape(name)}\Z"),) if name is not None else ()
        )

    @property
    def constraints(self) -> tuple[IDAConstraint, ...]:
        return self._constraints

    # The constraints every kind of symbol can carry: each method returns a new symbol, one constraint richer.

    def matching(self, pattern: str) -> Self:
        """This symbol, also with a name (a string: its text) the regular expression `pattern` finds a match in."""
        re.compile(pattern)  # a malformed pattern fails here, rather than inside IDA
        return self._with(Matching(pattern))

    def references(self, target: Symbol) -> Self:
        """This symbol, also referring to `target`'s address: as code taking it, or as data holding a pointer to it."""
        return self._with(References(self._checked(Symbol, target, "references")))

    def referenced_by(self, source: Symbol) -> Self:
        """This symbol, also with its address referred to by `source`."""
        return self._with(ReferencedBy(self._checked(Symbol, source, "referenced_by")))

    # How a symbol travels to IDA.

    @classmethod
    def from_constraints(cls, constraints: Iterable[IDAConstraint]) -> Self:
        """A symbol of this kind with exactly `constraints`."""
        symbol = cls()
        symbol._constraints = tuple(constraints)
        return symbol

    def to_fields(self) -> Mapping[str, object]:
        return {"id": self.id, "constraints": self._constraints}

    @classmethod
    def from_fields(cls, values: Mapping[str, object]) -> Self:
        symbol = cls.from_constraints(values["constraints"])  # type: ignore[arg-type]
        symbol.id = str(values["id"])  # the id it was sent with: both sides' logs name it alike
        return symbol

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and other.constraints == self._constraints

    def __hash__(self) -> int:
        return hash((type(self), self._constraints))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.id})" + "".join(map(str, self._constraints))

    def _with(self, constraint: IDAConstraint) -> Self:
        return self.from_constraints((*self._constraints, constraint))

    @staticmethod
    def _checked(kind: type[_Kind], argument: object, method: str) -> _Kind:
        """`argument`, checked to be a `kind`: `Function().calls(String('x'))` fails right where it's written."""
        if not isinstance(argument, kind):
            raise TypeError(f".{method}() takes a {kind.__name__}, not {argument!r}")
        return argument


class Function(Symbol):
    """A function of the binary's own code (an import's PLT stub is a PLTEntry)."""

    def calls(self, callee: Function, max_depth: int | None = 1) -> Self:
        """This function, also calling `callee`: directly, by a tail jump, or through a thunk.
        A `max_depth` above 1 allows calls on the way: 2, a call of a function calling it; None, any number."""
        return self._with(Calls(self._checked(Function, callee, "calls"), max_depth))

    def called_by(self, caller: Function, max_depth: int | None = 1) -> Self:
        """This function, also called by `caller`; with a `max_depth` above 1 (None: any), by a function it calls, too."""
        return self._with(CalledBy(self._checked(Function, caller, "called_by"), max_depth))

    def uses_const(self, value: int) -> Self:
        """This function, also using the integer `value`: as an instruction's immediate or displacement, or from a literal pool."""
        return self._with(UsesConst(value))

    def structured_with(self, *, loops: Count | None = None, ifs: Count | None = None, switch_cases: Count | None = None) -> Self:
        """
        This function, also with loops, ifs and switch cases in these counts, in its decompiled
        code (it needs Hex-Rays): exactly n, or (at least, at most), with None for unbounded.
        Optimization changes them (unrolling, branchless code, switches made tables): bounds last longer.

            Function().structured_with(loops=1, ifs=(2, None))
        """
        return self._with(StructuredWith(loops, ifs, switch_cases))


class PLTEntry(Function):
    """The PLT stub of an imported function, named by the import's demangled name: in full, or without its parameter list."""


class GlobalVar(Symbol):
    """A global variable: a data item where variables live, other than a string literal."""


class String(Symbol):
    """A NUL-terminated string literal, named by its text."""


class VTable(Symbol):
    """
    A C++ class's vtable (Itanium ABI): its primary table, and a secondary one for each
    base past the first, as `nm -S` sizes it. Found through the class's RTTI, or a `_ZTV`
    symbol, and named by the class's demangled name: `VTable("net::EchoHandler")`, or
    `VTable("vtable for net::EchoHandler")`.
    """
