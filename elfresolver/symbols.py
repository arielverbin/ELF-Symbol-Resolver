from __future__ import annotations
import re
from typing import Iterable, Mapping, Self
from elfresolver.constraints import CalledBy, Calls, IDAConstraint, Matching, ReferencedBy, References
from elfresolver.protocol.serializable import Serializable


class Symbol(Serializable):
    """Something in the binary, described by the constraints it must satisfy."""

    def __init__(self, name: str | None = None) -> None:
        """`name` forces a Matching constaint with an exact match.
        Use `.matching(regex)` for patterns."""
        self.id = hex(id(self))  # how its repr, and the logs, name it: on IDA's side too (see from_fields)
        self._constraints: tuple[IDAConstraint, ...] = (
            (Matching(rf"\A{re.escape(name)}\Z"),) if name is not None else ()
        )

    @classmethod
    def from_constraints(cls, constraints: Iterable[IDAConstraint]) -> Self:
        """A symbol of this kind with exactly `constraints` (how one is rebuilt from the wire)."""
        symbol = cls()
        symbol._constraints = tuple(constraints)
        return symbol

    @property
    def constraints(self) -> tuple[IDAConstraint, ...]:
        return self._constraints

    def to_fields(self) -> Mapping[str, object]:
        return {"id": self.id, "constraints": self._constraints}

    @classmethod
    def from_fields(cls, values: Mapping[str, object]) -> Self:
        symbol = cls.from_constraints(values["constraints"])  # type: ignore[arg-type]
        symbol.id = str(values["id"])  # the id it was sent with: both sides' logs name it alike
        return symbol

    def references(self, target: Symbol) -> Self:
        """This symbol, also referring to `target`'s address: as code taking it,
        or as data holding a pointer to it."""
        return self._with(References(_expect_symbol(Symbol, target, "references")))

    def referenced_by(self, source: Symbol) -> Self:
        """This symbol, also with its address referred to by `source`."""
        return self._with(ReferencedBy(_expect_symbol(Symbol, source, "referenced_by")))

    def matching(self, pattern: str) -> Self:
        """This symbol, also with a name (a string: its text) the regular expression
        `pattern` finds a match in."""
        re.compile(pattern)  # a malformed pattern fails here, rather than inside IDA
        return self._with(Matching(pattern))

    def _with(self, constraint: IDAConstraint) -> Self:
        return self.from_constraints((*self._constraints, constraint))

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and other.constraints == self._constraints

    def __hash__(self) -> int:
        return hash((type(self), self._constraints))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.id})" + "".join(map(str, self._constraints))


class Function(Symbol):
    """A function of the binary's own code (an import's PLT stub is a PLTEntry)."""

    def calls(self, callee: Function) -> Self:
        """This function, also calling `callee`: directly, by a tail jump, or through a thunk."""
        return self._with(Calls(_expect_symbol(Function, callee, "calls")))

    def called_by(self, caller: Function) -> Self:
        """This function, also called by `caller`."""
        return self._with(CalledBy(_expect_symbol(Function, caller, "called_by")))


class PLTEntry(Function):
    """The PLT stub of an imported function, named by the import's demangled name: in full, or
    without its parameter list."""


class GlobalVar(Symbol):
    """A global variable: a data item where variables live, other than a string literal."""


class String(Symbol):
    """A NUL-terminated string literal, named by its text."""


def _expect_symbol(kind: type[Symbol], argument: object, method: str) -> Symbol:
    """`argument`, checked to be a `kind`: `Function().calls(String('x'))` fails right where
    it's written."""
    if not isinstance(argument, kind):
        raise TypeError(f".{method}() takes a {kind.__name__}, not {argument!r}")
    return argument
