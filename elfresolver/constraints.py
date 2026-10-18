from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar
from elfresolver.serializable import Serializable
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
            f"{name}={argument.id if isinstance(argument, Symbol) else repr(argument)}"
            for name, argument in vars(self).items() if name != self.method
        )
        return f".{self.method}({arguments})"


@dataclass(frozen=True)
class Matching(IDAConstraint):
    """The symbol's name (a string's text) has a match of the regular expression `pattern` in it."""
    pattern: str
    method: ClassVar[str] = "matching"


@dataclass(frozen=True)
class Calls(IDAConstraint):
    """The function calls `callee`: directly, by a tail jump, or through a thunk."""
    callee: Function
    method: ClassVar[str] = "calls"


@dataclass(frozen=True)
class CalledBy(IDAConstraint):
    """The function is called by `caller`."""
    caller: Function
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


# WIP
@dataclass(frozen=True)
class StructuredWith(IDAConstraint):
    """The function is implemented with a specified number of loop and if statements."""
    loops: int | None
    ifs: int | None
    method: ClassVar[str] = "structured_with"
