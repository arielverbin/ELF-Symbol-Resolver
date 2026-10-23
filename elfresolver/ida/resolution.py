from __future__ import annotations
import functools
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, TypeVar
from elfresolver.constraints import IDAConstraint
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.symbols import Symbol
if TYPE_CHECKING:
    from elfresolver.ida.symbols import IDASymbol

logger = logging.getLogger(__name__)

_Method = TypeVar("_Method", bound=Callable[..., Any])


@dataclass(frozen=True)
class _ConstraintMethod:
    """A kind's method meeting a constraint (see SymbolResolution.constraint):
    the constraint's `method`, its cost, and its own name."""
    meets: str
    cost: int
    name: str


class SymbolResolution:
    """
    Resolves symbols in the database IDA has open: each constraint met by the method its kind
    marks for it (see constraint), each symbol equal to another resolved once.
    """

    def __init__(self, interrupted: Callable[[], bool] = lambda: False) -> None:
        """`interrupted` is asked before each constraint is met, and before each candidate is checked:
        True stops the resolve under way."""
        self.interrupted = interrupted
        self._resolved: dict[Symbol, IDASymbol] = {}

    @staticmethod
    def constraint(method: str, cost: int = 0) -> Callable[[_Method], _Method]:
        """
        Marks a kind's class method as meeting the constraint whose `method` is `method`
        (IDAConstraint.method: "calls"). Cost 0: it takes the constraint's fields and returns
        every symbol of the kind meeting it. Above 0: it takes one candidate, then the fields,
        and returns True if the candidate meets it. These run after the others, lowest cost
        first, on the candidates left.
        """
        def mark(function: _Method) -> _Method:
            function.constraint_method = _ConstraintMethod(method, cost, function.__name__)  # type: ignore[attr-defined]
            return function
        return mark

    def resolve(self, symbol: Symbol) -> IDASymbol:
        """`symbol`, resolved (see _apply_constraints): once for every symbol equal to it, which is answered from memory."""
        if (resolved := self._resolved.get(symbol)) is not None:
            logger.info("%r: %d match(es), resolved before", symbol, len(resolved.matches))
            return resolved

        logger.info("Resolving %r", symbol)
        kind = self._kind_of(symbol)
        matches = self._apply_constraints(kind, symbol)
        resolved = self._resolved[symbol] = kind(symbol, matches)
        logger.info("%r: %d match(es)", symbol, len(resolved.matches))
        return resolved

    def _apply_constraints(self, kind: type[IDASymbol], symbol: Symbol) -> frozenset[int]:
        """
        The address of every symbol of `kind` meeting `symbol`'s constraints: those of cost 0 met first,
        in the order written, then the others, lowest cost first; each on what the ones before
        left. Once nothing is, the rest are skipped, and the symbols in them never resolved.
        """
        matches: frozenset[int] | None = None  # every symbol of the kind, until a constraint is met
        for constraint in sorted(symbol.constraints, key=lambda constraint: self._method_meeting(kind, constraint).cost):
            if matches is not None and not matches:
                break
            matches = self._meet(kind, constraint, matches)
            logger.debug("%r: %s leaves %d candidate(s)", symbol, constraint, len(matches))
        return matches if matches is not None else frozenset(kind.all())

    def _meet(self, kind: type[IDASymbol], constraint: IDAConstraint, candidates: frozenset[int] | None) -> frozenset[int]:
        """What `constraint` leaves of `candidates` (None: every symbol of `kind`), once the symbols in it resolve."""
        method = self._method_meeting(kind, constraint)
        meet = getattr(kind, method.name)
        fields = [self.resolve(value) if isinstance(value, Symbol) else value for value in vars(constraint).values()]
        self._stop_if_cancelled()  # IDA's side runs on one thread: nothing else would notice a cancel
        if method.cost == 0:
            found = frozenset(meet(*fields))
            return found if candidates is None else candidates & found
        return frozenset(self._checked(meet, fields, kind.all() if candidates is None else candidates))

    def _checked(self, check: Callable[..., bool], fields: list[Any], candidates: Iterable[int]) -> Iterator[int]:
        """The candidates `check` passes, given `fields`: one by one, noticing a cancel before each."""
        for candidate in candidates:
            self._stop_if_cancelled()
            if check(candidate, *fields):
                yield candidate

    def _stop_if_cancelled(self) -> None:
        """Raise ResolveInterrupted if the resolver has cancelled the resolve under way (see `interrupted`)."""
        if self.interrupted():
            raise ResolveInterrupted("The resolver cancelled the resolve")

    @staticmethod
    def _kind_of(symbol: Symbol) -> type[IDASymbol]:
        """The IDASymbol class resolving `symbol`'s kind (see IDASymbol.kinds)."""
        from elfresolver.ida.symbols import IDASymbol  # with every kind it registers: they import this module, for constraint()
        return IDASymbol.kinds[type(symbol)]

    @staticmethod
    def _method_meeting(kind: type[IDASymbol], constraint: IDAConstraint) -> _ConstraintMethod:
        """The method of `kind` meeting `constraint`; a TypeError if it has none."""
        if (method := SymbolResolution._methods_of(kind).get(constraint.method)) is None:
            raise TypeError(f"{kind.__name__} meets no .{constraint.method}()")
        return method

    @staticmethod
    @functools.cache  # a kind's methods are set once it's defined
    def _methods_of(kind: type[IDASymbol]) -> dict[str, _ConstraintMethod]:
        """Every method of `kind` meeting a constraint, by the constraint's `method`: its own, and those it inherits
        without overriding."""
        methods: dict[str, _ConstraintMethod] = {}
        for klass in reversed(kind.__mro__):  # a subclass last: its methods replace those it inherits
            own: dict[str, _ConstraintMethod] = {}
            for attribute in vars(klass).values():
                marked = getattr(getattr(attribute, "__func__", attribute), "constraint_method", None)  # inside its classmethod
                if isinstance(marked, _ConstraintMethod):
                    if marked.meets in own:
                        raise TypeError(f"{klass.__name__} meets .{marked.meets}() twice: by {own[marked.meets].name} and {marked.name}")
                    own[marked.meets] = marked
            methods.update(own)
        return methods
