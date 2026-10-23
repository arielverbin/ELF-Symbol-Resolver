from __future__ import annotations
import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Iterable, Iterator, TypeVar
import ida_bytes # type: ignore
import ida_nalt # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.constraints import IDAConstraint
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import Symbol
if TYPE_CHECKING:
    from elfresolver.ida.resolution import SymbolResolution

logger = logging.getLogger(__name__)

_Method = TypeVar("_Method", bound=Callable[..., Any])


class IDASymbol(ABC):
    """A resolvable symbol, constructed from a ResolveRequest."""

    kinds: ClassVar[dict[type[Symbol], type[IDASymbol]]] = {}  # each kind of Symbol, and the IDASymbol resolving it

    def __init_subclass__(cls, kind: type[Symbol] | None = None, **kwargs: Any) -> None:
        """
        Subclasses mark which `Symbol` they solve.
        `class IDAFunction(IDASymbol, kind=Function)`: a Function resolves as an IDAFunction.
        """
        super().__init_subclass__(**kwargs)
        if kind is not None:
            IDASymbol.kinds[kind] = cls

    def __init__(self, symbol: Symbol, resolution: SymbolResolution) -> None:
        self.symbol = symbol
        self._resolution = resolution
        self._matches: frozenset[int] | None = None

    @staticmethod
    def heavy(method: _Method) -> _Method:
        """
        Marks a constraint's method as heavy: one checking candidates one by one. It runs
        after the light ones, given what they left as `candidates`, letting them run their
        logic only on a reduced number of symbols.
        """
        # TODO: create IDASymbol.constraint decorator, for better readabily of 'which functions can be invoked as a constraint',
        # the decorator will mark the method name invoking it from constraint.py, so the function name alone would not have to implicitly match
        # also support specifying HOW heavy they are, instead of @heavy decorator alone.
        # i.e, @IDASymbol.constraint(method="matching", heavy=3)
        method.heavy = True  # type: ignore[attr-defined]
        return method

    def resolve(self) -> frozenset[int]:
        """
        The address of every match, once each symbol nested in this one has resolved. The
        light constraints are met first, then the heavy ones (see heavy), each in the order
        written, and each on what the ones before left: once nothing is, the rest are skipped.
        """
        if self._matches is None:
            matches: frozenset[int] | None = None  # every symbol of the kind, until a constraint is met
            for constraint in sorted(self.symbol.constraints, key=lambda constraint: self._is_heavy(constraint)):
                if matches is not None and not matches:
                    break
                matches = self._step_resolve(constraint, matches)
            self._matches = matches if matches is not None else frozenset(self.all())
        return self._matches

    @property
    def resolved(self) -> bool:
        """True once resolve() has found the matches: asking again only remembers them."""
        return self._matches is not None

    # The constraints every kind of symbol can carry.

    @heavy
    def matching(self, pattern: str, *, candidates: frozenset[int]) -> Iterable[int]:
        """The candidates with a name the regular expression `pattern` finds a match in."""
        regex = re.compile(pattern)
        return (address for address in self._each(candidates) if any(map(regex.search, self.names_of(address))))

    def references(self, target: IDASymbol) -> Iterable[int]:
        """The symbols of this kind referring to `target`: as code taking its address, or as data holding a pointer to it."""
        return self.owners(target.references_to())

    def referenced_by(self, source: IDASymbol) -> Iterable[int]:
        """The symbols of this kind `source` refers to."""
        return self.owners(source.references_from())

    # What refers to the matches, and what they refer to: a kind with more to them than their address says so.

    def references_to(self) -> Iterable[int]:
        """Every address referring to one of the matches."""
        return self._data_refs(idautils.DataRefsTo, self.resolve())

    def references_from(self) -> Iterable[int]:
        """Every address one of the matches refers to."""
        return self._data_refs(idautils.DataRefsFrom, self.resolve())

    # What this kind of symbol is.

    @abstractmethod
    def all(self) -> Iterable[int]:
        """The address of every symbol of this kind."""

    @abstractmethod
    def owners(self, addresses: Iterable[int]) -> Iterable[int]:
        # TODO: rename to parse_from_addresses? yield_syms?
        # also, this is a classmethod, no? the addresses are given; they intoduce general logic to identify the class objects.
        """The symbols of this kind `addresses` belong to: an instruction's function, a byte's variable."""

    @abstractmethod
    def describe(self, address: int, /) -> ResolvedSymbol:
        # TODO: perhaps merge with owners; owners take a list of addresses and yield a ResolvedSymbol, and rename them to `parse_from_addresses`, or `parse_from`.
        """The symbol at `address`, as resolve() hands it to the user (see found)."""

    def names_of(self, address: int, /) -> tuple[str, ...]:
        """Every name the symbol at `address` answers to: the forms of IDA's name for it (see SymName.forms), if it has one."""
        name = ida_name.get_name(address)
        return SymName(name).forms if name else ()

    def found(self, address: int, name: str | None, size: int) -> ResolvedSymbol:
        """This symbol, found at `address`, named `name` and `size` bytes long."""
        # TODO: the function should only be called from inside describe. yet its part of the public API for some reason.
        # either remove it and duplicate its line for every implementation of describe, or rename to `_build_sym` or something
        return ResolvedSymbol(self.symbol, address, address - ida_nalt.get_imagebase(), name, size)

    def _step_resolve(self, constraint: IDAConstraint, candidates: frozenset[int] | None) -> frozenset[int]:
        # TODO: should this logic sit in symbol.py, or in resolution.py?
        # The current design might intoduce bugs by developers accidently uses `value.resolve()` intead of `self._resolution.resolve(value)`
        # The fact that `_resolution` feels optional like that is a design flaw. 
        # Perhaps move all of heavy decorator, `.resolve()`, `._step_resolve()` to resolution.py, and let the symbols only implement their
        # constraint logic.
        """What `constraint` leaves of `candidates` (None: every symbol of this kind). The
        symbols in it resolve first, so a cancel is noticed between them."""
        arguments = [
            self._resolution.resolve(value) if isinstance(value, Symbol) else value
            for value in vars(constraint).values()
        ]

        # give `interrupted` a chance to notice a cancel (IDA's side runs on one thread: nothing else would)
        self._resolution.stop_if_cancelled()

        # call the constraint's method (`.calls`, `.matching`, ...): a heavy one, on the candidates left
        method = getattr(self, constraint.method)
        if self._is_heavy(constraint):
            allowed = frozenset(method(*arguments, candidates=frozenset(self.all()) if candidates is None else candidates))
        else:
            allowed = frozenset(method(*arguments))
        left = allowed if candidates is None else candidates & allowed
        logger.debug("%r: %s leaves %d candidate(s)", self.symbol, constraint, len(left))
        return left

    def _is_heavy(self, constraint: IDAConstraint) -> bool:
        return getattr(getattr(self, constraint.method), "heavy", False)

    def _each(self, candidates: Iterable[int]) -> Iterator[int]:
        """`candidates` one by one, for a heavy constraint to check: stopping the resolve once the resolver cancels it."""
        # TODO: I understand its purpose, while iterating over candidates on heavy contraints we need a change to check stop_if_cancelled
        # but I don't like how stop_if_cancelled is being checked in two different places. 
        # perhaps: a heavy constraint receives a single candidate
        # and checks only this one. so _step_resolve can perform the iteration itself, and check stop_if_cancelled on each candidate.
        # that way we don't see en iteration over the candidates everywhere (each constraint only performs its logic)
        # and the check_if_cancelled is centralized inside _step_resolve.
        for candidate in candidates:
            self._resolution.stop_if_cancelled()
            yield candidate

    @staticmethod
    def _data_refs(refs: Callable[[int], Iterable[int]], addresses: Iterable[int]) -> Iterator[int]:
        """
        The data references of `addresses` `refs` gives (idautils.DataRefsTo, or
        DataRefsFrom), and those of the cells among them: a cell only holds an address
        for code to load (a GOT slot, or a data word inside code: an ARM literal pool),
        so what refers to a cell refers to what it points at.
        """
        for address in addresses:
            for other in refs(address):
                yield other
                region = Region.of(other)
                if region is Region.GOT or region is Region.OWN_CODE and ida_bytes.is_data(ida_bytes.get_flags(other)):
                    yield from refs(other)
