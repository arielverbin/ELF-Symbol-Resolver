from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable, Iterator
import ida_nalt # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.constraints import IDAConstraint
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.layout import is_cell
from elfresolver.ida.names import demangled, name_forms
from elfresolver.messages import ResolvedSymbol
from elfresolver.symbols import Symbol

if TYPE_CHECKING:
    from elfresolver.ida.resolution import Resolution


class IDASymbol(ABC):
    """A resolvable symbol, constructed from a ResolveRequest."""

    def __init__(self, symbol: Symbol, resolution: Resolution) -> None:
        self.symbol = symbol
        self._resolution = resolution
        self._matches: frozenset[int] | None = None

    def resolve(self) -> frozenset[int]:
        """The address of every match, once each symbol nested in this one has resolved."""
        if self._matches is None:
            allowed = [self._step_resolve(constraint) for constraint in self.symbol.constraints]
            self._matches = frozenset.intersection(*allowed) if allowed else frozenset(self.all())
        return self._matches

    @property
    def resolved(self) -> bool:
        """True once resolve() has found the matches: asking again only remembers them."""
        return self._matches is not None

    # The constraints every kind of symbol can carry.

    def matching(self, pattern: str) -> Iterable[int]:
        """The symbols of this kind with a name the regular expression `pattern` finds a match in."""
        regex = re.compile(pattern)
        return (address for address in self.all() if any(map(regex.search, self.names_of(address))))

    def references(self, target: IDASymbol) -> Iterable[int]:
        """The symbols of this kind referring to `target`: as code taking its address, or as data holding a pointer to it."""
        return self.owners(target.references_to())

    def referenced_by(self, source: IDASymbol) -> Iterable[int]:
        """The symbols of this kind `source` refers to."""
        return self.owners(source.references_from())

    # What refers to the matches, and what they refer to: a kind with more to them than their address says so.

    def references_to(self) -> Iterable[int]:
        """Every address referring to one of the matches."""
        return data_refs_to(self.resolve())

    def references_from(self) -> Iterable[int]:
        """Every address one of the matches refers to."""
        return data_refs_from(self.resolve())

    # What this kind of symbol is.

    @abstractmethod
    def all(self) -> Iterable[int]:
        """The address of every symbol of this kind."""

    @abstractmethod
    def owners(self, addresses: Iterable[int]) -> Iterable[int]:
        """The symbols of this kind `addresses` belong to: an instruction's function, a byte's variable."""

    @abstractmethod
    def describe(self, address: int) -> ResolvedSymbol:
        """The symbol at `address`, as resolve() hands it to the user (see found)."""

    def names_of(self, address: int) -> tuple[str, ...]:
        """Every name the symbol at `address` answers to: the forms of IDA's name for it (see name_forms), if it has one."""
        name = ida_name.get_name(address)
        return name_forms(name, demangled_name(name)) if name else ()

    def found(self, address: int, name: str | None, size: int) -> ResolvedSymbol:
        """This symbol, found at `address`, named `name` and `size` bytes long."""
        return ResolvedSymbol(self.symbol, address, address - ida_nalt.get_imagebase(), name, size)

    def _step_resolve(self, constraint: IDAConstraint) -> frozenset[int]:
        """The symbols of this kind `constraint` allows. The symbols in it resolve first,
        so a cancel is noticed between them."""
        arguments = [
            self._resolution.resolve(value) if isinstance(value, Symbol) else value
            for value in vars(constraint).values()
        ]

        # give runtime for `interrupted` to check if a cancellation occured (we
        # cannot be multithreaded inside IDA :/)
        if self._resolution.interrupted():
            raise ResolveInterrupted("The resolver cancelled the resolve")

        # call the constaint method (i.e, `.calls`, `.matching` etc...)
        return frozenset(getattr(self, constraint.method)(*arguments))


def demangled_name(name: str) -> str | None:
    """`name` demangled as GNU's tools show it (see names.demangled); without a C++ runtime to, as IDA does."""
    return demangled(name) or ida_name.demangle_name(name, 0)


def data_refs_to(addresses: Iterable[int]) -> Iterator[int]:
    """What refers to `addresses`, and what refers to the cells among those."""
    for address in addresses:
        for source in idautils.DataRefsTo(address):
            yield source
            if is_cell(source):
                yield from idautils.DataRefsTo(source)


def data_refs_from(addresses: Iterable[int]) -> Iterator[int]:
    """What `addresses` refer to, and what the cells among those point at."""
    for address in addresses:
        for target in idautils.DataRefsFrom(address):
            yield target
            if is_cell(target):
                yield from idautils.DataRefsFrom(target)
