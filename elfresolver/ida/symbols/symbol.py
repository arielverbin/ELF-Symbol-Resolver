from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable, Iterable, Iterator
import ida_bytes # type: ignore
import ida_nalt # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.constraints import IDAConstraint
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import Symbol

if TYPE_CHECKING:
    from elfresolver.ida.resolution import SymbolResolution


class IDASymbol(ABC):
    """A resolvable symbol, constructed from a ResolveRequest."""

    def __init__(self, symbol: Symbol, resolution: SymbolResolution) -> None:
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
        """The symbols of this kind `addresses` belong to: an instruction's function, a byte's variable."""

    @abstractmethod
    def describe(self, address: int) -> ResolvedSymbol:
        """The symbol at `address`, as resolve() hands it to the user (see found)."""

    def names_of(self, address: int) -> tuple[str, ...]:
        """Every name the symbol at `address` answers to: the forms of IDA's name for it (see Name.forms), if it has one."""
        name = ida_name.get_name(address)
        return SymName(name).forms if name else ()

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
