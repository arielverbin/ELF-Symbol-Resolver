from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import Any, Callable, ClassVar, Iterable, Iterator
import ida_bytes # type: ignore
import ida_nalt # type: ignore
import ida_name # type: ignore
import idautils # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.names import SymName
from elfresolver.ida.resolution import SymbolResolution
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import Symbol


class IDASymbol(ABC):
    """
    A symbol, resolved by SymbolResolution: the address of each of its matches. Its class is
    its kind, which knows what the symbols of the kind are, and meets constraints on them
    with the class methods it marks (see SymbolResolution.constraint).
    """

    kinds: ClassVar[dict[type[Symbol], type[IDASymbol]]] = {}  # each kind of Symbol, and the IDASymbol resolving it

    def __init_subclass__(cls, kind: type[Symbol] | None = None, **kwargs: Any) -> None:
        """
        Subclasses mark which `Symbol` they solve.
        `class IDAFunction(IDASymbol, kind=Function)`: a Function resolves as an IDAFunction.
        """
        super().__init_subclass__(**kwargs)
        if kind is not None:
            IDASymbol.kinds[kind] = cls

    def __init__(self, symbol: Symbol, matches: frozenset[int]) -> None:
        self.symbol = symbol
        self.matches = matches

    # The constraints every kind of symbol can carry.

    @classmethod
    @SymbolResolution.constraint("matching", cost=1)
    def matching(cls, address: int, pattern: str) -> bool:
        """True if the symbol at `address` has a name the regular expression `pattern` finds a match in."""
        return any(re.search(pattern, name) for name in cls.names_of(address))

    @classmethod
    @SymbolResolution.constraint("references")
    def references(cls, target: IDASymbol) -> Iterable[int]:
        """The symbols of this kind referring to `target`: as code taking its address, or as data holding a pointer to it."""
        return cls.filter_from(target.references_to())

    @classmethod
    @SymbolResolution.constraint("referenced_by")
    def referenced_by(cls, source: IDASymbol) -> Iterable[int]:
        """The symbols of this kind `source` refers to."""
        return cls.filter_from(source.references_from())

    # What refers to the matches, and what they refer to: a kind with more to them than their address says so.

    def references_to(self) -> Iterable[int]:
        """Every address referring to one of the matches."""
        return self._data_refs(idautils.DataRefsTo, self.matches)

    def references_from(self) -> Iterable[int]:
        """Every address one of the matches refers to."""
        return self._data_refs(idautils.DataRefsFrom, self.matches)

    def parse_from(self, address: int) -> ResolvedSymbol:
        """The match at `address`, as the resolver hands it to the user."""
        return ResolvedSymbol(self.symbol, address, address - ida_nalt.get_imagebase(), self.display_name(address), self.size_of(address))

    # What this kind of symbol is.

    @classmethod
    @abstractmethod
    def all(cls) -> Iterable[int]:
        """The address of every symbol of this kind."""

    @classmethod
    @abstractmethod
    def filter_from(cls, addresses: Iterable[int]) -> Iterable[int]:
        """Filter `addresses` to only the ones pointing to the symbols of this kind."""

    @classmethod
    def names_of(cls, address: int, /) -> tuple[str, ...]:
        """Every name the symbol at `address` answers to: the forms of IDA's name for it (see SymName.forms), if it has one."""
        name = ida_name.get_name(address)
        return SymName(name).forms if name else ()

    @classmethod
    @abstractmethod
    def display_name(cls, address: int, /) -> str | None:
        """The name the symbol at `address` is handed to the user by (see parse_from), if it has one."""

    @classmethod
    @abstractmethod
    def size_of(cls, address: int, /) -> int:
        """How many bytes long the symbol at `address` is."""

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
