from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable, Iterator
import ida_bytes
import ida_nalt
import ida_name
import ida_segment
import idautils
from elfresolver.constraints import IDAConstraint
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.messages import ResolvedSymbol
from elfresolver.symbols import Symbol

if TYPE_CHECKING:
    from elfresolver.ida.resolution import Resolution

_PLT = (".plt", ".plt.sec", ".plt.got", ".iplt")
_GOT = (".got", ".got.plt")


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

    def bodies(self) -> Iterator[int]:
        """Every address the matches are made of."""
        return (address for match in self.resolve() for address in self.body(match))

    def referables(self) -> Iterator[int]:
        """Every address a call or a reference must land on to reach a match."""
        return (address for match in self.resolve() for address in self.referable(match))

    # The constraints every kind of symbol can carry.

    def matching(self, pattern: str) -> Iterable[int]:
        """The symbols of this kind with a name the regular expression `pattern` finds a match in."""
        regex = re.compile(pattern)
        return (address for address in self.all() if any(map(regex.search, self.names_of(address))))

    def references(self, target: IDASymbol) -> Iterable[int]:
        """The symbols of this kind referring to `target`'s address: as code taking it, or as data holding a pointer to it."""
        return self.owners(_references_to(target.referables()))

    def referenced_by(self, source: IDASymbol) -> Iterable[int]:
        """The symbols of this kind `source` refers to, directly or through a cell."""
        return self.owners(_references_from(source.bodies()))

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
        return name_forms(name, ida_name.demangle_name(name, 0)) if name else ()

    def body(self, address: int) -> Iterable[int]:
        """The addresses the symbol at `address` is made of: where its calls and references start."""
        return ()

    def referable(self, address: int) -> Iterable[int]:
        """The addresses a call or a reference must land on to reach the symbol at `address`."""
        return (address,)

    def found(self, address: int, name: str | None, size: int) -> ResolvedSymbol:
        """This symbol, found at `address`, named `name` and `size` bytes long."""
        return ResolvedSymbol(self.symbol, address, address - ida_nalt.get_imagebase(), name, size)

    # Where an address lies in the ELF image.

    @staticmethod
    def segment_name(address: int) -> str | None:
        segment = ida_segment.getseg(address)
        return ida_segment.get_segm_name(segment) if segment is not None else None

    @staticmethod
    def in_plt(address: int) -> bool:
        return IDASymbol.segment_name(address) in _PLT

    @staticmethod
    def in_code(address: int) -> bool:
        """True inside the binary's own code: an executable segment, other than the PLT."""
        segment = ida_segment.getseg(address)
        return segment is not None and segment.type == ida_segment.SEG_CODE and not IDASymbol.in_plt(address)

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


def name_forms(name: str, demangled: str | None) -> tuple[str, ...]:
    """Every form of a symbol's name it answers to: as linked, demangled, and demangled without its parameter list."""
    forms = [name] if demangled is None else [name, demangled, without_parameters(demangled)]
    return tuple(dict.fromkeys(forms))


def without_version(name: str) -> str:
    """An ELF symbol's name without its version: 'recvfrom@GLIBC_2.2.5' -> 'recvfrom'."""
    return name.partition("@")[0]


def without_parameters(name: str) -> str:
    """A demangled name without its parameter list: 'ns::Box<int>::get(int) const' -> 'ns::Box<int>::get'."""
    depth = 0
    for index in range(name.rfind(")"), -1, -1):
        depth += {")": 1, "(": -1}.get(name[index], 0)
        if depth == 0:
            return name[:index]
    return name


def _references_to(addresses: Iterable[int]) -> Iterator[int]:
    """What refers to `addresses`, and what refers to the cells among those."""
    for address in addresses:
        for source in idautils.DataRefsTo(address):
            yield source
            if _is_cell(source):
                yield from idautils.DataRefsTo(source)


def _references_from(addresses: Iterable[int]) -> Iterator[int]:
    """What `addresses` refer to, and what the cells among those point at."""
    for address in addresses:
        for target in idautils.DataRefsFrom(address):
            yield target
            if _is_cell(target):
                yield from idautils.DataRefsFrom(target)


def _is_cell(address: int) -> bool:
    """True for a cell that only holds a pointer for code to load: a GOT slot, or a data word inside code (an ARM literal pool)."""
    in_got = IDASymbol.segment_name(address) in _GOT
    return in_got or (IDASymbol.in_code(address) and ida_bytes.is_data(ida_bytes.get_flags(address)))
