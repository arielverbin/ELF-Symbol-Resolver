"""
Real builds, for the tests marked `ida`. A program, given as its source, is built
for every target a cross compiler is installed for (the others are skipped), then
stripped, then opened in a real IDA (found through $IDADIR; skipped without one).

What a symbol must resolve to is what the unstripped build's symbol table says:
by the demangled name its compiler gave each function and variable (nm -C), with
its address and size. A program is built from the same file name every time, so
its builds are the same bytes on every run, and IDA analyzes each once (see
DatabaseCache).

    SERVER = Program("server", SOURCE)
    server = module_fixture(SERVER, TARGETS)       # one IDA per target, for the module's tests

    def test_the_reader(server):
        server.resolves(READER, to="net::read_request(int)")
"""
from __future__ import annotations
import re
import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator
import pytest
from elfresolver import ELFResolver, ResolvedSymbol
from elfresolver.exceptions import IDANotFoundError
from elfresolver.resolver.ida_installation import IDAInstallation
from elfresolver.symbols import Symbol

ELFFile = pytest.importorskip("elftools.elf.elffile", reason="pyelftools isn't installed").ELFFile


def _ida_is_installed() -> bool:
    try:
        IDAInstallation.find()
    except IDANotFoundError:
        return False
    return True


REAL_IDA = [pytest.mark.ida, pytest.mark.skipif(not _ida_is_installed(), reason="No IDA: set $IDADIR")]


@dataclass(frozen=True)
class Target:
    """What to build for: by target triplet, never plain gcc (Debian names a native compiler that way too)."""
    name: str
    triplet: str
    flags: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.name


EXECUTABLES = [
    Target("x86_64-O0", "x86_64-linux-gnu", ("-O0",)),
    Target("x86_64-O2", "x86_64-linux-gnu", ("-O2",)),
    Target("x86_64-O2-no-pie", "x86_64-linux-gnu", ("-O2", "-no-pie")),
    Target("x86_64-O3", "x86_64-linux-gnu", ("-O3",)),
    Target("i686-O2", "i686-linux-gnu", ("-O2",)),
    Target("aarch64-O0", "aarch64-linux-gnu", ("-O0",)),
    Target("aarch64-O2", "aarch64-linux-gnu", ("-O2",)),
    Target("armhf-O2", "arm-linux-gnueabihf", ("-O2",)),
]

SHARED_OBJECTS = [
    Target("x86_64-O0-shared", "x86_64-linux-gnu", ("-O0", "-fPIC", "-shared")),
    Target("x86_64-O2-shared", "x86_64-linux-gnu", ("-O2", "-fPIC", "-shared")),
    Target("i686-O2-shared", "i686-linux-gnu", ("-O2", "-fPIC", "-shared")),
    Target("aarch64-O2-shared", "aarch64-linux-gnu", ("-O2", "-fPIC", "-shared")),
    Target("armhf-O2-shared", "arm-linux-gnueabihf", ("-O2", "-fPIC", "-shared")),
]


@dataclass(frozen=True)
class Program:
    """A program to build: one file of C or C++ source."""
    name: str
    source: str
    language: str = "c++"
    flags: tuple[str, ...] = ()

    @property
    def file_name(self) -> str:
        return f"{self.name}.{'cpp' if self.language == 'c++' else 'c'}"

    def compiler(self, target: Target) -> str:
        return f"{target.triplet}-{'g++' if self.language == 'c++' else 'gcc'}"


@dataclass(frozen=True)
class SymbolTable:
    """Where the unstripped build puts each symbol, by its demangled name: every (address, size) of that name."""
    symbols: dict[str, list[tuple[int, int]]]
    image_base: int

    _LINE = re.compile(r"^([0-9a-f]+) (?:([0-9a-f]+) )?([A-Za-z]) (.+)$")

    @classmethod
    def of(cls, path: Path, target: Target) -> SymbolTable:
        listing = subprocess.run(
            [f"{target.triplet}-nm", "-C", "-S", "--defined-only", path.name],
            cwd=path.parent, capture_output=True, text=True, check=True,
        ).stdout
        symbols: dict[str, list[tuple[int, int]]] = {}
        for line in listing.splitlines():
            if (parsed := cls._LINE.match(line)) is None:
                continue
            address, size, kind, name = int(parsed[1], 16), int(parsed[2] or "0", 16), parsed[3], parsed[4]
            if target.triplet.startswith("arm") and kind in "tTwW":
                address &= ~1  # a Thumb function's symbol is its address, plus one
            symbols.setdefault(name, []).append((address, size))
        with open(path, "rb") as file:
            loads = [segment for segment in ELFFile(file).iter_segments() if segment["p_type"] == "PT_LOAD"]
            image_base = min(segment["p_vaddr"] & ~(segment["p_align"] - 1) for segment in loads)
        return cls(symbols, image_base)

    def address(self, name: str) -> int:
        """The address of the symbol named `name`; it must be one."""
        addresses = {address for address, _ in self._entries(name)}
        assert len(addresses) == 1, f"{name!r} names {len(addresses)} addresses in the symbol table: {sorted(map(hex, addresses))}"
        return addresses.pop()

    def range_of(self, name: str) -> range:
        """The addresses the symbol named `name` spans."""
        ((address, size),) = set(self._entries(name))
        return range(address, address + max(size, 1))

    def names(self, *parts: str) -> list[str]:
        """Every symbol name with all of `parts` in it."""
        return sorted(name for name in self.symbols if all(part in name for part in parts))

    def only_name(self, *parts: str) -> str:
        """The one symbol name with all of `parts` in it."""
        (name,) = self.names(*parts) or [None]
        assert name is not None, f"no symbol has {parts} in its name"
        return name

    def at(self, address: int) -> list[str]:
        """Every symbol at `address`."""
        return sorted(name for name, entries in self.symbols.items() if any(start == address for start, _ in entries))

    def around(self, address: int) -> list[str]:
        """Every symbol spanning `address` (a size-less one, at it)."""
        return sorted(
            name for name, entries in self.symbols.items()
            if any(start <= address < start + max(size, 1) for start, size in entries)
        )

    def _entries(self, name: str) -> list[tuple[int, int]]:
        assert name in self.symbols, f"no symbol is named {name!r}; with a like name: {self.names(name.split('(')[0])[:10]}"
        return self.symbols[name]


class Build:
    """A program built for a target, stripped, and open in IDA; and its unstripped symbol table, to check against."""

    def __init__(self, program: Program, target: Target, resolver: ELFResolver, symbols: SymbolTable) -> None:
        self.program = program
        self.target = target
        self.resolver = resolver
        self.symbols = symbols

    def resolve(self, symbol: Symbol) -> ResolvedSymbol:
        found = self.resolver.resolve(symbol)
        assert found.offset == found.address - self.symbols.image_base
        return found

    def resolve_all(self, symbol: Symbol) -> list[ResolvedSymbol]:
        return self.resolver.resolve_all(symbol)

    def resolves(self, symbol: Symbol, *, to: str) -> ResolvedSymbol:
        """Check that `symbol` resolves to the symbol named `to`."""
        found = self.resolve(symbol)
        expected = self.symbols.address(to)
        assert found.address == expected, f"{to!r} is at {expected:#x}, but found {found.address:#x}: {self._described(found.address)}"
        return found

    def resolves_within(self, symbol: Symbol, *, to: str) -> ResolvedSymbol:
        """Check that `symbol` resolves to an address inside the symbol named `to` (a part of a vtable, of a struct)."""
        found = self.resolve(symbol)
        span = self.symbols.range_of(to)
        assert found.address in span, f"{to!r} spans {span.start:#x}-{span.stop:#x}, but found {found.address:#x}: {self._described(found.address)}"
        return found

    def resolves_all(self, symbol: Symbol, *, to: Iterable[str]) -> list[ResolvedSymbol]:
        """Check that `symbol` resolves to exactly the symbols named in `to`."""
        found = self.resolve_all(symbol)
        expected = {self.symbols.address(name): name for name in to}
        missing = [name for address, name in expected.items() if address not in {match.address for match in found}]
        extra = [self._described(match.address) for match in found if match.address not in expected]
        assert not missing and not extra, f"missing {missing}, and found besides: {extra}"
        return found

    def resolves_all_within(self, symbol: Symbol, *, to: Iterable[str]) -> list[ResolvedSymbol]:
        """Check that every match of `symbol` lies inside one of the symbols named in `to`, and that each of those has one."""
        found = self.resolve_all(symbol)
        spans = {name: self.symbols.range_of(name) for name in to}
        outside = [self._described(match.address) for match in found if not any(match.address in span for span in spans.values())]
        missed = [name for name, span in spans.items() if not any(match.address in span for match in found)]
        assert not outside and not missed, f"found outside them: {outside}, and none inside {missed}"
        return found

    def resolves_to_one_of(self, symbol: Symbol, names: Iterable[str]) -> ResolvedSymbol:
        """Check that `symbol` resolves to one of the symbols named in `names`: where the compiler may have put the code."""
        found = self.resolve(symbol)
        expected = {self.symbols.address(name): name for name in names}
        assert found.address in expected, f"expected one of {sorted(expected.values())}, but found {found.address:#x}: {self._described(found.address)}"
        return found

    def _described(self, address: int) -> str:
        return f"{address:#x} {self.symbols.at(address) or self.symbols.around(address) or '(no symbol)'}"


def _built(program: Program, target: Target, directory: Path) -> tuple[Path, Path]:
    """`program` built for `target` in `directory`: unstripped, and stripped."""
    compiler = program.compiler(target)
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} isn't installed")
    (directory / program.file_name).write_text(program.source)
    unstripped, stripped = directory / f"{program.name}.elf", directory / f"{program.name}.stripped"
    subprocess.run(
        [compiler, *target.flags, *program.flags, program.file_name, "-o", unstripped.name],
        cwd=directory, check=True, capture_output=True,
    )
    shutil.copyfile(unstripped, stripped)
    subprocess.run([f"{target.triplet}-strip", stripped.name], cwd=directory, check=True)
    return unstripped, stripped


@contextmanager
def opened(program: Program, target: Target, directory: Path) -> Iterator[Build]:
    """`program`, built for `target` and open in IDA, for the block."""
    unstripped, stripped = _built(program, target, directory)
    symbols = SymbolTable.of(unstripped, target)
    with ELFResolver(stripped) as resolver:
        yield Build(program, target, resolver, symbols)


def limitation(request: pytest.FixtureRequest, reason: str, *, when: bool = True) -> None:
    """Mark the test under way as failing for a known reason, `when` it holds: it still runs, and passing says it's fixed (XPASS)."""
    if when:
        request.node.add_marker(pytest.mark.xfail(reason=reason, strict=False))


def module_fixture(program: Program, targets: list[Target]):
    """A fixture giving the Build of `program` for each of `targets` in turn, open in one IDA for all of a module's tests."""
    @pytest.fixture(scope="module", params=targets, ids=str)
    def build(request, tmp_path_factory) -> Iterator[Build]:
        with opened(program, request.param, tmp_path_factory.mktemp(f"{program.name}-{request.param}")) as built:
            yield built
    return build
