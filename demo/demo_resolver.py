from __future__ import annotations
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from elfresolver import ELFResolver, ResolvedSymbol
from elfresolver.exceptions import IDAError, ResolutionError
from elfresolver.symbols import Symbol

_NM_LINE = re.compile(r"^([0-9a-f]+) (?:([0-9a-f]+) )?([A-Za-z]) (.+)$", re.MULTILINE)  # address, size (if known), type, name
_EM_ARM = 40  # the ELF header's e_machine for 32-bit ARM


@dataclass(frozen=True)
class Check:
    """
    One resolve, checked against the unstripped build: each match, with the name of the
    expected symbol it is (None: none of them); the expected symbols nothing matched; the
    error the resolve raised, if it did; and how long it took.
    """
    symbol: Symbol
    found: list[tuple[ResolvedSymbol, str | None]]
    missing: list[str]
    error: str | None
    seconds: float

    @property
    def passed(self) -> bool:
        return self.error is None and not self.missing and all(name is not None for _, name in self.found)


class DemoResolver:
    """
    Resolves a demonstration's symbols in the stripped build, and checks each answer against
    the unstripped build's symbol table: by the symbol's demangled name, with its parameters or
    without ("http::open_listener"). A name the symbol table doesn't have (a string's text, an
    import's) is checked against the match's own name. A wrong answer is recorded (see Check),
    and the demonstration goes on.
    """

    def __init__(self, stripped: Path, unstripped: Path, nm: str) -> None:
        """`nm` is the target's nm, which reads the unstripped build's symbol table: "x86_64-linux-gnu-nm"."""
        self._resolver = ELFResolver(stripped)
        self._symbols = self._symbol_spans(unstripped, nm)
        self.checks: list[Check] = []
        self.startup_seconds = 0.0

    def __enter__(self) -> DemoResolver:
        started = time.perf_counter()
        self._resolver.__enter__()
        self.startup_seconds = time.perf_counter() - started
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._resolver.__exit__(*exc_info)

    def resolve(self, symbol: Symbol, expected: str) -> None:
        """Resolves the one match of `symbol` (see ELFResolver.resolve), and checks that it's the symbol named `expected`."""
        self._check(symbol, [expected], lambda: [self._resolver.resolve(symbol)])

    def resolve_all(self, symbol: Symbol, expected: list[str]) -> None:
        """Resolves every match of `symbol` (see ELFResolver.resolve_all), and checks that they're the symbols named in `expected`."""
        self._check(symbol, expected, lambda: self._resolver.resolve_all(symbol))

    def _check(self, symbol: Symbol, expected: list[str], resolving: Callable[[], list[ResolvedSymbol]]) -> None:
        """Resolves `symbol` by `resolving`, timed, and checks its matches against `expected` (see Check)."""
        started = time.perf_counter()
        try:
            matches, error = resolving(), None
        except (ResolutionError, IDAError) as raised:
            matches, error = [], str(raised).splitlines()[0]
        seconds = time.perf_counter() - started
        spans = {name: self._spans_of(name, matches) for name in expected}
        found = [
            (match, next((name for name, places in spans.items() if any(match.address in place for place in places)), None))
            for match in matches
        ]
        missing = [
            name for name, places in spans.items()
            if not places or not all(any(match.address in place for match in matches) for place in places)
        ]
        self.checks.append(Check(symbol, found, missing, error, seconds))

    def _spans_of(self, name: str, matches: list[ResolvedSymbol]) -> list[range]:
        """
        Where the symbol named `name` is: the span of each symbol of the symbol table by that
        name (see _is_named; a match inside one, a struct's field, is it). A name the table
        doesn't have is where a match of that name is.
        """
        spans = [span for symbol, spans in self._symbols.items() if self._is_named(symbol, name) for span in spans]
        return spans or [range(match.address, match.address + 1) for match in matches if match.name == name]

    @staticmethod
    def _is_named(symbol: str, name: str) -> bool:
        """
        True if `symbol`, a demangled name, is `name`, with its parameter list or without:
        "f(int) const" is "f"; neither "f(int)::counter" (a static of f) nor "f(int) [clone .cold]"
        (a part GCC moved out of f) is.
        """
        if not symbol.startswith(f"{name}("):
            return symbol == name
        depth = 0
        for index in range(len(name), len(symbol)):
            depth += {"(": 1, ")": -1}.get(symbol[index], 0)
            if depth == 0:
                return symbol[index + 1:] in ("", " const")
        return False

    @staticmethod
    def _symbol_spans(unstripped: Path, nm: str) -> dict[str, list[range]]:
        """Where each symbol of `unstripped`'s symbol table is, by its demangled name (nm -C -S)."""
        with unstripped.open("rb") as binary:
            arm = int.from_bytes(binary.read(20)[18:20], "little") == _EM_ARM
        listing = subprocess.run([nm, "-C", "-S", "--defined-only", str(unstripped)], stdout=subprocess.PIPE, text=True, check=True).stdout
        spans: dict[str, list[range]] = {}
        for address, size, kind, name in _NM_LINE.findall(listing):
            start = int(address, 16)
            if arm and kind in "tTwW":
                start &= ~1  # a Thumb function's symbol is its address, plus one
            spans.setdefault(name, []).append(range(start, start + max(int(size or "0", 16), 1)))
        return spans
