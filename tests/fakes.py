"""
A binary made up by a test, which the stand-ins for IDA's modules lay out as
IDA would show it (see fake_ida_modules.py).

    binary = FakeBinary()
    recvfrom = binary.plt_entry(0x1030, "recvfrom")
    reader = binary.function(0x1200, calls=[recvfrom])

Each fake symbol is one address, which is all its body too: calls and
references go from one symbol's address to another's.
"""
from __future__ import annotations
import json
from dataclasses import asdict, dataclass, field
from typing import Iterable


@dataclass
class FakeSymbol:
    kind: str           # the name of its Symbol class: "Function", "PLTEntry", ...
    name: str | None
    size: int


@dataclass
class FakeBinary:
    image_base: int = 0
    symbols: dict[int, FakeSymbol] = field(default_factory=dict)
    calls: list[tuple[int, int]] = field(default_factory=list)        # (caller, callee)
    references: list[tuple[int, int]] = field(default_factory=list)   # (source, target)
    constants: list[tuple[int, int]] = field(default_factory=list)    # (function, an immediate operand of its)
    delay: float = 0.0          # seconds each lookup of cross-references takes, for a test to cancel in time
    broken: bool = False        # every lookup of cross-references raises inside "IDA"
    crash_on_start: int = 0     # the exit code "IDA" exits with before connecting back, if any
    impostor: bool = False      # something other than "IDA" connects back first, and doesn't know the launch's token

    def function(self, address: int, *, calls: Iterable[int] = (), references: Iterable[int] = (), constants: Iterable[int] = ()) -> int:
        self.calls += [(address, callee) for callee in calls]
        self.references += [(address, target) for target in references]
        self.constants += [(address, value) for value in constants]
        return self._add(address, FakeSymbol("Function", f"sub_{address:X}", 0x40))

    def plt_entry(self, address: int, name: str) -> int:
        return self._add(address, FakeSymbol("PLTEntry", name, 0x10))

    def global_var(self, address: int, name: str | None = None, *, references: Iterable[int] = ()) -> int:
        self.references += [(address, target) for target in references]
        return self._add(address, FakeSymbol("GlobalVar", name or f"qword_{address:X}", 8))

    def string(self, address: int, text: str, *, mistyped: bool = False) -> int:
        """A string literal; `mistyped`, one IDA typed as data (as it may a short one, which looks like a pointer)."""
        return self._add(address, FakeSymbol("MistypedString" if mistyped else "String", text, len(text) + 1))

    def to_json(self) -> str:
        return json.dumps({**asdict(self), "symbols": {str(address): asdict(symbol) for address, symbol in self.symbols.items()}})

    @classmethod
    def from_json(cls, text: str) -> FakeBinary:
        fields = json.loads(text)
        symbols = {int(address): FakeSymbol(**symbol) for address, symbol in fields.pop("symbols").items()}
        calls, references, constants = (list(map(tuple, fields.pop(edges))) for edges in ("calls", "references", "constants"))
        return cls(**fields, symbols=symbols, calls=calls, references=references, constants=constants)

    def _add(self, address: int, symbol: FakeSymbol) -> int:
        self.symbols[address] = symbol
        return address


def example_binary() -> FakeBinary:
    """
    The server of the README's example: one function reads a request (it calls
    recvfrom, and prompts "enter input"), and the function it calls parses it,
    counting requests in a global. Another function prompts too, but reads nothing.
    """
    binary = FakeBinary(image_base=0x400000)
    recvfrom = binary.plt_entry(0x401030, "recvfrom")
    puts = binary.plt_entry(0x401040, "puts")
    prompt = binary.string(0x402004, "enter input")
    served = binary.global_var(0x404010)
    parse = binary.function(0x401200, references=[served])
    read = binary.function(0x401300, calls=[recvfrom, puts, parse], references=[prompt])
    binary.function(0x401400, calls=[puts], references=[prompt])
    binary.function(0x401500, calls=[read])
    return binary
