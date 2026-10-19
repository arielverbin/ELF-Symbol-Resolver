from __future__ import annotations
import functools
from typing import Callable, Iterable, Iterator
import ida_bytes # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import String


class IDAString(IDASymbol, kind=String):
    """A NUL-terminated string literal, named by its text."""

    def all(self) -> Iterable[int]:
        return self.literals().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        return (address for address in addresses if address in self.literals())

    def names_of(self, address: int) -> tuple[str, ...]:
        return (self.literals()[address],)

    def describe(self, address: int) -> ResolvedSymbol:
        text = self.literals()[address]
        return self.found(address, text, len(text.encode()) + 1)

    @staticmethod
    @functools.cache  # one IDA has one database open
    def literals() -> dict[int, str]:
        """Every C string literal where variables live, by its address (see c_strings): where it starts, its text."""
        literals = {}
        for segment in Region.VARIABLES.segments():
            if not ida_bytes.is_loaded(segment.start_ea):
                continue  # .bss: no bytes yet
            data = ida_bytes.get_bytes(segment.start_ea, segment.size()) or b""
            referenced = lambda offset: ida_bytes.has_xref(ida_bytes.get_flags(segment.start_ea + offset))
            literals.update((segment.start_ea + offset, text) for offset, text in IDAString.c_strings(data, referenced))
        return literals

    @staticmethod
    def c_strings(data: bytes, referenced: Callable[[int], bool] = lambda offset: False) -> Iterator[tuple[int, str]]:
        """Every C string literal in `data`: its offset and its text (see c_string_at).
        One starts after a NUL; or inside a run of text, at an offset `referenced`
        says something refers to. A linker merges a literal into the tail of a longer
        one, and a literal may follow other data with no NUL between: a double ending
        in 0x40 makes an '@' of it."""
        start = 0
        while (end := data.find(b"\0", start)) >= 0:
            for offset in [start, *(inner for inner in range(start + 1, end) if referenced(inner))]:
                if (text := IDAString.c_string_at(data, offset)) is not None:
                    yield offset, text
            start = end + 1

    @staticmethod
    def c_string_at(data: bytes, offset: int) -> str | None:
        """The text of the C string literal at `offset` in `data`, if one starts there: printable UTF-8 (tabs and newlines too), then a NUL."""
        end = data.find(b"\0", offset)
        try:
            text = data[offset:end].decode() if end >= 0 else ""
        except UnicodeDecodeError:
            return None
        return text if text and all(char.isprintable() or char in "\t\n\r" for char in text) else None
