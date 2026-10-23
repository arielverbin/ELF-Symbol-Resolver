from __future__ import annotations
import functools
import re
from typing import Callable, Iterable, Iterator
import ida_bytes # type: ignore
from elfresolver.ida.layout import Region
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.protocol.messages import ResolvedSymbol
from elfresolver.symbols import String

_TEXT_MARKS = bytes(  # each byte's mark: '0' for a NUL, 't' where it may be text (printable ASCII, whitespace, or UTF-8's), 'x' elsewhere
    ord("0") if byte == 0 else ord("t") if 0x20 <= byte < 0x7F or byte in b"\t\n\r" or byte >= 0x80 else ord("x")
    for byte in range(256)
)
_TEXT_UP_TO_NUL = re.compile(rb"(?<!t)t++(?=0)")  # in the marks: a whole run of text, which a NUL ends
_WHITESPACE = str.maketrans("", "", "\t\n\r")  # what a literal holds besides printable text


class IDAString(IDASymbol, kind=String):
    """A NUL-terminated string literal, named by its text."""

    def all(self) -> Iterable[int]:
        return self.literals().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        return (address for address in addresses if address in self.literals())

    def names_of(self, address: int, /) -> tuple[str, ...]:
        return (self.literals()[address],)

    def describe(self, address: int, /) -> ResolvedSymbol:
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
            referenced = lambda offset: bool(ida_bytes.get_flags(segment.start_ea + offset) & ida_bytes.FF_REF)  # has_xref(), unwrapped
            literals.update((segment.start_ea + offset, text) for offset, text in IDAString.c_strings(data, referenced))
        return literals

    @staticmethod
    def c_strings(data: bytes, referenced: Callable[[int], bool] = lambda offset: False) -> Iterator[tuple[int, str]]:
        """Every C string literal in `data`: its offset and its text (see c_string_at).
        One starts after a NUL; or inside a run of text, at an offset `referenced`
        says something refers to. A linker merges a literal into the tail of a longer
        one, and a literal may follow other data with no NUL between: a double ending
        in 0x40 makes an '@' of it."""
        marks = data.translate(_TEXT_MARKS)
        for run in _TEXT_UP_TO_NUL.finditer(marks):
            start, end = run.span()
            after_a_nul = start == 0 or data[start - 1] == 0
            for offset in range(start, end):
                if (offset == start and after_a_nul or referenced(offset)) and (text := IDAString.c_string_at(data, offset)) is not None:
                    yield offset, text

    @staticmethod
    def c_string_at(data: bytes, offset: int) -> str | None:
        """The text of the C string literal at `offset` in `data`, if one starts there: printable UTF-8 (tabs and newlines too), then a NUL."""
        end = data.find(b"\0", offset)
        try:
            text = data[offset:end].decode() if end >= 0 else ""
        except UnicodeDecodeError:
            return None
        return text if text and text.translate(_WHITESPACE).isprintable() else None
