from __future__ import annotations
import functools
from typing import Iterable, Iterator
import ida_bytes # type: ignore
from elfresolver.ida.layout import variable_segments
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.messages import ResolvedSymbol


class IDAString(IDASymbol):
    """A NUL-terminated string literal, named by its text."""

    def all(self) -> Iterator[int]:
        for start, data in _contents():
            yield from (start + offset for offset, _ in c_strings(data))

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        return (address for address in addresses if _text_at(address) is not None)

    def names_of(self, address: int) -> tuple[str, ...]:
        text = _text_at(address)
        return (text,) if text is not None else ()

    def describe(self, address: int) -> ResolvedSymbol:
        text = _text_at(address) or ""
        return self.found(address, text, len(text.encode()) + 1)


def c_strings(data: bytes) -> Iterator[tuple[int, str]]:
    """Every C string literal in `data`: its offset and its text (see c_string_at)."""
    start = 0
    while (end := data.find(b"\0", start)) >= 0:
        if (text := _printable(data[start:end])) is not None:
            yield start, text
        start = end + 1


def c_string_at(data: bytes, offset: int) -> str | None:
    """The text of the C string literal at `offset` in `data`, if one starts there: printable UTF-8, then a NUL."""
    end = data.find(b"\0", offset)
    return _printable(data[offset:end]) if end >= 0 else None


def _text_at(address: int) -> str | None:
    """The text of the C string literal starting at `address`, if one does."""
    for start, data in _contents():
        if start <= address < start + len(data):
            return c_string_at(data, address - start)
    return None


@functools.cache  # one IDA has one database open
def _contents() -> list[tuple[int, bytes]]:
    """The bytes of every initialized segment where variables live, each with its start address."""
    segments = (segment for segment in variable_segments() if ida_bytes.is_loaded(segment.start_ea))
    return [(segment.start_ea, ida_bytes.get_bytes(segment.start_ea, segment.size()) or b"") for segment in segments]


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode()
    except UnicodeDecodeError:
        return None
    return text if text and all(char.isprintable() or char in "\t\n\r" for char in text) else None
