from __future__ import annotations
import functools
from typing import Callable, Iterable, Iterator
import ida_bytes # type: ignore
from elfresolver.ida.layout import variable_segments
from elfresolver.ida.symbols.symbol import IDASymbol
from elfresolver.messages import ResolvedSymbol


class IDAString(IDASymbol):
    """A NUL-terminated string literal, named by its text."""

    def all(self) -> Iterable[int]:
        return _literals().keys()

    def owners(self, addresses: Iterable[int]) -> Iterator[int]:
        return (address for address in addresses if _text_at(address) is not None)

    def names_of(self, address: int) -> tuple[str, ...]:
        text = _text_at(address)
        return (text,) if text is not None else ()

    def describe(self, address: int) -> ResolvedSymbol:
        text = _text_at(address) or ""
        return self.found(address, text, len(text.encode()) + 1)


def c_strings(data: bytes, referenced: Callable[[int], bool] = lambda offset: False) -> Iterator[tuple[int, str]]:
    """Every C string literal in `data`: its offset and its text, printable UTF-8 a
    NUL ends. One starts after a NUL; or inside a run of text, at an offset
    `referenced` says something refers to. A linker merges a literal into the
    tail of a longer one, and a literal may follow other data with no NUL
    between: a double ending in 0x40 makes an '@' of it."""
    start = 0
    while (end := data.find(b"\0", start)) >= 0:
        if (text := _printable(data[start:end])) is not None:
            yield start, text
        for inner in range(start + 1, end):
            if referenced(inner) and (text := _printable(data[inner:end])) is not None:
                yield inner, text
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
def _literals() -> dict[int, str]:
    """Every C string literal where variables live, by its address (see c_strings)."""
    return {
        start + offset: text
        for start, data in _contents()
        for offset, text in c_strings(data, referenced=lambda offset, start=start: ida_bytes.has_xref(ida_bytes.get_flags(start + offset)))
    }


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
