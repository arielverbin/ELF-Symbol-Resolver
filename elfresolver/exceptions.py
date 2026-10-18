from __future__ import annotations
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from elfresolver.protocol.messages import ResolvedSymbol


class ELFResolverError(Exception):
    """Base exception for all elfresolver errors."""


class ResolutionError(ELFResolverError):
    """Base for a symbol that didn't resolve to exactly one match."""


class SymbolNotFoundError(ResolutionError):
    """Raised when nothing in the binary matches a symbol."""


class AmbiguousSymbolError(ResolutionError):
    """Raised when several things in the binary match a symbol expected to match one."""

    def __init__(self, message: str, matches: Sequence[ResolvedSymbol]) -> None:
        super().__init__(message)
        self.matches = tuple(matches)


class IDANotFoundError(ELFResolverError):
    """Raised when no IDA installation is found: pass `ida_dir`, or set $IDADIR."""


class IDAStartupError(ELFResolverError):
    """Raised when IDA exits, or doesn't connect back, before it is ready to resolve. The end of IDA's log is attached as a note."""


class IDAError(ELFResolverError):
    """
    Raised when an exception is raised inside IDA, or when IDA dies once it is
    ready. The traceback inside IDA, or the end of IDA's log, is attached as a note.
    """


class ResolveInterrupted(ELFResolverError):
    """Raised inside IDA when the resolver cancels the resolve under way (the resolver itself re-raises KeyboardInterrupt)."""
