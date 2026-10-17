from __future__ import annotations
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Self
from elfresolver.exceptions import AmbiguousSymbolError, SymbolNotFoundError
from elfresolver.messages import ResolvedSymbol
from elfresolver.resolver.database_cache import DatabaseCache
from elfresolver.resolver.ida_session import IDASession, find_idat
from elfresolver.symbols import Symbol

logger = logging.getLogger(__name__)


class ELFResolver:
    """Resolves symbols in one ELF binary, with a headless IDA that starts when
    the `with` block is entered, and exits when it is left."""

    def __init__(
        self,
        binary: str | os.PathLike,
        *,
        ida_dir: str | os.PathLike | None = None,
        cache: DatabaseCache | None = None,
        startup_timeout: float = 120.0,
    ) -> None:
        """
        `ida_dir` is IDA's installation directory (by default, $IDADIR, or idat
        on PATH). `cache` keeps the database of each binary IDA analyzed (by
        default, in $ELFRESOLVER_CACHE or the platform's cache directory).
        """
        self._binary = Path(binary)
        if not self._binary.is_file():
            raise FileNotFoundError(f"No binary at {self._binary}")
        self._idat = find_idat(ida_dir)
        self._cache = cache if cache is not None else DatabaseCache()
        self._startup_timeout = startup_timeout
        # Inside the `with` block: the IDA resolving, and the directory of its files.
        self._session: IDASession | None = None
        self._workspace = Path()
        self._analyzed_afresh = False

    def __enter__(self) -> Self:
        self._workspace = Path(tempfile.mkdtemp(prefix="elfresolver-"))
        try:
            self._start_ida()
        except BaseException:
            shutil.rmtree(self._workspace, ignore_errors=True)
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        try:
            exit_code = self._session.close()
            if self._analyzed_afresh and exit_code == 0:
                self._cache.store(self._binary, self._database)
                logger.info("Cached the database of %s", self._binary)
        finally:
            self._session = None
            shutil.rmtree(self._workspace, ignore_errors=True)

    def resolve(self, symbol: Symbol) -> ResolvedSymbol:
        """The one match of `symbol`. Raises SymbolNotFoundError, or AmbiguousSymbolError with every match."""
        matches = self.resolve_all(symbol)
        if not matches:
            raise SymbolNotFoundError(f"Nothing matches {symbol!r}")
        if len(matches) > 1:
            listed = ", ".join(f"{match.address:#x} {match.name}" for match in matches)
            raise AmbiguousSymbolError(f"{len(matches)} matches for {symbol!r}: {listed}", matches)
        return matches[0]

    def resolve_all(self, symbol: Symbol) -> list[ResolvedSymbol]:
        """Every match of `symbol`, by address."""
        if self._session is None:
            raise RuntimeError("An ELFResolver resolves inside its `with` block only")
        return list(self._session.resolve(symbol))

    @property
    def _database(self) -> Path:
        """The database IDA works on: a copy of the cached one, or the one it analyzes the binary into."""
        return self._workspace / f"{self._binary.name}.i64"

    def _start_ida(self) -> None:
        """Start IDA on a copy of the binary's cached database, else on the binary itself, and wait until it's ready."""
        self._analyzed_afresh = not self._cache.copy_to(self._binary, self._database)
        if self._analyzed_afresh:
            logger.info("No cached database of %s: IDA analyzes it afresh", self._binary)
        target = self._binary if self._analyzed_afresh else self._database
        self._session = IDASession(
            self._idat, target, log=self._workspace / "ida.log",
            new_database=self._database if self._analyzed_afresh else None, timeout=self._startup_timeout,
        )
