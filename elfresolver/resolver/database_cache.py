from __future__ import annotations
import hashlib
import os
import secrets
import shutil
import sys
from pathlib import Path


class DatabaseCache:
    """A directory of IDA databases, one per binary content.

    An entry is keyed by the SHA-256 of a binary's content, and is never opened in
    place: IDA always works on a copy (copying takes seconds, analysis minutes), so
    neither concurrent resolvers nor a crashed IDA can corrupt one. A database is
    stored only once its IDA has exited cleanly, and atomically."""

    def __init__(self, directory: str | os.PathLike | None = None) -> None:
        self.directory = Path(directory) if directory is not None else self.default_directory()

    def copy_to(self, binary: Path, destination: Path) -> bool:
        """Copy the database of `binary` to `destination`; False if none is stored."""
        entry = self._entry_of(binary)
        if not entry.is_file():
            return False
        shutil.copyfile(entry, destination)
        return True

    def store(self, binary: Path, database: Path) -> None:
        """Keep `database` as the database of `binary` (it is moved away)."""
        entry = self._entry_of(binary)
        entry.parent.mkdir(parents=True, exist_ok=True)
        staged = entry.with_name(f"{entry.name}.{secrets.token_hex(4)}.tmp")  # its own, should another resolver store too
        shutil.move(database, staged)
        os.replace(staged, entry)

    @staticmethod
    def default_directory() -> Path:
        """$ELFRESOLVER_CACHE, else elfresolver's directory in the platform's cache directory."""
        if configured := os.environ.get("ELFRESOLVER_CACHE"):
            return Path(configured)
        if sys.platform == "win32":
            caches = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        elif sys.platform == "darwin":
            caches = Path.home() / "Library" / "Caches"
        else:
            caches = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        return caches / "elfresolver"

    def _entry_of(self, binary: Path) -> Path:
        """Where the database of `binary` is kept: by the SHA-256 of its content."""
        with open(binary, "rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        return self.directory / f"{digest}.i64"
