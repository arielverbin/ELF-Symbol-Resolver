"""Tests for the database cache: databases are kept by binary content, and handed out as copies."""
from pathlib import Path
from elfresolver import DatabaseCache


def _write(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


def test_nothing_is_copied_before_a_database_is_stored(tmp_path, cache):
    binary = _write(tmp_path / "server", b"\x7fELF one build")
    assert not cache.copy_to(binary, tmp_path / "copy.i64")
    assert not (tmp_path / "copy.i64").exists()


def test_a_stored_database_is_copied_out(tmp_path, cache):
    binary = _write(tmp_path / "server", b"\x7fELF one build")
    cache.store(binary, _write(tmp_path / "analyzed.i64", b"IDA database"))
    assert cache.copy_to(binary, tmp_path / "copy.i64")
    assert (tmp_path / "copy.i64").read_bytes() == b"IDA database"


def test_databases_are_kept_by_content_not_by_path(tmp_path, cache):
    binary = _write(tmp_path / "server", b"\x7fELF one build")
    cache.store(binary, _write(tmp_path / "analyzed.i64", b"IDA database"))
    same_build = _write(tmp_path / "renamed", b"\x7fELF one build")
    other_build = _write(tmp_path / "server-arm", b"\x7fELF another build")
    assert cache.copy_to(same_build, tmp_path / "same.i64")
    assert not cache.copy_to(other_build, tmp_path / "other.i64")


def test_storing_leaves_no_staged_files_behind(tmp_path, cache):
    binary = _write(tmp_path / "server", b"\x7fELF one build")
    cache.store(binary, _write(tmp_path / "analyzed.i64", b"IDA database"))
    assert [path.suffix for path in cache.directory.iterdir()] == [".i64"]


def test_the_default_directory_is_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("ELFRESOLVER_CACHE", str(tmp_path))
    assert DatabaseCache.default_directory() == tmp_path
    assert DatabaseCache().directory == tmp_path
