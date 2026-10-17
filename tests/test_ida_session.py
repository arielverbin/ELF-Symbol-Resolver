"""Tests for finding IDA, and for the command line it is started with."""
import os
import sys
from pathlib import Path
import pytest
from elfresolver.exceptions import IDANotFoundError
from elfresolver.resolver.ida_session import _command, find_idat

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX executables")


def _installation(directory: Path, *executables: str) -> Path:
    directory.mkdir()
    for name in executables:
        (directory / name).touch(mode=0o755)
    return directory


def test_idat64_is_preferred_over_idat(tmp_path):
    """IDA 8 has both: idat64 opens every binary, idat 32-bit ones only."""
    ida = _installation(tmp_path / "ida", "idat", "idat64")
    assert find_idat(ida) == ida / "idat64"


def test_idat_alone_is_found(tmp_path):
    """IDA 9 has idat only."""
    ida = _installation(tmp_path / "ida", "idat")
    assert find_idat(ida) == ida / "idat"


def test_idadir_is_searched_without_an_ida_dir(tmp_path, monkeypatch):
    ida = _installation(tmp_path / "ida", "idat")
    monkeypatch.setenv("IDADIR", str(ida))
    assert find_idat() == ida / "idat"


def test_a_missing_idat_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("IDADIR", raising=False)
    monkeypatch.setenv("PATH", str(_installation(tmp_path / "empty")))
    with pytest.raises(IDANotFoundError, match="IDADIR"):
        find_idat()


def test_the_command_line_of_a_fresh_analysis():
    command = _command(Path("/ida/idat"), Path("/bin/server"), Path("/work/ida.log"), Path("/work/server.i64"))
    assert command[:2] == ["/ida/idat", "-A"]
    assert command[2].startswith('-S"') and command[2].endswith(f'{os.sep}bootstrap.py"')
    assert command[3:] == ["-L/work/ida.log", "-o/work/server.i64", "/bin/server"]


def test_the_command_line_of_a_cached_database():
    command = _command(Path("/ida/idat"), Path("/work/server.i64"), Path("/work/ida.log"), None)
    assert command[3:] == ["-L/work/ida.log", "/work/server.i64"]
