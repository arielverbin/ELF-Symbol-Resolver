"""
+--------------------------------------------------------------------+
|                 -+* Tests created with Claude! *+-                 |
+--------------------------------------------------------------------+

Shared fixtures. Most tests need no IDA: IDA's side runs on stand-ins for
IDA's modules over a FakeBinary (see fake_ida_modules.py), in this process, or
in a fake idat (see fake_idat.py) started in place of IDA's. The tests marked
`ida` run the real one, found in $IDADIR.
"""
import sys
from pathlib import Path
import pytest
import fake_ida_modules
from elfresolver import DatabaseCache
from fakes import FakeBinary, example_binary

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent

fake_ida_modules.install()  # before any test imports IDA's side of elfresolver


@pytest.fixture
def ida() -> fake_ida_modules.FakeIDA:
    """The example binary (see fakes.example_binary), open in the stand-ins for IDA's modules."""
    return fake_ida_modules.open(example_binary())


@pytest.fixture
def fake_ida(tmp_path: Path) -> Path:
    """An IDA installation directory holding the fake idat (see fake_idat.py)."""
    if sys.platform == "win32":
        pytest.skip("The fake idat is a script with a shebang")
    directory = tmp_path / "ida"
    directory.mkdir()
    idat = directory / "idat"
    idat.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.path[:0] = {[str(TESTS), str(ROOT)]!r}\n"
        "from fake_idat import main\n"
        "sys.exit(main(sys.argv[1:]))\n"
    )
    idat.chmod(0o755)
    return directory


@pytest.fixture
def cache(tmp_path: Path) -> DatabaseCache:
    return DatabaseCache(tmp_path / "cache")


@pytest.fixture
def write_binary(tmp_path: Path):
    """Writes a FakeBinary where the resolver can be pointed at it, as if it were an ELF."""
    def write(binary: FakeBinary, name: str = "server.stripped") -> Path:
        path = tmp_path / name
        path.write_text(binary.to_json())
        return path
    return write
