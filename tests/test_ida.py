"""
Tests against a real IDA (set $IDADIR; skipped without one). One C program
(server.c) is built for every architecture and optimization level a compiler
is installed for, then stripped. The same symbols must resolve, in every build,
to where the unstripped build's symbol table puts the functions and variables
they describe.

Databases go to the cache elfresolver uses by default (see DatabaseCache), so
only the first run waits for IDA's auto-analysis of each build.
"""
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
import pytest
ELFFile = pytest.importorskip("elftools.elf.elffile", reason="pyelftools isn't installed").ELFFile
from elfresolver import ELFResolver
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from elfresolver.exceptions import IDANotFoundError, SymbolNotFoundError
from elfresolver.resolver.ida_session import find_idat
from conftest import TESTS


def _ida_is_installed() -> bool:
    try:
        find_idat()
    except IDANotFoundError:
        return False
    return True


pytestmark = [pytest.mark.ida, pytest.mark.skipif(not _ida_is_installed(), reason="No IDA: set $IDADIR")]


@dataclass(frozen=True)
class Build:
    name: str
    compiler: str
    flags: tuple[str, ...]


# By target triplet, never plain gcc: Debian names a native compiler that way too.
BUILDS = [
    Build("x86_64-O0", "x86_64-linux-gnu-gcc", ("-O0",)),
    Build("x86_64-O2", "x86_64-linux-gnu-gcc", ("-O2",)),
    Build("x86_64-O2-no-pie", "x86_64-linux-gnu-gcc", ("-O2", "-no-pie")),
    Build("x86_64-O2-shared", "x86_64-linux-gnu-gcc", ("-O2", "-fPIC", "-shared")),
    Build("i686-O2", "i686-linux-gnu-gcc", ("-O2",)),
    Build("aarch64-O2", "aarch64-linux-gnu-gcc", ("-O2",)),
    Build("armhf-O2", "arm-linux-gnueabihf-gcc", ("-O2",)),
]

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)
COUNTER = GlobalVar().referenced_by(PARSER)


def _build(build: Build, directory: Path) -> tuple[Path, Path]:
    """server.c built as `build`: unstripped, and stripped."""
    if shutil.which(build.compiler) is None:
        pytest.skip(f"{build.compiler} isn't installed")
    unstripped, stripped = directory / f"{build.name}.elf", directory / f"{build.name}.stripped"
    subprocess.run([build.compiler, *build.flags, str(TESTS / "server.c"), "-o", str(unstripped)], check=True)
    shutil.copyfile(unstripped, stripped)
    subprocess.run([build.compiler.removesuffix("gcc") + "strip", str(stripped)], check=True)
    return unstripped, stripped


@dataclass(frozen=True)
class SymbolTable:
    """Where the unstripped build puts its symbols, and where its image starts."""
    addresses: dict[str, int]
    image_base: int

    @classmethod
    def of(cls, path: Path) -> "SymbolTable":
        with open(path, "rb") as file:
            elf = ELFFile(file)
            thumb = elf["e_machine"] == "EM_ARM"
            addresses = {
                symbol.name.partition(".")[0]: symbol["st_value"] & ~1 if thumb else symbol["st_value"]  # parse_request.isra.0
                for symbol in elf.get_section_by_name(".symtab").iter_symbols()
                if symbol["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT")
            }
            loads = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]
            image_base = min(segment["p_vaddr"] & ~(segment["p_align"] - 1) for segment in loads)
        return cls(addresses, image_base)


@pytest.mark.parametrize("build", BUILDS, ids=lambda build: build.name)
def test_the_same_symbols_resolve_in_every_build(build, tmp_path):
    unstripped, stripped = _build(build, tmp_path)
    expected = SymbolTable.of(unstripped)
    with ELFResolver(stripped) as resolver:
        for name, symbol in [("read_request", READER), ("parse_request", PARSER), ("requests_served", COUNTER)]:
            resolved = resolver.resolve(symbol)
            assert resolved.address == expected.addresses[name], name
            assert resolved.offset == expected.addresses[name] - expected.image_base, name


def test_a_symbol_nothing_matches_raises(tmp_path):
    _, stripped = _build(BUILDS[1], tmp_path)
    with ELFResolver(stripped) as resolver:
        with pytest.raises(SymbolNotFoundError, match=r"^Nothing matches Function\(\)\.calls\(PLTEntry\('sendto'\)\)$"):
            resolver.resolve(Function().calls(PLTEntry("sendto")))
