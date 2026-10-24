"""
Tests against a real IDA, on the examples (examples/*.py), each built for every
target a cross compiler is installed for, then stripped (see real_ida.py):

  * Each example's resolve() finds only functions, globals and vtables of the
    unstripped build's symbol table (or a field of one).
  * main is a function, wherever the linker put it.
"""
from types import ModuleType
from typing import Iterator
import pytest
from elfresolver import ELFResolver, ResolvedSymbol
from elfresolver.symbols import Function, PLTEntry, String, Symbol
from examples import calculator, file_inspector, firmware, game_entities, http_server, log_pipeline
from real_ida import EXECUTABLES, REAL_IDA, Build, Program, limitation, opened

pytestmark = REAL_IDA

EXAMPLES: list[ModuleType] = [http_server, game_entities, firmware, file_inspector, log_pipeline, calculator]


class RecordingResolver:
    """
    A build's resolver, for an example's resolve() to use in place of its DemoResolver: remembering
    every match it finds, whatever the example expects (a known limitation may make it another).
    """

    def __init__(self, resolver: ELFResolver) -> None:
        self._resolver = resolver
        self.found: list[ResolvedSymbol] = []

    def resolve(self, symbol: Symbol, expected: str) -> None:
        self.found.append(self._resolver.resolve(symbol))

    def resolve_all(self, symbol: Symbol, expected: list[str]) -> None:
        self.found += self._resolver.resolve_all(symbol)


@pytest.fixture(
    scope="module", params=[(example, target) for example in EXAMPLES for target in EXECUTABLES],
    ids=lambda param: f"{param[0].NAME}-{param[1]}",
)
def example(request, tmp_path_factory) -> Iterator[tuple[ModuleType, Build]]:
    """An example, and its program built for a target, open in IDA."""
    module, target = request.param
    program = Program(module.NAME, module.SOURCE, flags=("-std=c++17",))
    with opened(program, target, tmp_path_factory.mktemp(f"{module.NAME}-{target}")) as build:
        yield module, build


def test_an_example_finds_only_symbols_of_the_unstripped_build(example, request):
    module, build = example
    limitation(request, when=module is firmware and "-no-pie" in build.target.flags, reason=(
        "without relocations, IDA types the settings by their widest access (an xmmword copy): the "
        "hostname's pointer inside is no offset"
    ))
    resolver = RecordingResolver(build.resolver)
    module.resolve(resolver)
    strays = [
        match for match in resolver.found
        if not isinstance(match.symbol, (String, PLTEntry)) and not build.symbols.around(match.address)  # strings and stubs have none
    ]
    assert not strays, [f"{match.address:#x} {match.name}" for match in strays]


def test_main_is_a_function(example):
    _, build = example
    assert build.symbols.address("main") in {match.address for match in build.resolve_all(Function())}
