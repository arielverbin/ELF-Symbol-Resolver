"""
Tests for how symbols resolve: IDA's real kinds, on the example binary open in
the stand-ins for IDA's modules (see fakes.example_binary and fake_ida_modules.py).

  * Every constraint allows the symbols it should, and a symbol's matches satisfy all its constraints.
  * A name is matched whole, and literally.
  * A symbol met again, alone or nested in another, is answered from memory.
  * An interrupted resolve raises ResolveInterrupted, and isn't remembered.
  * A variable holding a function's pointer is found by it, and finds it.
"""
import logging
import pytest
import fake_ida_modules
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from elfresolver import ResolvedSymbol
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.resolution import SymbolResolution
from fakes import FakeBinary

RECVFROM, PUTS, PROMPT, SERVED = 0x401030, 0x401040, 0x402004, 0x404010
PARSE, READ, OTHER_PROMPTER, MAIN = 0x401200, 0x401300, 0x401400, 0x401500

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)


@pytest.fixture
def resolution(ida) -> SymbolResolution:
    return SymbolResolution()


def test_the_readme_example(resolution):
    assert resolution.as_resolvable(READER).resolve() == {READ}
    assert resolution.as_resolvable(PARSER).resolve() == {PARSE}
    assert resolution.as_resolvable(GlobalVar().referenced_by(PARSER)).resolve() == {SERVED}


@pytest.mark.parametrize(("symbol", "matches"), [
    (PLTEntry("recvfrom"), {RECVFROM}),
    (PLTEntry().matching("^re"), {RECVFROM}),
    (String("enter input"), {PROMPT}),
    (String().matching("input"), {PROMPT}),
    (Function().calls(PLTEntry("puts")), {READ, OTHER_PROMPTER}),
    (Function().called_by(Function().calls(PLTEntry("recvfrom"))), {PARSE}),
    (Function().references(String("enter input")), {READ, OTHER_PROMPTER}),
    (String().referenced_by(Function().called_by(Function())), {PROMPT}),
], ids=repr)
def test_each_constraint_allows_what_it_should(resolution, symbol, matches):
    assert resolution.as_resolvable(symbol).resolve() == matches


def test_a_symbol_with_no_constraints_matches_everything_of_its_kind(resolution):
    assert resolution.as_resolvable(PLTEntry()).resolve() == {RECVFROM, PUTS}


def test_a_function_is_never_a_plt_entry(resolution):
    """PLT stubs are called by the reader, yet the functions it calls are only the parser."""
    assert resolution.as_resolvable(PLTEntry().called_by(READER)).resolve() == {RECVFROM, PUTS}
    assert resolution.as_resolvable(Function().called_by(READER)).resolve() == {PARSE}


def test_a_symbol_nothing_matches(resolution):
    assert resolution.as_resolvable(Function().calls(PLTEntry("sendto"))).resolve() == frozenset()


def test_a_name_is_matched_whole(resolution):
    """'enter input' ends with 'input', yet isn't named 'input': only a pattern finds part of a name."""
    assert resolution.as_resolvable(String("input")).resolve() == frozenset()
    assert resolution.as_resolvable(String().matching("input$")).resolve() == {PROMPT}


def test_a_name_is_matched_literally(resolution):
    """A '.' in a name is a dot, not a wildcard (which would match the 'c' of 'recvfrom')."""
    assert resolution.as_resolvable(PLTEntry("re.vfrom")).resolve() == frozenset()


def test_a_match_is_described_as_the_user_gets_it(resolution):
    assert resolution.as_resolvable(PARSER).describe(PARSE) == ResolvedSymbol(PARSER, PARSE, PARSE - 0x400000, "sub_401200", 0x40)


def test_a_symbol_met_again_is_answered_from_memory(ida, resolution):
    resolution.as_resolvable(PARSER).resolve()
    resolution.as_resolvable(GlobalVar().referenced_by(PARSER)).resolve()
    resolution.as_resolvable(Function().calls(PLTEntry("recvfrom")).references(String("enter input"))).resolve()
    assert ida.xrefs_to_asked == [RECVFROM]  # the calls to recvfrom, which READER's .calls() looks up once


def test_an_interrupted_resolve_raises(ida):
    resolution = SymbolResolution(interrupted=lambda: True)
    with pytest.raises(ResolveInterrupted):
        resolution.as_resolvable(READER).resolve()


def test_an_interrupted_resolve_is_resolved_afresh_next_time(ida):
    interrupted = True
    resolution = SymbolResolution(interrupted=lambda: interrupted)
    with pytest.raises(ResolveInterrupted):
        resolution.as_resolvable(PARSER).resolve()
    interrupted = False
    assert resolution.as_resolvable(PARSER).resolve() == {PARSE}


def test_the_log_follows_the_recursion(resolution, caplog):
    """Each symbol logs its own resolve, one level deep, as the recursion reaches it: inner ones first to finish."""
    caplog.set_level(logging.INFO, logger="elfresolver.ida.resolution")
    recvfrom, prompt = PLTEntry("recvfrom"), String("enter input")
    reader = Function().calls(recvfrom).references(prompt)
    resolution.resolve(reader)
    resolution.resolve(Function().called_by(reader))
    assert caplog.messages[:6] == [
        f"Resolving {reader!r}",
        f"Resolving {recvfrom!r}",
        f"{recvfrom!r}: 1 match(es)",
        f"Resolving {prompt!r}",
        f"{prompt!r}: 1 match(es)",
        f"{reader!r}: 1 match(es)",
    ]
    assert f"{reader!r}: 1 match(es), resolved before" in caplog.messages[6:]


def test_an_import_is_named_without_its_version():
    binary = FakeBinary(image_base=0x400000)
    stub = binary.plt_entry(0x401030, "recvfrom@GLIBC_2.2.5")
    fake_ida_modules.open(binary)
    assert SymbolResolution().as_resolvable(PLTEntry("recvfrom")).resolve() == {stub}


@pytest.mark.parametrize("entry", [0x401140, 0x401141], ids=["even", "odd"])
def test_a_variable_holding_a_functions_pointer_is_found_by_it_and_finds_it(entry):
    """At -O0, x86's functions start anywhere, an odd address too: a pointer to one is still no jump table's (whose case addresses lie inside functions)."""
    binary = FakeBinary(image_base=0x400000)
    hook = binary.function(entry)
    pointer = binary.global_var(0x404010, "exit_hook", references=[hook])
    fake_ida_modules.open(binary)
    resolution = SymbolResolution()
    assert resolution.as_resolvable(GlobalVar().references(Function())).resolve() == {pointer}
    assert resolution.as_resolvable(Function().referenced_by(GlobalVar("exit_hook"))).resolve() == {hook}
