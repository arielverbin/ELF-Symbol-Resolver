"""
Tests for how symbols resolve: IDA's real kinds, on the example binary open in
the stand-ins for IDA's modules (see fakes.example_binary and fake_ida_modules.py).

  * Every constraint allows the symbols it should, and a symbol's matches satisfy all its constraints.
  * A name is matched whole, and literally.
  * A symbol met again, alone or nested in another, is answered from memory.
  * An interrupted resolve raises ResolveInterrupted, and isn't remembered.
"""
import pytest
from elfresolver import Function, GlobalVar, PLTEntry, ResolvedSymbol, String
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.resolution import Resolution

RECVFROM, PUTS, PROMPT, SERVED = 0x401030, 0x401040, 0x402004, 0x404010
PARSE, READ, OTHER_PROMPTER, MAIN = 0x401200, 0x401300, 0x401400, 0x401500

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)


@pytest.fixture
def resolution(ida) -> Resolution:
    return Resolution()


def test_the_readme_example(resolution):
    assert resolution.of(READER).resolve() == {READ}
    assert resolution.of(PARSER).resolve() == {PARSE}
    assert resolution.of(GlobalVar().referenced_by(PARSER)).resolve() == {SERVED}


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
    assert resolution.of(symbol).resolve() == matches


def test_a_symbol_with_no_constraints_matches_everything_of_its_kind(resolution):
    assert resolution.of(PLTEntry()).resolve() == {RECVFROM, PUTS}


def test_a_function_is_never_a_plt_entry(resolution):
    """PLT stubs are called by the reader, yet the functions it calls are only the parser."""
    assert resolution.of(PLTEntry().called_by(READER)).resolve() == {RECVFROM, PUTS}
    assert resolution.of(Function().called_by(READER)).resolve() == {PARSE}


def test_a_symbol_nothing_matches(resolution):
    assert resolution.of(Function().calls(PLTEntry("sendto"))).resolve() == frozenset()


def test_a_name_is_matched_whole(resolution):
    """'enter input' ends with 'input', yet isn't named 'input': only a pattern finds part of a name."""
    assert resolution.of(String("input")).resolve() == frozenset()
    assert resolution.of(String().matching("input$")).resolve() == {PROMPT}


def test_a_name_is_matched_literally(resolution):
    """A '.' in a name is a dot, not a wildcard (which would match the 'c' of 'recvfrom')."""
    assert resolution.of(PLTEntry("re.vfrom")).resolve() == frozenset()


def test_a_match_is_described_as_the_user_gets_it(resolution):
    assert resolution.of(PARSER).describe(PARSE) == ResolvedSymbol(PARSER, PARSE, PARSE - 0x400000, "sub_401200", 0x40)


def test_a_symbol_met_again_is_answered_from_memory(ida, resolution):
    resolution.of(PARSER).resolve()
    resolution.of(GlobalVar().referenced_by(PARSER)).resolve()
    resolution.of(Function().calls(PLTEntry("recvfrom")).references(String("enter input"))).resolve()
    assert ida.xrefs_to_asked == [RECVFROM]  # the calls to recvfrom, which READER's .calls() looks up once


def test_an_interrupted_resolve_raises(ida):
    resolution = Resolution(interrupted=lambda: True)
    with pytest.raises(ResolveInterrupted):
        resolution.of(READER).resolve()


def test_an_interrupted_resolve_is_resolved_afresh_next_time(ida):
    interrupted = True
    resolution = Resolution(interrupted=lambda: interrupted)
    with pytest.raises(ResolveInterrupted):
        resolution.of(PARSER).resolve()
    interrupted = False
    assert resolution.of(PARSER).resolve() == {PARSE}
