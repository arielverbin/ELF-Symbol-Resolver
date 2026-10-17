"""
End-to-end tests: an ELFResolver starting the fake idat (see fake_idat.py),
which serves the real IDA's side of elfresolver, resolving in a FakeBinary.

  * Symbols resolve to their offsets from the image base, as the symbols they are.
  * Records logged on IDA's side are logged again on the resolver's.
  * An exception inside IDA raises IDAError, with IDA's traceback attached.
  * A database IDA analyzed afresh is cached, and later started on.
  * Ctrl+C cancels the resolve under way, and the resolver goes on working.
  * IDA dying before it's ready raises IDAStartupError, with its log attached; so does an impostor connecting first.
"""
import _thread
import logging
import threading
import pytest
from elfresolver import ELFResolver, Function, GlobalVar, PLTEntry, String
from elfresolver.exceptions import AmbiguousSymbolError, IDAError, IDAStartupError, SymbolNotFoundError
from fakes import example_binary

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)


@pytest.fixture
def resolver(fake_ida, cache, write_binary):
    with ELFResolver(write_binary(example_binary()), ida_dir=fake_ida, cache=cache) as resolver:
        yield resolver


def test_the_readme_example(resolver):
    parse = resolver.resolve(PARSER)
    served = resolver.resolve(GlobalVar().referenced_by(PARSER))
    assert (parse.symbol, parse.address, parse.offset, parse.name) == (PARSER, 0x401200, 0x1200, "sub_401200")
    assert (served.offset, served.size) == (0x4010, 8)


def test_resolve_all_returns_every_match_by_address(resolver):
    prompters = resolver.resolve_all(Function().references(String("enter input")))
    assert [prompter.address for prompter in prompters] == [0x401300, 0x401400]


def test_nothing_matching_raises(resolver):
    symbol = Function().called_by(Function().calls(PLTEntry("sendto")).references(String("enter input")))
    with pytest.raises(SymbolNotFoundError) as raised:
        resolver.resolve(symbol)
    assert str(raised.value) == f"Nothing matches {symbol!r}"


def test_several_matches_raise_with_every_match(resolver):
    with pytest.raises(AmbiguousSymbolError, match="2 matches for PLTEntry") as raised:
        resolver.resolve(PLTEntry())
    assert [match.name for match in raised.value.matches] == ["recvfrom", "puts"]


def test_records_logged_inside_ida_are_logged_again(fake_ida, cache, write_binary, caplog):
    caplog.set_level(logging.INFO, logger="elfresolver")
    with ELFResolver(write_binary(example_binary()), ida_dir=fake_ida, cache=cache) as resolver:
        resolver.resolve(READER)
    assert ("elfresolver.ida.server", logging.INFO, f"{READER!r}: 1 match(es)") in caplog.record_tuples


def test_an_exception_inside_ida_raises_with_its_traceback(fake_ida, cache, write_binary):
    binary = example_binary()
    binary.broken = True
    with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache) as resolver:
        with pytest.raises(IDAError, match="RuntimeError: The fake database is broken") as raised:
            resolver.resolve(READER)
        assert "Raised inside IDA" in raised.value.__notes__[0]


def test_a_fresh_analysis_is_cached_then_started_on(fake_ida, cache, write_binary, caplog):
    caplog.set_level(logging.INFO, logger="elfresolver")
    binary = write_binary(example_binary())
    for _ in range(2):
        with ELFResolver(binary, ida_dir=fake_ida, cache=cache) as resolver:
            assert resolver.resolve(READER).address == 0x401300
    analyzed_afresh = [record for record in caplog.messages if "analyzes it afresh" in record]
    assert len(analyzed_afresh) == 1
    assert len(list(cache.directory.glob("*.i64"))) == 1


def test_ctrl_c_cancels_the_resolve_and_the_resolver_goes_on(fake_ida, cache, write_binary, caplog):
    caplog.set_level(logging.INFO, logger="elfresolver")
    binary = example_binary()
    binary.delay = 0.2  # per lookup of cross-references: the resolve below takes most of a second
    slow = Function().called_by(Function().called_by(Function().called_by(PARSER)))
    with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache) as resolver:
        threading.Timer(0.3, _thread.interrupt_main).start()  # as if Ctrl+C was pressed
        with pytest.raises(KeyboardInterrupt):
            resolver.resolve(slow)
        assert f"Cancelled resolving {slow!r}" in caplog.messages  # logged inside IDA
        assert resolver.resolve(PLTEntry("recvfrom")).address == 0x401030


def test_ida_dying_before_it_is_ready_raises_with_its_log(fake_ida, cache, write_binary):
    binary = example_binary()
    binary.crash_on_start = 7
    with pytest.raises(IDAStartupError, match="exited with code 7") as raised:
        with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache):
            pass
    assert "Fake IDA crashed on start" in raised.value.__notes__[0]


def test_an_impostor_connecting_first_fails_the_startup(fake_ida, cache, write_binary):
    binary = example_binary()
    binary.impostor = True
    with pytest.raises(IDAStartupError, match="Something other than the IDA started here connected"):
        with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache):
            pass


def test_an_old_ida_python_is_explained(fake_ida, cache, write_binary):
    binary = example_binary()
    binary.crash_on_start = 3  # bootstrap.py's exit code for a Python older than 3.11
    with pytest.raises(IDAStartupError, match="idapyswitch"):
        with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache):
            pass


def test_nothing_is_cached_when_ida_dies(fake_ida, cache, write_binary):
    binary = example_binary()
    binary.crash_on_start = 7
    with pytest.raises(IDAStartupError):
        with ELFResolver(write_binary(binary), ida_dir=fake_ida, cache=cache):
            pass
    assert not cache.directory.exists() or not list(cache.directory.iterdir())
