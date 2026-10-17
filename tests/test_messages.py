"""
Tests for the messages: every message comes back as it was sent, with its
symbols still hashable and equal to the symbols they were; every request has a
token of its own; nothing but a Serializable is built from what arrives.
"""
import pytest
from elfresolver import Function, GlobalVar, PLTEntry, ResolvedSymbol, String
from elfresolver.messages import (
    CancelRequest, CancelResponse, FailureResponse, HelloResponse, IDALaunchEnv, LogResponse, Message,
    ReadyResponse, ResolveRequest, ResolveResponse, ShutdownRequest,
)

SYMBOL = GlobalVar().referenced_by(
    Function().called_by(Function().calls(PLTEntry("recvfrom")).references(String("enter input")))
).matching("^g_")
TOKEN = "0123abcd"


@pytest.mark.parametrize("message", [
    IDALaunchEnv(port=50123, log_level=10, save_database=True),
    ResolveRequest(SYMBOL),
    CancelRequest(token=TOKEN),
    ShutdownRequest(),
    HelloResponse(token=TOKEN),
    LogResponse("elfresolver.ida.resolution", 20, "Resolved", 1760000000.25, token=TOKEN),
    ReadyResponse(token=TOKEN),
    ResolveResponse((ResolvedSymbol(SYMBOL, 0x404010, 0x4010, "g_served", 8),), token=TOKEN),
    FailureResponse("RuntimeError", "boom", "Traceback (most recent call last): ...", token=TOKEN),
    CancelResponse(token=TOKEN),
], ids=lambda message: type(message).__name__)
def test_a_message_comes_back_as_it_was_sent(message):
    assert Message.from_serialized(message.serialize()) == message


def test_a_symbol_comes_back_hashable_and_equal():
    resolve = Message.from_serialized(ResolveRequest(SYMBOL).serialize())
    assert resolve.symbol == SYMBOL
    assert hash(resolve.symbol) == hash(SYMBOL)


def test_a_symbol_comes_back_with_its_id():
    """So IDA's logs name a symbol, and every symbol in it, as the resolver's side does."""
    resolve = Message.from_serialized(ResolveRequest(SYMBOL).serialize())
    assert repr(resolve.symbol) == repr(SYMBOL)


def test_every_request_has_a_token_of_its_own():
    first, second = ResolveRequest(SYMBOL), ResolveRequest(SYMBOL)
    assert first.token != second.token
    assert len(first.token) == 32


def test_a_launch_travels_through_the_environment():
    launch = IDALaunchEnv(port=50123, log_level=30, save_database=False)
    assert IDALaunchEnv.from_dict({"PATH": "/usr/bin", **launch.to_dict()}) == launch


def test_an_unknown_type_is_refused():
    with pytest.raises(ValueError, match="'Exploit'"):
        Message.from_serialized('{"type": "Exploit"}')


def test_something_other_than_a_message_is_refused():
    with pytest.raises(ValueError, match="Not a Message"):
        Message.from_serialized(Function().serialize())
