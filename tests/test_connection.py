"""
Tests for the connection between the resolver and IDA.

  * Messages arrive whole, however the frames carrying them are split.
  * receive() returns None once its timeout passes, and raises once the other side has gone.
  * A Listener hands over the connection made to its port, and messages pass both ways.
"""
import socket
import struct
import threading
import pytest
from elfresolver.symbols import Function, PLTEntry
from elfresolver.protocol.connection import Connection, Listener
from elfresolver.protocol.messages import CancelRequest, HelloResponse, ResolveRequest, ShutdownRequest

TOKEN = "0123abcd"


@pytest.fixture
def pair():
    left, right = socket.socketpair()
    with Connection(left) as near, Connection(right) as far:
        yield near, far


def test_messages_arrive_in_order(pair):
    near, far = pair
    resolve, shutdown = ResolveRequest(Function().calls(PLTEntry("recvfrom"))), ShutdownRequest()
    near.send(resolve)
    near.send(shutdown)
    assert far.receive(timeout=1) == resolve
    assert far.receive(timeout=1) == shutdown


def test_a_frame_split_across_reads_arrives_whole():
    left, right = socket.socketpair()
    cancel = CancelRequest(token=TOKEN)
    frame = cancel.serialize()
    data = struct.pack(">I", len(frame)) + frame
    with Connection(right) as far:
        for index in range(len(data)):  # one byte at a time
            assert far.receive(timeout=0) is None
            left.send(data[index:index + 1])
        assert far.receive(timeout=1) == cancel
    left.close()


def test_receive_returns_none_once_its_timeout_passes(pair):
    _, far = pair
    assert far.receive(timeout=0.05) is None


def test_receive_raises_once_the_other_side_has_closed(pair):
    near, far = pair
    near.close()
    with pytest.raises(ConnectionAbortedError):
        far.receive(timeout=1)


def test_a_listener_hands_over_the_connection_made_to_its_port():
    hello, shutdown = HelloResponse(token=TOKEN), ShutdownRequest()
    received_back = []

    def connect():
        with Connection.connect(listener.port) as near:
            near.send(hello)
            received_back.append(near.receive(timeout=2))

    with Listener() as listener:
        thread = threading.Thread(target=connect)
        thread.start()
        far = listener.accept(timeout=2)
        assert far is not None
        with far:
            assert far.receive(timeout=2) == hello
            far.send(shutdown)
        thread.join()
    assert received_back == [shutdown]


def test_accept_returns_none_once_its_timeout_passes():
    with Listener() as listener:
        assert listener.accept(timeout=0.05) is None
