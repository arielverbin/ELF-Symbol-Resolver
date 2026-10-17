from __future__ import annotations
import select
import socket
import struct
import time
from typing import Self
from elfresolver.messages import Message

_LOOPBACK = "127.0.0.1"
_HEADER = struct.Struct(">I")


class Listener:
    """A free loopback port, listening for the other side to connect."""

    def __init__(self) -> None:
        self._socket = socket.create_server((_LOOPBACK, 0))  # port 0: any free one
        self.port: int = self._socket.getsockname()[1]

    def accept(self, timeout: float) -> Connection | None:
        """The connection made to the port; None if none is made within `timeout` seconds."""
        readable, _, _ = select.select([self._socket], [], [], timeout)
        return Connection(self._socket.accept()[0]) if readable else None

    def close(self) -> None:
        self._socket.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class Connection:
    """Messages over one connected socket, read from one thread."""

    def __init__(self, sock: socket.socket) -> None:
        sock.settimeout(None)  # reads wait in select(), which can time out on every platform
        self._socket = sock
        self._buffer = bytearray()

    @classmethod
    def connect(cls, port: int, timeout: float = 30.0) -> Connection:
        """A connection to the Listener on `port`."""
        return cls(socket.create_connection((_LOOPBACK, port), timeout=timeout))

    def send(self, message: Message) -> None:
        frame = message.serialize()
        self._socket.sendall(_HEADER.pack(len(frame)) + frame)

    def receive(self, timeout: float | None = None) -> Message | None:
        """
        The next message; None if it hasn't arrived within `timeout` seconds
        (None waits for it, 0 only takes one already here). Raises
        ConnectionAbortedError once the other side has closed the connection.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while (frame := self._take_frame()) is None:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            if not self._read(remaining):
                return None
        return Message.from_serialized(frame)

    def close(self) -> None:
        self._socket.close()

    def _take_frame(self) -> bytes | None:
        """The first frame's message, taken out of the buffer once all of it has arrived."""
        if len(self._buffer) < _HEADER.size:
            return None
        (length,) = _HEADER.unpack_from(self._buffer)
        end = _HEADER.size + length
        if len(self._buffer) < end:
            return None
        frame = bytes(self._buffer[_HEADER.size:end])
        del self._buffer[:end]
        return frame

    def _read(self, timeout: float | None) -> bool:
        """Buffer whatever arrives within `timeout` seconds; False if nothing did."""
        readable, _, _ = select.select([self._socket], [], [], timeout)
        if not readable:
            return False
        chunk = self._socket.recv(65536)
        if not chunk:
            raise ConnectionAbortedError("The other side closed the connection")
        self._buffer += chunk
        return True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
