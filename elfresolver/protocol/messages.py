from __future__ import annotations
import secrets
from dataclasses import dataclass, field
from typing import ClassVar, Mapping
from elfresolver.protocol.serializable import Serializable
from elfresolver.symbols import Symbol


class Message(Serializable):
    """A request, or a response."""


@dataclass(frozen=True)
class IDARequest(Message):
    """Something the resolver asks of IDA."""
    token: str = field(kw_only=True, default_factory=lambda: secrets.token_hex(16))


@dataclass(frozen=True)
class IDAResponse(Message):
    """Something IDA tells the resolver, in answer to the request whose token it echoes."""
    token: str = field(kw_only=True)


@dataclass(frozen=True)
class IDALaunchEnv(IDARequest):
    """The first request, which the resolver passes the IDA it launches through its environment."""
    port: int             # where the resolver listens, for IDA to connect back to
    log_level: int        # the lowest level of record worth sending to the resolver
    save_database: bool   # IDA analyzed the binary afresh: its database is worth keeping

    VARIABLE: ClassVar[str] = "ELFRESOLVER_LAUNCH"

    def to_dict(self) -> dict[str, str]:
        return {self.VARIABLE: self.serialize().decode()}

    @classmethod
    def from_dict(cls, environment: Mapping[str, str]) -> IDALaunchEnv:
        return cls.from_serialized(environment[cls.VARIABLE])


@dataclass(frozen=True)
class ResolveRequest(IDARequest):
    """Find every match of `symbol`."""
    symbol: Symbol


@dataclass(frozen=True)
class CancelRequest(IDARequest):
    """Stop the request whose token this one has: the user pressed Ctrl+C."""


@dataclass(frozen=True)
class ShutdownRequest(IDARequest):
    """Exit IDA."""


@dataclass(frozen=True)
class HelloResponse(IDAResponse):
    """IDA's first message, once it has connected back: it answers the launch."""


@dataclass(frozen=True)
class LogResponse(IDAResponse):
    """A record logged on IDA's side while answering a request, for the resolver to log again on its own."""
    name: str
    level: int
    message: str
    created: float


@dataclass(frozen=True)
class ReadyResponse(IDAResponse):
    """IDA's auto-analysis is done: it can resolve symbols. It answers the launch."""


@dataclass(frozen=True)
class ResolvedSymbol(Serializable):
    """Where a symbol was found in the binary."""
    symbol: Symbol
    address: int        # its link-time virtual address, as IDA shows it
    offset: int         # its address from the image base: add it to where the binary is loaded
    name: str | None    # IDA's name for it, an import's demangled name, or a string's text
    size: int           # in bytes


@dataclass(frozen=True)
class ResolveResponse(IDAResponse):
    """Every match of the symbol a ResolveRequest asked for, by address."""
    matches: tuple[ResolvedSymbol, ...]


@dataclass(frozen=True)
class FailureResponse(IDAResponse):
    """An exception raised inside IDA."""
    exception: str   # its class's name
    message: str
    traceback: str


@dataclass(frozen=True)
class CancelResponse(IDAResponse):
    """The request a CancelRequest stopped."""
