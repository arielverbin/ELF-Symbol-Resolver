from __future__ import annotations
import logging
import traceback
from contextlib import contextmanager
from typing import Callable, Iterator, Mapping, Self
import ida_loader # type: ignore
import idc # type: ignore
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.analysis import AutoAnalysis
from elfresolver.ida.resolution import SymbolResolution
from elfresolver.protocol.connection import Connection
from elfresolver.protocol.messages import (
    CancelRequest, CancelResponse, FailureResponse, HelloResponse, IDALaunchEnv, IDAResponse, LogResponse,
    ReadyResponse, ResolveRequest, ResolveResponse, ShutdownRequest,
)
from elfresolver.symbols import Symbol

logger = logging.getLogger(__name__)


class Server:
    """Answers the resolver's requests about the database IDA has open, one at a time, until it shuts down."""

    def __init__(self, connection: Connection, launch: IDALaunchEnv) -> None:
        self._connection = connection
        self._launch = launch
        self._token = launch.token  # of the request being answered: the launch, until the resolver sends one
        self._resolution = SymbolResolution(interrupted=self._cancel_arrived)

    @classmethod
    def create(cls, environment: Mapping[str, str]) -> Self:
        """The server of the resolver that started this IDA, connected back to it as `environment` tells (see IDALaunchEnv)."""
        launch = IDALaunchEnv.from_dict(environment)
        return cls(Connection.connect(launch.port), launch)  # run() closes the connection once it's done with it

    def run(self) -> int:
        """Answer the launch, then every request until a shutdown, then hang up; the exit code to exit IDA with."""
        with self._connection:
            self._connection.send(HelloResponse(token=self._token))  # before any log record: the resolver expects it first
            with self._logs_piped():
                try:
                    AutoAnalysis.complete()
                    self._connection.send(ReadyResponse(token=self._token))
                    self._serve()
                    if self._launch.save_database:
                        ida_loader.save_database(idc.get_idb_path(), 0)  # for the resolver to cache, once IDA has exited
                except Exception as error:
                    logger.debug("IDA's side failed", exc_info=True)
                    self._connection.send(self._failure(error))
                    return 1
        return 0

    def _serve(self) -> None:
        """Answer every resolve, until a shutdown. A cancel arriving after its resolve has finished is ignored."""
        while not isinstance(request := self._connection.receive(), ShutdownRequest):
            if isinstance(request, ResolveRequest):
                self._token = request.token
                self._connection.send(self._answer(request.symbol))

    def _answer(self, symbol: Symbol) -> IDAResponse:
        """Every match of `symbol`, described; or why there is none: the resolver cancelled the resolve, or something raised."""
        try:
            resolvable = self._resolution.resolve(symbol)  # its constraints, recursively, each logged
        except ResolveInterrupted:
            logger.info("Cancelled resolving %r", symbol)
            return CancelResponse(token=self._token)
        except Exception as error:
            return self._failure(error)
        matches = sorted(resolvable.resolve())  # remembered
        return ResolveResponse(tuple(resolvable.describe(address) for address in matches), token=self._token)

    def _cancel_arrived(self) -> bool:
        """True if the resolver has asked to stop the request under way (the only message it sends meanwhile)."""
        request = self._connection.receive(timeout=0)
        return isinstance(request, CancelRequest) and request.token == self._token

    def _failure(self, error: Exception) -> FailureResponse:
        """The response telling the resolver `error` was raised: its class's name, message, and traceback."""
        return FailureResponse(type(error).__name__, str(error), "".join(traceback.format_exception(error)), token=self._token)

    @contextmanager
    def _logs_piped(self) -> Iterator[None]:
        """For the block, every elfresolver record from the launch's log level up is sent to the resolver too,
        as part of the answer to the request under way."""
        package_logger = logging.getLogger("elfresolver")
        handler = ConnectionLogHandler(self._connection, token=lambda: self._token)
        package_logger.addHandler(handler)
        package_logger.setLevel(self._launch.log_level)
        try:
            yield
        finally:
            package_logger.removeHandler(handler)


class ConnectionLogHandler(logging.Handler):
    """Sends every record it handles over a connection, for the resolver to log again,
    as part of the answer to the request `token()` gives."""

    def __init__(self, connection: Connection, token: Callable[[], str]) -> None:
        super().__init__()
        self._connection = connection
        self._token = token

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._connection.send(
                LogResponse(record.name, record.levelno, self.format(record), record.created, token=self._token())
            )
        except Exception:
            self.handleError(record)
