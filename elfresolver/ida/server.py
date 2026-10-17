from __future__ import annotations
import logging
import traceback
import time
import ida_auto
import ida_loader
import idc
from contextlib import contextmanager
from typing import Callable, Generator, Mapping, Self
from elfresolver.connection import Connection
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.resolution import Resolution
from elfresolver.messages import (
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
        self._resolution = Resolution(interrupted=self._cancel_arrived)

    @classmethod
    def create(cls, environment: Mapping[str, str]) -> Self:
        """The server of the resolver that started this IDA, connected back to it as `environment` tells (see IDALaunchEnv)."""
        launch = IDALaunchEnv.from_dict(environment)
        return cls(Connection.connect(launch.port), launch)  # run() closes the connection once it's done with it

    def run(self) -> int:
        """Answer the launch, then every request until a shutdown, then hang up; the exit code to exit IDA with."""
        with self._connection:
            self._connection.send(HelloResponse(token=self._token))  # before any log record: the resolver expects it first
            with _pipe_logs_to_session(self._connection, self._launch.log_level, token=lambda: self._token):
                try:
                    self._wait_for_analysis()
                    self._connection.send(ReadyResponse(token=self._token))
                    self._serve_main()
                    if self._launch.save_database:
                        self._save_database()
                except Exception as error:
                    logger.debug("IDA's side failed", exc_info=True)
                    self._connection.send(self._failure(error))
                    return 1
        return 0

    def _serve_main(self) -> None:
        """Answer every resolve, until a shutdown. A cancel arriving after its resolve has finished is ignored."""
        while not isinstance(request := self._connection.receive(), ShutdownRequest):
            if isinstance(request, ResolveRequest):
                self._token = request.token
                self._connection.send(self._answer(request.symbol))

    def _answer(self, symbol: Symbol) -> IDAResponse:
        try:
            # parse requested symbol as an IDASymbol
            resolvable = self._resolution.of(symbol)
            # recursively resolve its constraints using the `.resolve` entry
            addresses = resolvable.resolve()
        except ResolveInterrupted:
            logger.info("Cancelled resolving %r", symbol)
            return CancelResponse(token=self._token)
        except Exception as error:
            return self._failure(error)
        logger.info("%r: %d match(es)", symbol, len(addresses))
        return ResolveResponse(tuple(resolvable.describe(address) for address in sorted(addresses)), token=self._token)

    def _cancel_arrived(self) -> bool:
        """True if the resolver has asked to stop the request under way (the only message it sends meanwhile)."""
        request = self._connection.receive(timeout=0)
        return isinstance(request, CancelRequest) and request.token == self._token

    def _failure(self, error: Exception) -> FailureResponse:
        return FailureResponse(
            type(error).__name__,
            str(error), "".join(traceback.format_exception(error)),
            token=self._token
        )

    def _wait_for_analysis(self) -> None:
        """Return once IDA's auto-analysis of the open database has finished."""
        logger.info("Waiting for IDA's auto-analysis")
        started = time.monotonic()
        ida_auto.auto_wait()
        logger.info("Auto-analysis finished in %.1fs", time.monotonic() - started)

    def _save_database(self) -> None:
        """Write the database to its file, for the resolver to cache once IDA has exited."""
        ida_loader.save_database(idc.get_idb_path(), 0)


# Log handling: pipe logs to session

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


@contextmanager
def _pipe_logs_to_session(connection: Connection, level: int, token: Callable[[], str]) -> Generator[None]:
    """For the block, every elfresolver record from `level` up is sent over `connection` too."""
    package_logger = logging.getLogger("elfresolver")
    handler = ConnectionLogHandler(connection, token)
    package_logger.addHandler(handler)
    package_logger.setLevel(level)
    try:
        yield
    finally:
        package_logger.removeHandler(handler)

