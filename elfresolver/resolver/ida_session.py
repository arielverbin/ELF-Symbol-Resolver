from __future__ import annotations
import contextlib
import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, TypeVar
from elfresolver.connection import Connection, Listener
from elfresolver.exceptions import ELFResolverError, IDAError, IDANotFoundError, IDAStartupError
from elfresolver.messages import (
    CancelRequest, FailureResponse, HelloResponse, IDALaunchEnv, IDARequest, IDAResponse, LogResponse, Message,
    ReadyResponse, ResolvedSymbol, ResolveRequest, ResolveResponse, ShutdownRequest,
)
from elfresolver.symbols import Symbol

logger = logging.getLogger(__name__)

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]  # the directory holding elfresolver/
_BOOTSTRAP = _PACKAGE_ROOT / "elfresolver" / "ida" / "bootstrap.py"
_INCOMPATIBLE_PYTHON = 3  # bootstrap.py exits with it
_POLL_INTERVAL = 0.1      # seconds each wait for IDA lasts at most: a longer one would miss Ctrl+C on Windows
_LOG_TAIL = 20            # lines of IDA's log shown when it dies

_T = TypeVar("_T")


class IDASession:
    """A headless IDA running elfresolver's script on one target, and the conversation with it."""

    def __init__(self, idat: Path, target: Path, *, log: Path, new_database: Path | None, timeout: float) -> None:
        """Start an IDA session for resolving symbols.

        A session on `target`: a database, or a binary to analyze into
        `new_database`. Returns once IDA is ready to resolve. It must connect
        back within `timeout` seconds; its auto-analysis may take as long as it
        takes. A Ctrl+C meanwhile kills it."""
        self._log = log
        self._ready = False
        with Listener() as listener:
            launch = IDALaunchEnv(
                port=listener.port, save_database=new_database is not None,
                log_level=logging.getLogger("elfresolver").getEffectiveLevel(),
            )
            self._process = _start_ida(idat, target, launch, log=log, new_database=new_database)
            try:
                self._connection = self._accept_hello(listener, launch, deadline=time.monotonic() + timeout)
                self._response_to(launch, ReadyResponse)
            except BaseException:
                self._kill()
                raise
        self._ready = True

    def resolve(self, symbol: Symbol) -> tuple[ResolvedSymbol, ...]:
        """Every match of `symbol`, by address. On Ctrl+C, IDA is asked to cancel
        the resolve, and KeyboardInterrupt is raised once it has (or once a
        second Ctrl+C has killed IDA)."""
        request = ResolveRequest(symbol)
        self._send(request)
        try:
            return self._response_to(request, ResolveResponse).matches
        except KeyboardInterrupt:
            self._cancel(request)
            raise

    def close(self, timeout: float = 120.0) -> int:
        """Ask IDA to exit, and its exit code once it has. It is killed if it takes over `timeout` seconds, or on Ctrl+C."""
        try:
            with contextlib.suppress(ConnectionError):  # IDA is gone already
                logger.info("Requesting IDA to shutdown...")
                self._connection.send(ShutdownRequest())
            return self._process.wait(timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Timeout expired: killing IDA.")
            self._kill()
            return self._process.returncode
        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt: killing IDA.")
            self._kill()
            raise
        finally:
            self._connection.close()

    def _accept_hello(self, listener: Listener, launch: IDALaunchEnv, deadline: float) -> Connection:
        """IDA's connection back, once it has said Hello, echoing the launch's token."""
        connection = self._wait(lambda: listener.accept(_POLL_INTERVAL), deadline)
        try:
            hello = self._wait(lambda: connection.receive(_POLL_INTERVAL), deadline)
        except (ValueError, TypeError):  # not speaking elfresolver
            hello = None
        if not _says_hello(hello, launch.token):
            connection.close()
            raise self._with_log_tail(IDAStartupError(f"Something other than the IDA started here connected to port {listener.port}"))
        return connection

    def _send(self, request: IDARequest) -> None:
        try:
            self._connection.send(request)
        except ConnectionError:
            raise self._exited() from None

    def _response_to(self, request: IDARequest, expected: type[IDAResponse]) -> IDAResponse:
        """IDA's response to `request`, which must be an `expected`. Log records
        meanwhile are logged again here, and responses to other requests
        dropped. A failure raises IDAError, whatever it answers: IDA may exit after one."""
        while True:
            response = self._wait(lambda: self._connection.receive(_POLL_INTERVAL))
            if isinstance(response, LogResponse):
                _ida_log(response)
            elif isinstance(response, FailureResponse):
                raise _raised_inside_ida(response)
            elif not isinstance(response, IDAResponse) or response.token != request.token:
                logger.warning("Dropped a message from IDA answering no request under way: %r", response)
            elif not isinstance(response, expected):
                raise IDAError(f"IDA answered a {type(request).__name__} with {response!r}")
            else:
                # an actual final response
                return response

    def _cancel(self, request: IDARequest) -> None:
        """Ask IDA to cancel `request`, and wait until it has; a second Ctrl+C kills it instead."""
        logger.warning("Cancelling the resolve: press Ctrl+C again to kill IDA")
        try:
            with contextlib.suppress(IDAError):  # the request failed first, or IDA died: the Ctrl+C still wins
                self._send(CancelRequest(token=request.token))
                self._response_to(request, IDAResponse)  # a CancelResponse, or the answer that crossed paths with the cancel
        except KeyboardInterrupt:
            self._kill()

    def _wait(self, attempt: Callable[[], _T | None], deadline: float | None = None) -> _T:
        """Calls `attempt` until it gives a value, raises if IDA crashes or `deadline` is passed.
        Returns the value returned by `attempt` on success."""
        try:
            while (result := attempt()) is None:
                if self._process.poll() is not None:
                    raise self._exited()
                if deadline is not None and time.monotonic() > deadline:
                    raise self._with_log_tail(IDAStartupError("IDA didn't connect back in time"))
        except ConnectionError:
            raise self._exited() from None
        return result

    def _exited(self) -> ELFResolverError:
        """What IDA exiting raises: an IDAStartupError until it was ready, an IDAError once it was."""
        try:
            exit_code = self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:  # it closed the connection, yet runs on
            self._kill()
            exit_code = self._process.returncode
        if self._ready:
            error: ELFResolverError = IDAError(f"IDA exited unexpectedly, with code {exit_code}")
        elif exit_code == _INCOMPATIBLE_PYTHON:
            error = IDAStartupError("IDA's Python is older than 3.11: switch IDA to a newer one with idapyswitch")
        else:
            error = IDAStartupError(f"IDA exited with code {exit_code} before it was ready")
        return self._with_log_tail(error)

    def _with_log_tail(self, error: ELFResolverError) -> ELFResolverError:
        error.add_note(_tail_of(self._log))
        return error

    def _kill(self) -> None:
        if self._process.poll() is None:
            logger.warning("Killing IDA")
            self._process.kill()
        self._process.wait()


# Starting IDA.

def find_idat(ida_dir: str | os.PathLike | None = None) -> Path:
    """IDA's text-mode executable, in `ida_dir`, else in $IDADIR, else on PATH: idat64 (IDA 8) if there is one, else idat."""
    for directory in _ida_directories(ida_dir):
        for name in ("idat64", "idat"):
            if (found := shutil.which(name, path=directory)) is not None:
                return Path(found)
    where = f"in {ida_dir}" if ida_dir is not None else "in $IDADIR, nor on PATH"
    raise IDANotFoundError(f"Found no idat {where}: pass ida_dir, or set $IDADIR to IDA's installation directory")


def _ida_directories(ida_dir: str | os.PathLike | None) -> list[str | None]:
    """Where to look for idat, in order (None: on PATH)."""
    if ida_dir is not None:
        return [os.fspath(ida_dir)]
    return [os.environ["IDADIR"], None] if os.environ.get("IDADIR") else [None]


def _start_ida(idat: Path, target: Path, launch: IDALaunchEnv, *, log: Path, new_database: Path | None) -> subprocess.Popen:
    """IDA, started headless on `target`, running elfresolver's script with `launch` in its environment."""
    command = _command(idat, target, log, new_database)
    logger.debug("Starting %s", command)
    return subprocess.Popen(
        command, env=_environment(launch),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        **_own_process_group(),
    )


def _command(idat: Path, target: Path, log: Path, new_database: Path | None) -> list[str]:
    """idat's command line: autonomous (-A), running the bootstrap script (-S), logging (-L), saving to `new_database` (-o)."""
    command = [str(idat), "-A", f'-S"{_BOOTSTRAP}"', f"-L{log}"]
    if new_database is not None:
        command.append(f"-o{new_database}")
    return [*command, str(target)]


def _environment(launch: IDALaunchEnv) -> dict[str, str]:
    """IDA's environment: ours, with the launch, and elfresolver's location for bootstrap.py to import it from."""
    environment = {**os.environ, **launch.to_dict(), "ELFRESOLVER_PACKAGE_ROOT": str(_PACKAGE_ROOT)}
    if os.name == "posix":
        environment["TVHEADLESS"] = "1"  # idat needs no terminal
    return environment


def _own_process_group() -> dict[str, Any]:
    """Popen's arguments that start IDA in a process group of its own, out of reach of the console's Ctrl+C."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


# What IDA says.

def _says_hello(message: Message | None, token: str) -> bool:
    """True for a Hello echoing `token`."""
    return (
        isinstance(message, HelloResponse) and isinstance(message.token, str)
        and secrets.compare_digest(message.token.encode(), token.encode())
    )


def _raised_inside_ida(failure: FailureResponse) -> IDAError:
    error = IDAError(f"{failure.exception}: {failure.message}")
    error.add_note(f"Raised inside IDA:\n{failure.traceback}")
    return error


def _ida_log(log: LogResponse) -> None:
    """Log a record of IDA's side here, through the logger it was logged to, as if it happened here."""
    target = logging.getLogger(log.name)
    if target.isEnabledFor(log.level):
        target.handle(logging.makeLogRecord({
            "name": log.name, "levelno": log.level, "levelname": logging.getLevelName(log.level),
            "msg": log.message, "created": log.created, "msecs": log.created % 1 * 1000,
        }))


def _tail_of(log: Path) -> str:
    try:
        lines = log.read_text(errors="replace").splitlines()
    except OSError:
        return f"IDA's log ({log}) is missing"
    return "\n".join([f"The end of IDA's log ({log}):", *lines[-_LOG_TAIL:]])
