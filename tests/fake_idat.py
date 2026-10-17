"""
A stand-in for IDA's idat, which tests start instead (see conftest.fake_ida).
It runs elfresolver's real bootstrap.py, on stand-ins for IDA's modules with
the FakeBinary its target holds open (see fake_ida_modules.py): the "binary" is a
FakeBinary's JSON, and so is the "database" it saves, which the resolver may
cache and later start it on.
"""
import contextlib
import os
import runpy
from pathlib import Path
import fake_ida_modules
from elfresolver.connection import Connection
from elfresolver.messages import HelloResponse, IDALaunchEnv
from fakes import FakeBinary


def main(arguments: list[str]) -> int:
    options = {argument[:2]: argument[2:] for argument in arguments[:-1]}  # -A, -S"...", -L..., -o...
    log, target = Path(options["-L"]), Path(arguments[-1])
    binary = FakeBinary.from_json(target.read_text())
    with log.open("a") as log_file:
        print(f"Fake IDA started on {target.name}", file=log_file, flush=True)
        if binary.crash_on_start:
            print("Fake IDA crashed on start", file=log_file)
            return binary.crash_on_start
        if binary.impostor:
            with Connection.connect(IDALaunchEnv.from_dict(os.environ).port) as connection:
                connection.send(HelloResponse(token="not the token"))
                with contextlib.suppress(ConnectionError):
                    connection.receive(timeout=10)  # until the resolver has hung up
            return 0
        fake_ida_modules.install()
        fake_ida_modules.open(binary, idb_path=Path(options["-o"]) if "-o" in options else target)
        with contextlib.redirect_stdout(log_file), contextlib.redirect_stderr(log_file):  # IDA logs its scripts' output
            try:
                runpy.run_path(options["-S"].strip('"'), run_name="__main__")
            except SystemExit as exited:  # bootstrap.py ends with ida_pro.qexit()
                return int(exited.code or 0)
    return 0
