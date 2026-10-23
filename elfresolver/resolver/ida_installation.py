from __future__ import annotations
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from elfresolver.exceptions import IDANotFoundError
from elfresolver.protocol.messages import IDALaunchEnv

logger = logging.getLogger(__name__)

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]  # the directory holding elfresolver/
_BOOTSTRAP = _PACKAGE_ROOT / "elfresolver" / "ida" / "bootstrap.py"


class IDAInstallation:
    """An installation of IDA, whose text-mode executable (idat) runs elfresolver's script headless."""

    def __init__(self, idat: Path) -> None:
        self.idat = idat

    @classmethod
    def find(cls, ida_dir: str | os.PathLike | None = None) -> IDAInstallation:
        """The installation in `ida_dir`, else in $IDADIR, else on PATH: with its idat64 (IDA 8) if it has one, else its idat."""
        if ida_dir is not None:
            directories: list[str | None] = [os.fspath(ida_dir)]
        else:
            directories = [os.environ["IDADIR"], None] if os.environ.get("IDADIR") else [None]  # None: on PATH
        for directory in directories:
            for name in ("idat64", "idat"):
                if (found := shutil.which(name, path=directory)) is not None:
                    return cls(Path(found))
        where = f"in {ida_dir}" if ida_dir is not None else "in $IDADIR, nor on PATH"
        raise IDANotFoundError(f"Found no idat {where}: pass ida_dir, or set $IDADIR to IDA's installation directory")

    def start(self, target: Path, launch: IDALaunchEnv, *, log: Path, new_database: Path | None) -> subprocess.Popen:
        """
        IDA, started headless on `target` (see command), with `launch` in its environment, and
        elfresolver's location for its script to import it from. It runs in a process group
        of its own, out of reach of the console's Ctrl+C.
        """
        command = self.command(target, log=log, new_database=new_database)
        environment = {**os.environ, **launch.to_dict(), "ELFRESOLVER_PACKAGE_ROOT": str(_PACKAGE_ROOT)}
        if os.name == "posix":
            environment["TVHEADLESS"] = "1"  # idat needs no terminal
        own_process_group: dict[str, Any]
        if sys.platform == "win32":
            own_process_group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            own_process_group = {"start_new_session": True}
        logger.debug("Starting %s", command)
        return subprocess.Popen(
            command, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            **own_process_group,
        )

    def command(self, target: Path, *, log: Path, new_database: Path | None) -> list[str]:
        """idat's command line: autonomous (-A), running the bootstrap script (-S), logging (-L), saving to `new_database` (-o)."""
        command = [str(self.idat), "-A", f'-S"{_BOOTSTRAP}"', f"-L{log}"]
        if new_database is not None:
            command.append(f"-o{new_database}")
        return [*command, str(target)]
