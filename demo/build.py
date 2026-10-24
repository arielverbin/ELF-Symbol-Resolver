from __future__ import annotations
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from rich.console import Console
from rich.table import Table
from rich import box
from demo_resolver import DemoResolver, Check


@dataclass(frozen=True)
class DemoReport:
    """What a demonstration resolved, checked (see Check), and how long IDA took to start."""
    name: str
    checks: list[Check]
    startup_seconds: float

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def show(self, console: Console) -> None:
        """A row for each match, and each expected symbol nothing matched; a section for each check, with its time."""
        seconds = [check.seconds for check in self.checks]
        table = Table(title=f"{self.name}: symbol resolve status", box=box.ROUNDED, title_justify="left", caption=(
            f"{sum(check.passed for check in self.checks)} of {len(self.checks)} checks passed · "
            f"resolved in {sum(seconds):.2f}s, the slowest {max(seconds, default=0) * 1000:.1f} ms · "
            f"IDA ready in {self.startup_seconds:.1f}s"
        ))
        for column in ("", "expected", "kind", "offset", "size", "found", "time"):
            table.add_column(column, justify="right" if column in ("offset", "size", "time") else "left")
        for check in self.checks:
            rows = self._rows(check)
            for index, row in enumerate(rows):
                took = f"{check.seconds * 1000:.1f} ms" if index == 0 else ""
                table.add_row(*row, took, end_section=index == len(rows) - 1)
        console.print(table)

    @staticmethod
    def _rows(check: Check) -> list[tuple[str, ...]]:
        """The check's rows: each match, and the expected symbol it is; each expected symbol nothing matched; or the error."""
        passed, failed, kind = "[green]✓", "[red]✗", type(check.symbol).__name__
        if check.error is not None:
            return [(failed, ", ".join(check.missing), kind, "", "", f"[red]{check.error}")]
        rows = [
            (passed if name is not None else failed, name or "[red]unexpected", type(match.symbol).__name__,
             f"{match.offset:#x}", str(match.size), match.name or "")
            for match, name in check.found
        ]
        rows += [(failed, name, kind, "", "", "[red]missing") for name in check.missing]
        return rows or [(passed, "[dim]nothing", kind, "", "", "[dim]no match")]


@dataclass(frozen=True)
class Build:
    """A demonstration's program, built for a target, at an optimization level."""
    demo: ModuleType
    triplet: str
    optimization: str

    def make(self, directory: Path) -> tuple[Path, Path]:
        """
        Compiles the program in `directory`, then strips a copy of it: the stripped binary, and
        the unstripped one. The same source makes the same bytes every time, so IDA's database
        of the stripped binary stays cached.
        """
        compiler = f"{self.triplet}-g++"
        if shutil.which(compiler) is None:
            raise SystemExit(f"{compiler} isn't installed: pick another --target")
        source, unstripped, stripped = (directory / f"{self.demo.NAME}{suffix}" for suffix in (".cpp", ".elf", ""))
        source.write_text(self.demo.SOURCE)
        subprocess.run([compiler, f"-{self.optimization}", "-std=c++17", source.name, "-o", unstripped.name], cwd=directory, check=True)
        shutil.copy(unstripped, stripped)
        subprocess.run([f"{self.triplet}-strip", stripped.name], cwd=directory, check=True)
        return stripped, unstripped


@dataclass(frozen=True)
class DemoRunner:
    """Runs a demonstration on its build, made in a temporary directory, gone once it ran."""
    build: Build

    def run(self) -> DemoReport:
        """Makes the build, then resolves the demonstration's symbols on it (as they log)."""
        with tempfile.TemporaryDirectory(prefix="elfresolver-example-") as directory:
            stripped, unstripped = self.build.make(Path(directory))
            with DemoResolver(stripped, unstripped, nm=f"{self.build.triplet}-nm") as resolver:
                self.build.demo.resolve(resolver)
        return DemoReport(self.build.demo.NAME, resolver.checks, resolver.startup_seconds)