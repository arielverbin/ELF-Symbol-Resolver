import argparse
import logging
import sys
from rich.console import Console
from rich.logging import RichHandler
from examples import log_pipeline
from examples import calculator, file_inspector, firmware, game_entities, http_server
from build import DemoRunner, Build

DEMOS = {demo.NAME: demo for demo in (http_server, game_entities, firmware, file_inspector, log_pipeline, calculator)}
TARGETS = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu", "armhf": "arm-linux-gnueabihf", "i686": "i686-linux-gnu"}


class CommandLine:
    """The demonstrations to run, and the build to run them on, as the command line asks."""

    @classmethod
    def main(cls, arguments: list[str]) -> int:
        """Runs the demonstrations `arguments` ask for, showing each one's report; 1 if a check failed."""
        options = cls._parser().parse_args(arguments)
        console = Console()
        logging.basicConfig(
            level={0: logging.WARNING, 1: logging.INFO}.get(options.verbose, logging.DEBUG), format="%(name)s: %(message)s",
            handlers=[RichHandler(console=console, show_path=False, show_time=False)],
        )
        demos = DEMOS.values() if options.demo == "all" else [DEMOS[options.demo]]
        reports = []
        for demo in demos:
            report = DemoRunner(Build(demo, TARGETS[options.target], options.optimization)).run()
            print()
            report.show(console)
            reports.append(report)
            print("\n")
        return 0 if all(report.passed for report in reports) else 1

    @staticmethod
    def _parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="python -m examples",
                                         description="Resolve a demonstration's symbols in a stripped build of its program.")

        parser.add_argument("demo", choices=[*DEMOS, "all"], help="the demonstration to run")
        parser.add_argument("--target", choices=TARGETS, default="x86_64", help="the processor to build for (default: x86_64)")
        parser.add_argument("--opt", dest="optimization", choices=["O0", "O1", "O2", "O3", "Os"], default="O2",
                            help="the optimization level (default: O2)")
        parser.add_argument("-v", "--verbose", action="count", default=0, help="log at info level; -vv, at debug level")
        return parser


if __name__ == "__main__":
    sys.exit(CommandLine.main(sys.argv[1:]))
