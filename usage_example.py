"""
A tour of elfresolver: compile a tiny server, strip it of every symbol name,
then find its functions and globals again by what they call and reference.

    IDADIR=/path/to/ida python usage_example.py

Needs gcc, and IDA running Python 3.11 or newer (see idapyswitch).
"""
import logging
import subprocess
from pathlib import Path
from elfresolver import ELFResolver
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from elfresolver.exceptions import SymbolNotFoundError

SOURCE = r"""
#include <stdio.h>
#include <sys/socket.h>

static char request[512];
static int requests_served;

// noipa: no inlining nor specializing, as for a helper with many callers.
__attribute__((noipa)) static void parse_request(const char *text, long length) {
    requests_served++;
    printf("request #%d: %.*s\n", requests_served, (int)length, text);
}

__attribute__((noipa)) static void read_request(int fd) {
    puts("enter input");
    long length = recvfrom(fd, request, sizeof request, 0, NULL, NULL);
    if (length > 0)
        parse_request(request, length);
}

int main(void) {
    read_request(0);
    return 0;
}
"""


def compile_stripped(source: str, directory: Path) -> Path:
    """Compile C source into an executable with no symbol names left to go by."""
    binary = directory / "server"
    subprocess.run(["gcc", "-O2", "-x", "c", "-", "-o", str(binary)], input=source.encode(), check=True)
    subprocess.run(["strip", str(binary)], check=True)
    return binary


def main() -> None:
    # IDA's side logs too: its records show up here, as if logged here.
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")

    # A symbol is its kind, and the constraints it satisfies. Anchor it on what
    # survives from build to build (imports, strings), then walk a hop or two.
    reader = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
    parser = Function().called_by(reader)
    counter = GlobalVar().referenced_by(parser)

    binary = "server.out"

    # The first run on a binary waits for IDA's auto-analysis. Its database
    # is then cached, so later runs on the same binary start in seconds.
    # Ctrl+C cancels a resolve under way, and the resolver goes on.
    with ELFResolver(binary) as resolver:
        for name, symbol in [("read_request", reader), ("parse_request", parser), ("requests_served", counter)]:
            found = resolver.resolve(symbol)  # `reader` is resolved once: then answered from memory
            print(f"{name:<16} at offset {found.offset:#x} (IDA calls it {found.name})")

        # resolve() wants exactly one match; resolve_all() takes them all.
        for string in resolver.resolve_all(String().matching("input|request")):
            print(f"a string at offset {string.offset:#x}: {string.name!r}")

        # When nothing matches, resolve() raises SymbolNotFoundError (several matches: AmbiguousSymbolError).
        try:
            resolver.resolve(Function().calls(PLTEntry("sendto")).references(String("enter input")))
        except SymbolNotFoundError as error:
            print(error)


if __name__ == "__main__":
    main()
