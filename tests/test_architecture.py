"""Tests for how elfresolver's parts depend on each other."""
import subprocess
import sys
from conftest import ROOT

_IDA_MODULES = "name.startswith(('ida_', 'idaapi', 'idautils', 'idc'))"


def _imported_ida_modules(module: str) -> str:
    """The IDA modules importing `module` imports, in a fresh interpreter."""
    script = f"import sys, {module}; print(sorted(name for name in sys.modules if {_IDA_MODULES}))"
    return subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def test_the_resolver_imports_no_ida_module():
    """Your Python has no IDA: only IDA's side of elfresolver, inside IDA, uses its API."""
    assert _imported_ida_modules("elfresolver") == "[]"
