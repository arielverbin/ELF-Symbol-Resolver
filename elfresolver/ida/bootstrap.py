"""
The script IDA runs (idat -S). It makes the resolver's own copy of elfresolver
importable in IDA's Python, which needn't have it installed, then serves the
resolver until it shuts IDA down.

Written for Python >= 3.11, an older IDA Python exits with a code the resolver
explains (see IDASession).
"""
import os
import sys
import traceback
import ida_pro # type: ignore

INCOMPATIBLE_PYTHON = 3  # the exit code for an IDA Python older than elfresolver's

if sys.version_info < (3, 11):
    ida_pro.qexit(INCOMPATIBLE_PYTHON)

# Ahead of any other copy, so IDA runs exactly the version the resolver does.
package_root = os.environ["ELFRESOLVER_PACKAGE_ROOT"]
if package_root not in sys.path:
    sys.path.insert(0, package_root)

try:
    from elfresolver.ida.server import Server
    exit_code = Server.create(os.environ).run()
except BaseException:
    traceback.print_exc()  # into IDA's log, which the resolver shows if IDA dies early
    exit_code = 1

ida_pro.qexit(exit_code)
