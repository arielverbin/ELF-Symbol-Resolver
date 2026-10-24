# ELF Symbol Resolver

elfresolver finds symbols in stripped ELF binaries. A symbol is described by its relations to
the rest of the binary (the functions it calls, the strings and globals it references, the
constants it uses) rather than by its name or address. elfresolver opens the binary in a
headless IDA and returns every address that fits the description.

The description holds wherever those relations do, so one description finds the same symbol
across builds: other architectures, other optimization levels, or changed source files.

```python
from elfresolver import ELFResolver
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String

reader = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
parser = Function().called_by(reader)
counter = GlobalVar().referenced_by(parser)

with ELFResolver("build/server.stripped") as resolver:
    print(hex(resolver.resolve(parser).offset))
    print(hex(resolver.resolve(counter).offset))   # `parser` is already resolved: answered from memory
```


## Quick start

Requires Python 3.11+, and IDA 8.x or 9.x with its Python switched to 3.11+ (`idapyswitch`).
Nothing is installed into IDA's Python.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install ".[examples]"

export IDADIR=/path/to/ida        # or ELFResolver(..., ida_dir=...)
python demo calculator --opt O1 --target x86_64 -v
```


## Symbols

A symbol is a kind, plus the constraints it must satisfy. Every kind takes an optional exact
name: `PLTEntry("recvfrom")`, `String("enter input")`.

| Kind        | Matches |
| ----------- | --- |
| `Function`  | a function of the binary's own code |
| `PLTEntry`  | an import's PLT stub, named by the import's demangled name |
| `GlobalVar` | a data item where variables live (`.data`, `.bss`, `.rodata`, ...), other than a string |
| `String`    | a NUL-terminated string literal, named by its text |
| `VTable`    | a C++ class's vtable (Itanium ABI), found through RTTI and named by its class |


## Constraints

Each constraint returns a new symbol, so symbols can be stored, combined, and nested inside
other constraints.

| Constraint        | On         | Matches a symbol that... |
| ----------------- | ---------- | --- |
| `matching`        | every kind | has a name matching a regular expression (a string: its text) |
| `references`      | every kind | refers to another symbol: code taking its address, or data pointing at it |
| `referenced_by`   | every kind | another symbol refers to |
| `calls`           | `Function` | calls another function, directly, by a tail jump, or through a thunk |
| `called_by`       | `Function` | another function calls |
| `uses_const`      | `Function` | uses an integer constant |
| `structured_with` | `Function` | decompiles to given numbers of loops, ifs and switch cases |

- `calls` and `called_by` take `max_depth` (1 by default, `None` for any depth) to follow calls
  through the functions in between.
- `uses_const` finds the value at any width it fits (`-1` is `0xFFFFFFFF` in 32 bits): as an
  immediate, a displacement, a literal pool's word, or built in parts (ARM's `MOVZ`/`MOVK`,
  `MOVW`/`MOVT`).
- `structured_with(loops=, ifs=, switch_cases=)` takes each count as `n` or `(at least, at most)`,
  with `None` for unbounded. It needs IDA's Hex-Rays decompiler.

`resolve(symbol)` returns the one match, and raises `SymbolNotFoundError` for none and
`AmbiguousSymbolError` for several. `resolve_all(symbol)` returns every match. A match is a
`ResolvedSymbol`: its `address` as linked, its `offset` from the image base, its `name` and its
`size`.

### Writing symbols that last

Anchor symbols on what survives between builds (imports, strings, constants), then follow a
hop or two of calls and references. If a build changes too much, `resolve()` raises instead of
guessing.

Compiler and architecture differences are handled inside IDA, so symbols don't need to account
for them:

- tail jumps count as calls, and thunks are seen through (local thunks, PLT stubs a shared object
  calls its own exports through, ARM's Thumb entries to stubs)
- i686's PC thunk (`__x86.get_pc_thunk.bx`) doesn't count as a call
- a function IDA folded into a caller that only tail-jumps to it is a function of its own
- reaching a global through its GOT slot, or an address through an ARM literal pool, refers to
  the global or the address itself; taking an import's address refers to its `PLTEntry`
- Thumb function pointers (the address plus one) refer to the function
- PLT stubs are found in `.plt`, `.plt.sec` (`-fcf-protection`) and `.plt.got`


## How it works

```
 your Python                                      IDA's Python (idat -A, headless)
 ┌───────────────────────────┐   loopback TCP   ┌────────────────────────────────┐
 │ elfresolver.resolver      │◀── JSON frames ─▶│ elfresolver.ida                │
 │   ELFResolver             │                  │   bootstrap → server           │
 │   IDASession              │                  │     → analysis                 │
 │   IDAInstallation         │                  │     → resolution → symbols/    │
 │   DatabaseCache           │                  │                                │
 └─────────────┬─────────────┘                  └───────────────┬────────────────┘
               └──────▶ symbols · constraints · protocol ◀──────┘
```

`ELFResolver` finds IDA (`$IDADIR`, or `idat` on `PATH`) and starts it headless on the binary.
IDA runs `elfresolver/ida/bootstrap.py`, which imports elfresolver from the resolver's own
copy, connects back, and answers each symbol it is sent.

Each constraint narrows the symbol's candidates. Constraints that follow other symbols run
first; those that check candidates one at a time (`matching`, `uses_const`, `structured_with`)
run last, cheapest first, and stop once nothing is left. Each symbol is resolved once per
session, and answered from memory after that.

The first run on a binary waits for IDA's auto-analysis: seconds for a small binary, about a
minute and a half for 12 MB. After that, resolves take milliseconds.

- **Logs and errors**: IDA's logs are re-emitted on your side under the same logger names. An
  exception inside IDA is raised as an `IDAError`, with IDA's traceback attached.
- **Ctrl+C** cancels the resolve in progress and keeps IDA running. A second Ctrl+C, or one during
  auto-analysis, stops IDA.
- **Database cache**: each analyzed binary's IDA database is kept under `$ELFRESOLVER_CACHE` (the
  platform's cache directory by default), keyed by the binary's SHA-256. IDA works on a copy, so
  a crash can't corrupt the cache.


### Known limitations

- **Globals are items as IDA typed them**: a struct read field by field may be one item per
  field, and a table of pointers one item per pointer.
- **Section anchors**: at `-O2`, GCC reaches ARM statics through the first static of their
  section plus an offset, and IDA refers to that first static instead.
- **Thread-locals** aren't found: code reaches them through the thread pointer, which IDA doesn't
  cross-reference.
- **Constants**: 32-bit targets split 64-bit constants in halves, and a division by a constant
  becomes a multiplication by another.
- **Decompiled structure** changes with optimization (unrolled loops, switches turned into tables
  or compares): ranges hold up better than exact counts.
- **VTables** need RTTI or a `_ZTV` symbol. Without a symbol, a construction vtable of class `B`
  can't be told apart from `B`'s own.


---

## Demos

`demo/` holds six example programs, each a C++ source and the symbols to find in it. 
They demonstrate resolving through PLT entries, VTables, string referencing, call graphs,
magic values used, decompiled structured, etc...

A run compiles the program, strips it, resolves its symbols, and checks each result against the
unstripped build's symbol table. It needs the target's cross compiler and binutils
(`x86_64-linux-gnu-g++`, `aarch64-linux-gnu-g++` or `arm-linux-gnueabihf-g++`).

```bash
python demo http_server
python demo all --target aarch64 --opt O0 -vv     # -v: info logs, -vv: debug logs
```


## Running the tests

```bash
sudo apt-get install {gcc,g++}-{x86-64-linux-gnu,i686-linux-gnu,aarch64-linux-gnu,arm-linux-gnueabihf}

pip install -e ".[dev]"
pytest -rsx
```

Most tests run without IDA, on stand-ins for IDA's Python modules. Tests marked `ida` build
real programs with each installed cross compiler, strip them, and open them in IDA. They are
skipped when IDA or a compiler is missing.
