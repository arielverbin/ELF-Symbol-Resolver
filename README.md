# ELF Symbol Resolver

Find functions and globals in stripped ELF binaries by what they call and reference.

This tool lets you formalize relations between different symbols in an ELF binary.
Those relations, defined as `constraints`, lets you reverse-engineer a binary once,
and apply it again when new builds arrive: another architecture, another optimization
level, or changes in source files.

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

Requires Python 3.11+, and IDA (8.x or 9.x) with its Python switched to 3.11+ (`idapyswitch`).
Nothing needs to be installed into IDA's Python. From a checkout of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .

IDADIR=/path/to/ida python examples calculator --opt O1 --target x86_64 --verbose  
```


## Symbols

| Kind        | What it matches                                                                 |
|-------------|----------------------------------------------------------------------------------|
| `Function`  | a function of the binary's own code                                             |
| `PLTEntry`  | an imported function's PLT stub, named by the import's demangled name (a `Function` too) |
| `GlobalVar` | a data item where variables live (`.data`, `.bss`, `.rodata`, ...), other than a string: as IDA typed it (see below) |
| `String`    | a NUL-terminated string literal, named by its text                               |
| `VTable`    | a C++ class's virtual table (Itanium ABI), found through its RTTI, named by its class (`VTable("net::Handler")`) |

## Constraints

Constraints are applied to symbols, some constraints are global and some can be applied to certain symbols.
Applying a constraint updates the symbol and returns it back so constraints can be accumulated.
Constraints can receive dependencies which are other symbols (i.e. `Function().calls(PLTEntry("recvfrom"))`) so
they can be nested.

A few examples,

| Constraint                | On          | Holds when the symbol...                                            |
|---------------------------|-------------|---------------------------------------------------------------------|
| `.matching(regex)`        | every kind  | has a name (a string: its text) the regex finds a match in          |
| `.referenced_by(symbol)`  | every kind  | has its address referred to by `symbol`                             |
| `.calls(function)` | `Function` | calls `function`: directly, by a tail jump, or through a thunk; with a `max_depth` above 1 (None: any), through functions calling it too |
| `.structured_with(...)` | `Function` | has these in its decompiled code (Hex-Rays'): each a count, or `(at least, at most)` with `None` for unbounded |

`resolve(symbol)` returns its one match, a `ResolvedSymbol` with an `address` (as linked), an
`offset` (from the image base: add it to where the binary is loaded), a `name` and a `size`.
`resolve_all(symbol)` returns every match. When a symbol matches nothing, `resolve()` raises
`SymbolNotFoundError`; when it matches several things, `AmbiguousSymbolError`.

### Writing symbols that last

Anchor your symbols on what survives from build to build: imports, strings and globals. Constraints allow
the source code to be modified, as long as it does not break the constraint. `resolve()` failing loudly
is the safety net: a symbol that still resolves to exactly one match still describes one thing.

Architectures are normalized inside IDA and don't matter to a symbol. Normalization includes,

- a tail jump (`-O2`) is a call, and a local thunk is seen through: so is the PLT stub a
  shared object calls its own exported functions through, and ARM's Thumb entry to a stub
- i686's PC thunk (`__x86.get_pc_thunk.bx`), which PIC code calls for its own address, is no call
- a function IDA folded into a caller that only tail-jumps to it (aarch64 at `-O2`) is one of its own
- PIC code reaching a global through its GOT slot references the global, and taking an import's
  address references its `PLTEntry`
- PLT stubs are found in `.plt`, `.plt.sec` (`-fcf-protection`) and `.plt.got`
- etc...

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

`ELFResolver` finds IDA (`IDAInstallation`) and starts `idat` headless on the binary with
`elfresolver/ida/bootstrap.py`, which puts the resolver's own copy of elfresolver on IDA's
`sys.path`.

Everything IDA's side logs is logged again on your side, under the same logger names. An
exception inside IDA is raised as an `IDAError`, with IDA's traceback attached as a note.

**Ctrl+C** cancels the resolve under way: IDA stays up, and `resolve()` goes on working. A
second Ctrl+C, or one during auto-analysis, kills IDA. IDA runs in a process group of its own,
so the console's Ctrl+C reaches only the resolver.

**The database cache** keeps the IDA database of every binary IDA analyzed, keyed by the
SHA-256 of its content, under `$ELFRESOLVER_CACHE` (by default, the platform's cache directory).
Only the first run on a binary waits for auto-analysis. Entries are never opened in place:
IDA works on a copy, so neither concurrent resolvers nor a crashed IDA can corrupt one. A
database is stored only after its IDA exited cleanly.

### Known limitations

- **Thread-locals** aren't found: code reaches one through the thread pointer and its offset in
  the TLS block (`fs:-4`, `tpidr_el0`), which IDA cross-references to nothing.
- **Section anchors**: GCC's `-O2` reaches ARM's statics as the first static of their section,
  plus an offset. IDA refers to that first static, and not always to the static used.
- **Constants**: a 32-bit target uses a 64-bit constant a half at a time (`0x5DEECE66D` is
  `0xDEECE66D` and `5`), and a division by a constant is a multiplication by another.
- **Decompiled structure** needs IDA's Hex-Rays decompiler for the binary's processor:
  without it, `.structured_with()` raises an `IDAError` saying so.
- **VTables** need RTTI or a `_ZTV` symbol (`-fno-rtti` and stripped finds none). Without a
  symbol, a table with virtual bases starts at its offset to top (past its vcall and vbase
  offsets), and a construction vtable of base `B` isn't told apart from `B`'s own.

## Running the tests

```bash
sudo apt-get install {gcc,g++}-{x86-64-linux-gnu,i686-linux-gnu,aarch64-linux-gnu,arm-linux-gnueabihf}

pip install -e ".[dev]"
pytest -rsx
```
