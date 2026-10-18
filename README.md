# ELF Resolver

Find functions and globals in stripped ELF binaries by what they call and reference.

You reverse-engineered a binary once. Then a new build arrives: another architecture,
another optimization level, a few changed source files. Every address you found has
moved, and the symbol names are still gone. elfresolver lets you write down *how* you
found each symbol, as constraints that hold in every build, and finds it again in each
one with a headless IDA:

```python
from elfresolver import ELFResolver, Function, GlobalVar, PLTEntry, String

reader = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
parser = Function().called_by(reader)
counter = GlobalVar().referenced_by(parser)

with ELFResolver("build/server.stripped") as resolver:
    print(hex(resolver.resolve(parser).offset))
    print(hex(resolver.resolve(counter).offset))   # `parser` is already resolved: answered from memory
```

---

## Quick start

Requires Python 3.11+, and IDA (8.x or 9.x) with its Python switched to 3.11+ (`idapyswitch`).
Nothing needs to be installed into IDA's Python. From a checkout of this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
export IDADIR=/path/to/ida      # or pass ELFResolver(..., ida_dir=...)
python usage_example.py
```

---

## Symbols

A symbol is its kind and the constraints it must satisfy. Each constraint method returns
a new symbol, one constraint richer, so symbols are values: build them once, share them,
nest them.

| Kind        | What it matches                                                                 |
|-------------|----------------------------------------------------------------------------------|
| `Function`  | a function of the binary's own code                                             |
| `PLTEntry`  | an imported function's PLT stub, named by the import's demangled name (a `Function` too) |
| `GlobalVar` | a data item where variables live (`.data`, `.bss`, `.rodata`, ...), other than a string: as IDA typed it (see below) |
| `String`    | a NUL-terminated string literal, named by its text                               |

| Constraint                | On          | Holds when the symbol...                                            |
|---------------------------|-------------|---------------------------------------------------------------------|
| `Kind("name")`            | every kind  | is named exactly that, in full (an import's demangled name with or without its parameters, a string's text): an exact `.matching()` |
| `.matching(regex)`        | every kind  | has a name (a string: its text) the regex finds a match in          |
| `.references(symbol)`     | every kind  | refers to `symbol`'s address: code taking it, data holding a pointer to it |
| `.referenced_by(symbol)`  | every kind  | has its address referred to by `symbol`                             |
| `.calls(function)`        | `Function`  | calls `function`: directly, by a tail jump, or through a thunk      |
| `.called_by(function)`    | `Function`  | is called by `function`                                             |

`resolve(symbol)` returns its one match, a `ResolvedSymbol` with an `address` (as linked), an
`offset` (from the image base: add it to where the binary is loaded), a `name` and a `size`.
`resolve_all(symbol)` returns every match. When a symbol matches nothing, `resolve()` raises
`SymbolNotFoundError`; when it matches several things, `AmbiguousSymbolError`, with every match:

```
SymbolNotFoundError: Nothing matches Function(0x10bc4f190).calls(0x10bc4e3d0).references(0x10ad1c310)
```

A symbol's repr goes one level deep, naming each symbol in it by its id (`hex(id(symbol))`).
IDA's side logs each symbol it resolves under the same id as the recursion reaches it, so the
log shows which nested symbol matched nothing:

```
elfresolver.ida.resolution: Resolving Function(0x10bc4f190).calls(0x10bc4e3d0).references(0x10ad1c310)
elfresolver.ida.resolution: Resolving PLTEntry(0x10bc4e3d0).matching('\\Asendto\\Z')
elfresolver.ida.resolution: PLTEntry(0x10bc4e3d0).matching('\\Asendto\\Z'): 0 match(es)
elfresolver.ida.resolution: String(0x10ad1c310).matching('\\Aenter\\ input\\Z'): 1 match(es), resolved before
elfresolver.ida.resolution: Function(0x10bc4f190).calls(0x10bc4e3d0).references(0x10ad1c310): 0 match(es)
```

### Writing symbols that last

Anchor symbols on what survives from build to build: imports, strings and globals. Then walk
one or two hops of calls. Internal call shapes change more than you'd think. Inlining,
identical-code folding and LTO can merge functions, or make them disappear. GCC's `.cold`
splitting can move a function's error paths, and their strings, into a function of their own.
`resolve()` failing loudly is the safety net: a symbol that still resolves to exactly one match
still describes one thing.

Architectures don't matter to a symbol. Calls and references are normalized inside IDA:

- a tail jump (`-O2`) is a call, and a local thunk is seen through: so is the PLT stub a
  shared object calls its own exported functions through, and ARM's Thumb entry to a stub
- i686's PC thunk (`__x86.get_pc_thunk.bx`), which PIC code calls for its own address, is no call
- a function IDA folded into a caller that only tail-jumps to it (aarch64 at `-O2`) is one of its own
- PIC code reaching a global through its GOT slot references the global, and taking an import's
  address references its `PLTEntry`
- ARM loading an address from a literal pool references what the pool holds; a Thumb function's
  pointer (its address plus one) references the function, and on 32-bit ARM, code only such a
  pointer leads to (`main`, which `_start` loads from the GOT) is made a function
- PLT stubs are found in `.plt`, `.plt.sec` (`-fcf-protection`) and `.plt.got`

C++ names are demangled as GNU's tools show them (`nm -C`, `c++filt`), whatever IDA's own
demangler says: `geo::Box<int>::area() const`, `{lambda(int)#1}`. A name answers to its forms
without its return type (a template's), without its ABI tags, and without its parameters too:
`Function("geo::scale")` matches every overload, `Function("geo::scale(geo::Point, double)")`
one. A stripped executable has no names of its own functions, but a shared object keeps those
it exports, and every C++ binary keeps its classes' typeinfo names (`String("N3geo7PolygonE")`).

Strings are read from the binary's bytes, not from IDA's string list: a literal is the
printable text between two NULs, or starting where something refers to it (the tail the linker
merged into a longer literal: `"input"` in `"enter input"`). A name is matched whole:
`String("input")` doesn't match `"enter input"`, while `String().matching("input$")` does.

A `GlobalVar` is a data item as IDA typed it, and in a stripped binary IDA types data as code
uses it: a struct whose fields are read may be one item per field, and an array of pointers
(a vtable, a table of handlers) one item per pointer. `GlobalVar().references(handler)` finds
the slot holding the handler's pointer, inside the table; `resolve_all()` gets every item a
function reads.

### Known limitations

- **Thread-locals** aren't found: code reaches one through the thread pointer and its offset in
  the TLS block (`fs:-4`, `tpidr_el0`), which IDA cross-references to nothing.
- **Section anchors**: GCC's `-O2` reaches ARM's statics as the first static of their section,
  plus an offset. IDA refers to that first static, and not always to the static used.
- **One item per pointer**: following a table from one of its slots (`Function().referenced_by(
  GlobalVar().references(handler))`) finds the functions that slot points at, not the whole
  table's. ARM's tables, vtables and typeinfo get this; x86's tables are usually one item.
- **Biased pointers**: a loop counting from 1 may refer to its array minus one element, which
  is what `GlobalVar().referenced_by(loop)` finds.

---

## How it works

```
 your Python                                      IDA's Python (idat -A, headless)
 ┌───────────────────────────┐  loopback TCP   ┌────────────────────────────────┐
 │ elfresolver.resolver      │◀── JSON frames ─▶│ elfresolver.ida                │
 │   ELFResolver             │                  │   bootstrap → server           │
 │   IDASession              │                  │     → resolution → symbols/    │
 │   DatabaseCache           │                  │                                │
 └─────────────┬─────────────┘                  └───────────────┬────────────────┘
               └──────▶ symbols · constraints · protocol ◀──────┘
```

`ELFResolver` starts `idat` headless on the binary with `elfresolver/ida/bootstrap.py`, which
puts the resolver's own copy of elfresolver on IDA's `sys.path`. Then the conversation goes:

1. The resolver listens on a free loopback port (TCP works the same on Windows), and passes IDA
   the launch through its environment: the port to connect back to, and a token.
2. IDA connects back and says Hello, echoing the token, which only the IDA the resolver started
   knows. If the first connection doesn't, starting fails.
3. IDA says Ready once its auto-analysis is done.
4. IDA answers each symbol it's sent. Every request carries a token of its own, which its answer echoes.
5. On leaving the `with` block, the resolver asks IDA to shut down.

Inside IDA, each constraint allows a set of addresses, and a symbol's matches are the
addresses all of them allow. A constraint relating to another symbol is followed back from that
symbol's matches (usually one import or one string), so nothing is scanned for nothing.
Every symbol is resolved once per session: met again, alone or nested, it is answered from memory.

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

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

Most tests need no IDA. IDA's side of elfresolver runs, unchanged, on stand-ins for IDA's Python
modules over a made-up binary (`tests/fake_ida_modules.py`). A stand-in `idat`
(`tests/fake_idat.py`) runs the real `bootstrap.py` on them, so the whole path is exercised for
real: the process, the connection, IDA's kinds of symbols, logs, errors, cancellation and the cache.

The tests marked `ida` run the real IDA, found through `$IDADIR`. Each module holds programs as
source, which `tests/real_ida.py` builds for x86-64 (`-O0`, `-O2`, `-O3`, `-no-pie`), i686, aarch64
and armhf, or as shared objects, strips, and opens in IDA once per module. A test checks that its
symbols resolve to the addresses in the unstripped build's symbol table (`nm -C`), on every build:

| Module                         | Program                                                                 |
|--------------------------------|-------------------------------------------------------------------------|
| `test_ida.py`                  | a C++ server: exceptions, virtual functions, thunks, lambdas, templates, statics |
| `test_ida_cpp_library.py`      | a C++ shared object: exported names, overloads, operators, calls through its own PLT |
| `test_ida_c.py`                | the server above in C, and C control flow: tail calls, cold paths, inlining, merged literals |
| `test_ida_c_data.py`           | C data: tables of functions and strings, structs, lists, switch tables  |

A known limitation is marked as an expected failure where it applies, so a fix shows as XPASS.
A build whose compiler isn't installed is skipped. The compilers are looked up by target triplet
(`aarch64-linux-gnu-g++`, ...), with their `strip` and `nm`. On Debian/Ubuntu:

```bash
sudo apt-get install {gcc,g++}-{x86-64-linux-gnu,i686-linux-gnu,aarch64-linux-gnu,arm-linux-gnueabihf}
```

On macOS, wrappers on `PATH` named the same, running a Linux VM's compilers, work as well.

---

## Next

- **VTables** (Itanium C++ ABI): `VTable("net::Connection")`, found through its typeinfo name,
  and `.slot(n)` to get a virtual function as a `Function`.
- **Control flow**: `.with_loops()`, `.with_switch(cases=5)`, basic-block counts.
- **More constraints**: `.uses_constant(0xDEADBEEF)`, constant call arguments, call order,
  transitive calls (`.reaches(x, depth=3)`), callbacks (`.passed_to(PLTEntry("pthread_create"), arg=2)`),
  reads and writes of a global, `Export("name")`, negation and alternatives.
- **Infrastructure**: a result cache that skips IDA altogether for builds seen before, an idalib
  backend, a pool of IDAs for many builds, and a CLI emitting offsets as JSON or a C header.
