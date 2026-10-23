# ELF Resolver

Find functions and globals in stripped ELF binaries by what they call and reference.

You reverse-engineered a binary once. Then a new build arrives: another architecture,
another optimization level, a few changed source files. Every address you found has
moved, and the symbol names are still gone. elfresolver lets you write down *how* you
found each symbol, as constraints that hold in every build, and finds it again in each
one with a headless IDA:

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
| `VTable`    | a C++ class's virtual table (Itanium ABI), found through its RTTI, named by its class (`VTable("net::Handler")`) |

| Constraint                | On          | Holds when the symbol...                                            |
|---------------------------|-------------|---------------------------------------------------------------------|
| `Kind("name")`            | every kind  | is named exactly that, in full (an import's demangled name with or without its parameters, a string's text): an exact `.matching()` |
| `.matching(regex)`        | every kind  | has a name (a string: its text) the regex finds a match in          |
| `.references(symbol)`     | every kind  | refers to `symbol`'s address: code taking it, data holding a pointer to it |
| `.referenced_by(symbol)`  | every kind  | has its address referred to by `symbol`                             |
| `.calls(function, max_depth=1)` | `Function` | calls `function`: directly, by a tail jump, or through a thunk; with a `max_depth` above 1 (None: any), through functions calling it too |
| `.called_by(function, max_depth=1)` | `Function` | is called by `function`; with a `max_depth` above 1 (None: any), by the functions it calls too |
| `.uses_const(value)`      | `Function`  | uses the integer `value`: as an instruction's immediate or displacement (of any width it fits: `-1` is `0xFFFFFFFF` in 32 bits), or from a literal pool |
| `.structured_with(loops=, ifs=, switch_cases=)` | `Function` | has these in its decompiled code (Hex-Rays'): each a count, or `(at least, at most)` with `None` for unbounded |

`resolve(symbol)` returns its one match, a `ResolvedSymbol` with an `address` (as linked), an
`offset` (from the image base: add it to where the binary is loaded), a `name` and a `size`.
`resolve_all(symbol)` returns every match. When a symbol matches nothing, `resolve()` raises
`SymbolNotFoundError`; when it matches several things, `AmbiguousSymbolError`, with every match:

```
SymbolNotFoundError: Nothing matches Function(0x10bc4f190).calls(callee=0x10bc4e3d0).references(target=0x10ad1c310)
```

A symbol's repr goes one level deep, naming each symbol in it by its id (`hex(id(symbol))`), and
leaving out arguments at their default. IDA's side logs each symbol it resolves under the same id
as the recursion reaches it, so the log shows which nested symbol matched nothing (and, at debug
level, what each constraint left). Once nothing is left, the constraints after aren't met at all:
here, the string isn't resolved.

```
elfresolver.ida.resolution: Resolving Function(0x10bc4f190).calls(callee=0x10bc4e3d0).references(target=0x10ad1c310)
elfresolver.ida.resolution: Resolving PLTEntry(0x10bc4e3d0).matching(pattern='\\Asendto\\Z')
elfresolver.ida.resolution: PLTEntry(0x10bc4e3d0).matching(pattern='\\Asendto\\Z'): 0 match(es)
elfresolver.ida.resolution: Function(0x10bc4f190).calls(callee=0x10bc4e3d0).references(target=0x10ad1c310): 0 match(es)
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

A `VTable` is a class's whole vtable, as `nm -S` sizes it: its primary table (vcall and vbase
offsets, offset to top, typeinfo, then the virtual functions' pointers), and a secondary table
for each base past the first. It is found through the class's RTTI (a typeinfo name, pointed at
by a typeinfo, pointed at by the table), or by a `_ZTV` symbol (as a shared object exports, and
IDA names those whose RTTI it parsed). Every vtable libstdc++ exports is found this way, each at
its symbol's address, with its symbol's size. So `Function().referenced_by(VTable("geo::Polygon"))` finds all of
its virtual functions, `VTable().references(method)` the tables holding `method`, and
`Function().references(VTable("net::EchoHandler"))` the code making or unmaking its objects.

Constraints that check candidates one by one (`.matching()`, `.uses_const()`,
`.structured_with()`) run after the others, cheapest first, on what those left: write the cheap
anchors (an import, a string, a call), and decompiling is only for the few functions they leave.
`.structured_with()` counts change with optimization (loops unrolled, switches turned into
tables or chains of compares, ifs made branchless): bounds outlast exact counts.

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
- **Constants**: a 32-bit target uses a 64-bit constant a half at a time (`0x5DEECE66D` is
  `0xDEECE66D` and `5`), and a division by a constant is a multiplication by another.
- **Decompiled structure** needs IDA's Hex-Rays decompiler for the binary's processor:
  without it, `.structured_with()` raises an `IDAError` saying so.
- **VTables** need RTTI or a `_ZTV` symbol (`-fno-rtti` and stripped finds none). Without a
  symbol, a table with virtual bases starts at its offset to top (past its vcall and vbase
  offsets), and a construction vtable of base `B` isn't told apart from `B`'s own.

---

## How it works

```
 your Python                                      IDA's Python (idat -A, headless)
 ┌───────────────────────────┐  loopback TCP   ┌────────────────────────────────┐
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
`sys.path`. Then the conversation (`IDASession`) goes:

1. The resolver listens on a free loopback port (TCP works the same on Windows), and passes IDA
   the launch through its environment: the port to connect back to, and a token.
2. IDA connects back and says Hello, echoing the token, which only the IDA the resolver started
   knows. If the first connection doesn't, starting fails.
3. IDA says Ready once its auto-analysis is done, and completed where it falls short
   (`AutoAnalysis`: Thumb code only a pointer leads to, functions folded into their callers).
4. IDA answers each symbol it's sent. Every request carries a token of its own, which its answer echoes.
5. On leaving the `with` block, the resolver asks IDA to shut down.

Inside IDA, each constraint allows a set of addresses, and a symbol's matches are the
addresses all of them allow. A constraint relating to another symbol is followed back from that
symbol's matches (usually one import or one string), so nothing is scanned for nothing.
`SymbolResolution` meets the constraints that find their matches at once first, in the order
written, then those checking candidates one by one, lowest cost first: each is handed what the
constraints before it left (every symbol of the kind, if none came before), and once nothing is
left, the rest are skipped. Every symbol is resolved once per session: met again, alone or
nested, it is answered from memory.

A new constraint is three pieces: a dataclass in `elfresolver/constraints.py`, the `Symbol`
method adding it, and a class method on its kind inside IDA, marked with the constraint it
meets: `@SymbolResolution.constraint("calls")` for one returning every match at once, or
`@SymbolResolution.constraint("uses_const", cost=2)` for one checking a single candidate. Each
constraint has one method meeting it, called with the kind being resolved as `cls`: a kind
specializes it through the class methods it calls (`names_of`, `filter_from`, `references_to`). A
new kind is a `Symbol` class, and an `IDASymbol` class registering itself for it
(`class IDAVTable(IDASymbol, kind=VTable)`) in `elfresolver/ida/symbols/`.

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

## Performance

IDA's auto-analysis is the slow part, and it happens once per binary: the database is cached.
Measured with IDA 9.2 on Ubuntu's aarch64 builds of each binary:

| Query                                         | dash (0.2 MB) | libstdc++ (2.7 MB) | gdb (12 MB) |
|-----------------------------------------------|---------------|--------------------|-------------|
| First analysis, then opening the cached database | 1.8s, 0.5s | 12s, 0.7s          | 95s, 1.3s   |
| Every string; every global                    | 0.01s; 0.02s  | 0.13s; 0.14s       | 1.4s; 1.3s  |
| Every vtable (once the strings are read)      | 0s            | 0.03s              | 0.07s       |
| The callers of `malloc`; at any depth         | 0s; 0.01s     | 0s; 0.16s          | 0.01s; 0.7s |
| A constant, in every function                 | 0.03s         | 0.5s               | 3.0s        |
| Decompiling a function (`.structured_with()`) |               |                    | 0.5s each   |

A constraint relating to an anchor (an import, a string) takes milliseconds, whatever the
binary's size. One checking candidates costs per candidate, so give it anchors: `.structured_with()` on
the 360 functions calling `malloc` in gdb takes 3 minutes, on a handful a few seconds.

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
| `test_ida.py`                  | a C++ server: exceptions, virtual functions and vtables, thunks, lambdas, templates, statics |
| `test_ida_cpp_library.py`      | a C++ shared object: exported names, overloads, operators, vtables, calls through its own PLT |
| `test_ida_c.py`                | the server above in C, and C control flow: tail calls, cold paths, inlining, merged literals, constants, call depth |
| `test_ida_c_data.py`           | C data: tables of functions and strings, structs, lists, switch tables, decompiled structure |

A known limitation is marked as an expected failure where it applies, so a fix shows as XPASS.
A build whose compiler isn't installed is skipped. The compilers are looked up by target triplet
(`aarch64-linux-gnu-g++`, ...), with their `strip` and `nm`. On Debian/Ubuntu:

```bash
sudo apt-get install {gcc,g++}-{x86-64-linux-gnu,i686-linux-gnu,aarch64-linux-gnu,arm-linux-gnueabihf}
```

On macOS, wrappers on `PATH` named the same, running a Linux VM's compilers, work as well.

---

## Next

- **VTables**: `.slot(n)`, to get a virtual function as a `Function`.
- **Control flow**: basic-block counts, and more of the decompiled code's shape (calls, returns, gotos).
- **More constraints**: constant call arguments, call order, callbacks
  (`.passed_to(PLTEntry("pthread_create"), arg=2)`), reads and writes of a global,
  `Export("name")`, negation and alternatives.
- **Infrastructure**: a result cache that skips IDA altogether for builds seen before, an idalib
  backend, a pool of IDAs for many builds, and a CLI emitting offsets as JSON or a C header.
