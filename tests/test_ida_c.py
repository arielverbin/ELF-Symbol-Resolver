"""
Tests against a real IDA, on C programs built for every target a cross compiler
is installed for, then stripped (see real_ida.py): the README's server, and a
program of the control flow optimizing compilers make of C (tail calls, cold
paths, inlined helpers, merged strings).
"""
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from real_ida import EXECUTABLES, REAL_IDA, SHARED_OBJECTS, Program, limitation, module_fixture

pytestmark = REAL_IDA

# The README's server: read_request reads a request (recvfrom) after prompting for it,
# and hands it to parse_request, which counts it in requests_served.
SERVER_SOURCE = r"""
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

SERVER = Program("server", SERVER_SOURCE, language="c")
server = module_fixture(SERVER, EXECUTABLES + [target for target in SHARED_OBJECTS if target.name == "x86_64-O2-shared"])

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)
COUNTER = GlobalVar().referenced_by(PARSER)


def test_the_readmes_symbols_resolve_in_every_build(server):
    server.resolves(READER, to="read_request")
    server.resolves(PARSER, to="parse_request")
    server.resolves(COUNTER, to="requests_served")


FLOW_SOURCE = r"""
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define KEEP __attribute__((noipa))

// A chain of tail calls.
KEEP int stage_three(int x) { printf("stage three %d\n", x); return x * 3; }
KEEP int stage_two(int x) { printf("stage two %d\n", x); return stage_three(x + 2); }
KEEP int stage_one(int x) { printf("stage one %d\n", x); return stage_two(x + 1); }

// Recursion.
KEEP long fibonacci(int n) { return n < 2 ? n : fibonacci(n - 1) + fibonacci(n - 2); }
KEEP long report_fibonacci(int n) { long f = fibonacci(n); printf("fibonacci(%d) = %ld\n", n, f); return f; }

// An unlikely error path, which GCC moves into a .cold part of the function.
KEEP int parse_number(const char *text) {
    char *end;
    long value = strtol(text, &end, 10);
    if (__builtin_expect(*end != '\0', 0)) {
        fprintf(stderr, "not a number: %s\n", text);
        exit(2);
    }
    return (int)value;
}

// A helper the optimizer inlines into its callers.
static inline void log_line(const char *what) { printf("log line: %s\n", what); }
KEEP void open_door(void) { log_line("door opened"); }
KEEP void close_door(void) { log_line("door closed"); }

// One literal, used by two functions.
KEEP void first_sharer(void) { puts("shared message"); }
KEEP void second_sharer(void) { puts("shared message"); puts("first sharer"); }

// A literal the linker merges into the tail of a longer one.
KEEP void prompt_long(void) { puts("please enter the input"); }
KEEP void prompt_short(void) { puts("the input"); }

// Addresses taken: of functions of its own, and of an import.
KEEP static void on_interrupt(int signal_number) { (void)signal_number; puts("interrupted"); }
KEEP void install_handlers(void) { signal(SIGINT, on_interrupt); }
KEEP void *puts_address(void) { return (void *)&puts; }

// A tail call into the PLT.
KEEP void complain(const char *what) { perror(what); }

// Constants: a 64-bit multiplier (several instructions on ARM), and FNV-1a's offset basis and prime.
KEEP unsigned long long lcg_next(unsigned long long x) { return x * 0x5DEECE66DULL + 0xB; }
KEEP unsigned fnv1a(const char *text) {
    unsigned hash = 2166136261u;
    for (; *text; ++text) {
        hash ^= (unsigned char)*text;
        hash *= 16777619u;
    }
    return hash;
}

// A call to a function that never returns.
KEEP __attribute__((noreturn)) void die(const char *why) { fprintf(stderr, "dying: %s\n", why); exit(1); }
KEEP int checked_divide(int a, int b) { if (b == 0) die("division by zero"); return a / b; }

int main(int argc, char **argv) {
    stage_one(argc);
    report_fibonacci(argc + 10);
    parse_number(argc > 1 ? argv[1] : "42");
    open_door();
    close_door();
    first_sharer();
    second_sharer();
    prompt_long();
    prompt_short();
    install_handlers();
    printf("%p\n", puts_address());
    complain("main");
    printf("%llu %u\n", lcg_next(argc), fnv1a(argv[0]));
    return checked_divide(argc, argc);
}
"""

FLOW = Program("flow", FLOW_SOURCE, language="c")
flow = module_fixture(FLOW, EXECUTABLES)


def test_a_tail_called_function_is_called_by_its_caller(flow):
    flow.resolves(Function().called_by(Function().references(String("stage one %d\n"))), to="stage_two")


def test_a_tail_calling_function_calls_its_callee(flow):
    flow.resolves(Function().calls(Function().references(String("stage three %d\n"))), to="stage_two")


def test_a_chain_of_tail_calls_is_followed_hop_by_hop(flow):
    symbol = Function().called_by(Function().called_by(Function().references(String("stage one %d\n"))))
    flow.resolves(symbol, to="stage_three")


def test_a_recursive_function_calls_itself(flow):
    fibonacci = Function().called_by(Function().references(String("fibonacci(%d) = %ld\n")))
    flow.resolves(fibonacci, to="fibonacci")
    flow.resolves(Function().called_by(fibonacci), to="fibonacci")


def test_a_cold_path_is_found_by_its_string(flow):
    """The error path of parse_number: in the function, or the .cold part GCC moved it to."""
    flow.resolves_to_one_of(Function().references(String("not a number: %s\n")), flow.symbols.names("parse_number"))


def test_an_import_renamed_by_the_c_standard_is_found_by_a_pattern(flow):
    """glibc maps strtol to __isoc23_strtol in C23 (GCC 15's default): a pattern finds either."""
    flow.resolves_to_one_of(Function().calls(PLTEntry().matching(r"(^|_)strtol$")), flow.symbols.names("parse_number"))


def test_an_inlined_helpers_string_is_found_in_its_callers(flow):
    """At -O0, log_line is a function of its own; once inlined, its callers each refer to its string."""
    expected = ["log_line"] if flow.symbols.names("log_line") else ["open_door", "close_door"]
    flow.resolves_all(Function().references(String("log line: %s\n")), to=expected)


def test_a_literal_two_functions_use_is_referred_to_by_both(flow):
    flow.resolves_all(Function().references(String("shared message")), to=["first_sharer", "second_sharer"])


def test_a_literal_merged_into_another_is_found_by_its_own_text(flow):
    """The linker keeps "the input" as the tail of "please enter the input": each still names its own user."""
    flow.resolves(Function().references(String("the input")), to="prompt_short")
    flow.resolves(Function().references(String("please enter the input")), to="prompt_long")


def test_a_function_whose_address_is_taken_is_referred_to(flow):
    flow.resolves(Function().references(Function().references(String("interrupted"))), to="install_handlers")
    flow.resolves(Function().calls(PLTEntry("signal")), to="install_handlers")


def test_a_function_taking_an_imports_address_refers_to_it(flow):
    """A PIC program takes it from the GOT, whose slot points at the import, not at its PLT stub."""
    flow.resolves(Function().references(PLTEntry("puts")), to="puts_address")


def test_a_tail_call_into_the_plt_is_a_call(flow):
    """At -O2, complain is one jump to perror: IDA makes a thunk of it, through which its caller calls perror too."""
    found = {name for match in flow.resolve_all(Function().calls(PLTEntry("perror"))) for name in flow.symbols.at(match.address)}
    assert "complain" in found and found <= {"complain", "main"}, found


def test_a_call_to_a_function_that_never_returns_is_a_call(flow):
    die = Function().references(String("dying: %s\n"))
    flow.resolves(die, to="die")
    flow.resolves_to_one_of(Function().calls(die), flow.symbols.names("checked_divide"))


def test_a_function_is_found_by_its_constants(flow):
    """aarch64 builds a constant 16 bits at a time (MOVZ, MOVK), ARM 16 (MOVW, MOVT): IDA joins them into one MOV."""
    flow.resolves(Function().uses_const(2166136261), to="fnv1a")
    flow.resolves(Function().uses_const(16777619), to="fnv1a")


def test_a_64_bit_constant_is_found_on_a_64_bit_target(flow, request):
    limitation(request, when=flow.target.triplet.startswith(("i686", "arm")), reason=(
        "A 32-bit target multiplies by a 64-bit constant a half at a time: 0xDEECE66D, and 5"
    ))
    flow.resolves(Function().uses_const(0x5DEECE66D), to="lcg_next")


def test_a_negative_constant_is_found_as_the_unsigned_one_it_is(flow):
    """A negative value names the unsigned one of its width: 2166136261 - 2**32 is 0x811C9DC5, in 32 bits."""
    flow.resolves(Function().uses_const(2166136261 - 2**32), to="fnv1a")


def test_calls_are_followed_as_deep_as_asked(flow):
    stage_one = Function().references(String("stage one %d\n"))
    flow.resolves_all(Function().called_by(stage_one, max_depth=2), to=["stage_two", "stage_three"])
    stage_three = Function().references(String("stage three %d\n"))
    flow.resolves_all(Function().calls(stage_three, max_depth=2), to=["stage_one", "stage_two"])
    flow.resolves_all(Function().calls(stage_three, max_depth=None), to=["stage_one", "stage_two", "main"])
