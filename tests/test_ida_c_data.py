"""
Tests against a real IDA, on a C program of data built for every target a cross
compiler is installed for, then stripped (see real_ida.py): tables of function
pointers and of strings, structs, lists, thread-locals, and the switches GCC
turns into tables.

A GlobalVar is a data item as IDA typed it. In a stripped binary, that is often
a part of a C object: one of an array's pointers, one of a struct's fields. So
these tests check that a match lies inside the object the symbol table names.
"""
from elfresolver.symbols import Function, GlobalVar, String
from real_ida import EXECUTABLES, REAL_IDA, Program, limitation, module_fixture

pytestmark = REAL_IDA

SOURCE = r"""
#include <stdio.h>
#include <string.h>

#define KEEP __attribute__((noipa))

typedef int (*handler_t)(const char *path);

KEEP static int on_get(const char *path) { printf("GET %s\n", path); return 200; }
KEEP static int on_put(const char *path) { printf("PUT %s\n", path); return 201; }
KEEP static int on_delete(const char *path) { printf("DELETE %s\n", path); return 204; }

static handler_t const handlers[] = { on_get, on_put, on_delete };

KEEP int dispatch(int method, const char *path) {
    if (method < 0 || method > 2)
        return 400;
    return handlers[method](path);
}

static const char *const method_names[] = { "alpha method", "beta method", "gamma method" };
KEEP const char *method_name(int method) { return method_names[method % 3]; }

struct config { int verbose; int port; const char *host; };
struct config settings = { 0, 8080, "config host name" };
KEEP int configured_port(void) { printf("port %d\n", settings.port); return settings.port; }

struct node { const char *label; struct node *next; int value; };
static struct node third = { "third node", NULL, 3 };
static struct node second = { "second node", &third, 2 };
static struct node first = { "first node", &second, 1 };
KEEP int sum_list(void) {
    int sum = 0;
    for (struct node *node = &first; node != NULL; node = node->next)
        sum += node->value;
    printf("list sum %d\n", sum);
    return sum;
}

static const int primes[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29 };
KEEP int sum_primes(int count) {
    int sum = 0;
    for (int i = 0; i < count && i < 10; ++i)
        sum += primes[i];
    printf("sum of %d primes: %d\n", count, sum);
    return sum;
}

static char scratch[4096];
static int hits;
KEEP void remember(const char *text) {
    printf("remembering %s\n", text);
    strncpy(scratch, text, sizeof scratch - 1);
    hits++;
}

KEEP static void hook(void) { puts("the hook ran"); }
void (*exit_hook)(void) = hook;

__thread int thread_hits;
KEEP int count_thread_hit(void) { printf("thread hit %d\n", thread_hits); return ++thread_hits; }

KEEP const char *color_name(int color) {
    switch (color) {
    case 0: return "red";
    case 1: return "orange";
    case 2: return "yellow";
    case 3: return "green";
    case 4: return "blue";
    case 5: return "indigo";
    case 6: return "violet";
    default: return "no color";
    }
}

KEEP int classify(int value) {
    printf("classify %d\n", value);
    switch (value) {
    case 0: puts("zero"); return 10;
    case 1: remember("one"); return 11;
    case 2: perror("two"); return 12;
    case 3: return dispatch(1, "three");
    case 4: return sum_list();
    case 5: return sum_primes(5);
    case 6: return count_thread_hit();
    default: return -1;
    }
}

int main(int argc, char **argv) {
    printf("%d %s\n", dispatch(argc % 3, argc > 1 ? argv[1] : "/"), method_name(argc));
    printf("%d %d %d\n", configured_port(), sum_list(), sum_primes(argc + 3));
    remember(argv[0]);
    exit_hook();
    printf("%s %d\n", color_name(argc), classify(argc));
    return 0;
}
"""

DATA = Program("data", SOURCE, language="c")
data = module_fixture(DATA, EXECUTABLES)

GET = Function().references(String("GET %s\n"))


def on_arm(data) -> bool:
    return data.target.triplet.startswith(("aarch64", "arm"))


def section_anchors(data, request) -> None:
    """GCC's -O2 reaches ARM's statics through a section anchor: the address of the first in their section, plus an offset."""
    limitation(request, when=on_arm(data) and "-O2" in data.target.flags, reason=(
        "GCC reaches a static through a section anchor on ARM (the first static of its section, plus "
        "an offset): IDA refers to the anchor, a different variable, and not always to the static"
    ))


def test_each_handler_is_found_by_its_string(data):
    data.resolves(GET, to="on_get")
    data.resolves(Function().references(String("DELETE %s\n")), to="on_delete")


def test_main_is_a_function_on_every_target(data):
    """32-bit ARM's _start loads main's address (plus one: it is Thumb code) from the GOT, which IDA doesn't follow on its own."""
    data.resolves(Function().calls(Function().references(String("classify %d\n"))), to="main")


def test_a_table_of_function_pointers_is_found_by_a_function_in_it(data):
    data.resolves_within(GlobalVar().references(GET), to="handlers")
    data.resolves_within(GlobalVar().references(Function().references(String("PUT %s\n"))), to="handlers")


def test_the_function_indexing_a_table_refers_to_its_start(data, request):
    """dispatch refers to handlers, whose first pointer is on_get's."""
    section_anchors(data, request)  # method_name reaches method_names through handlers, the anchor
    data.resolves(Function().references(GlobalVar().references(GET)), to="dispatch")


def test_every_function_in_a_table_is_found_through_it(data, request):
    limitation(request, when=on_arm(data), reason=(
        "IDA types an ARM array of function pointers one pointer to an item (x86's, as one array): "
        "the global found by on_get is the first pointer, which refers to on_get alone"
    ))
    data.resolves_all(Function().referenced_by(GlobalVar().references(GET)), to=["on_get", "on_put", "on_delete"])


def test_a_table_of_strings_is_found_by_a_string_in_it(data):
    data.resolves_within(GlobalVar().references(String("beta method")), to="method_names")


def test_the_function_indexing_a_table_of_strings_refers_to_it(data, request):
    section_anchors(data, request)
    data.resolves(Function().references(GlobalVar().references(String("alpha method"))), to="method_name")


def test_a_field_read_by_a_function_lies_in_its_struct(data):
    """configured_port reads settings.port, past the struct's start: ARM's code refers to the start too, to add the offset to."""
    data.resolves_all_within(GlobalVar().referenced_by(Function().references(String("port %d\n"))), to=["settings"])


def test_a_struct_is_found_by_the_string_a_field_points_at(data):
    data.resolves_within(GlobalVar().references(String("config host name")), to="settings")


def test_a_node_of_a_list_is_found_by_its_label(data):
    data.resolves_within(GlobalVar().references(String("second node")), to="second")


def test_a_node_of_a_list_is_found_by_the_node_after_it(data):
    """A node's label is its first field: the global found by the label is where the node before points."""
    data.resolves_within(GlobalVar().references(GlobalVar().references(String("third node"))), to="second")


def test_the_function_walking_a_list_refers_to_its_head(data, request):
    section_anchors(data, request)  # first is the anchor's (settings) offset 0x10
    walker = Function().references(String("list sum %d\n"))
    data.resolves_within(GlobalVar().referenced_by(walker), to="first")


def test_a_read_only_table_is_a_global(data):
    """
    x86_64's GCC counts sum_primes's loop from 1 at -O2, and refers to primes - 4:
    right before the table, still. At -O3, it unrolls the loop into the table's
    numbers, and drops the table.
    """
    read = GlobalVar().referenced_by(Function().references(String("sum of %d primes: %d\n")))
    if "primes" not in data.symbols.symbols:
        assert data.resolve_all(read) == []
        return
    found = data.resolve(read)
    primes = data.symbols.range_of("primes")
    assert found.address in range(primes.start - 4, primes.stop), data._described(found.address)


def test_uninitialized_globals_are_found_by_the_function_writing_them(data):
    data.resolves_all_within(GlobalVar().referenced_by(Function().references(String("remembering %s\n"))), to=["scratch", "hits"])


def test_an_uninitialized_global_holds_no_pointer(data):
    """.bss is zeros on disk: nothing in it refers to anything."""
    assert data.resolve_all(Function().referenced_by(GlobalVar().referenced_by(Function().references(String("remembering %s\n"))))) == []


def test_a_function_pointer_variable_is_found_by_the_function_it_points_at(data):
    hook = Function().references(String("the hook ran"))
    data.resolves(GlobalVar().references(hook), to="exit_hook")
    data.resolves(Function().referenced_by(GlobalVar().references(hook)), to="hook")


def test_a_thread_local_is_found_by_the_function_using_it(data, request):
    limitation(request, reason=(
        "Code reaches a thread-local through the thread pointer and its offset in the TLS block (fs:-4, "
        "tpidr_el0, a GOT entry), which IDA cross-references to nothing: it doesn't even make a .tbss segment"
    ))
    data.resolves_within(GlobalVar().referenced_by(Function().references(String("thread hit %d\n"))), to="thread_hits")


def test_a_switch_returning_strings_finds_them_directly_or_through_its_table(data):
    """At -O2, GCC turns color_name's switch into a lookup table (CSWTCH) of the strings: through it, or not, they are found."""
    direct = data.resolve_all(Function().references(String("indigo")))
    through_table = data.resolve_all(Function().references(GlobalVar().references(String("indigo"))))
    assert {match.address for match in direct + through_table} == {data.symbols.address("color_name")}


def test_a_jump_table_is_no_global(data):
    """classify's switch jumps through a table of addresses inside it: that table is code's, no variable."""
    classify = Function().references(String("classify %d\n"))
    data.resolves(classify, to="classify")
    globals_used = data.resolve_all(GlobalVar().referenced_by(classify))
    assert globals_used == [], [data._described(match.address) for match in globals_used]
