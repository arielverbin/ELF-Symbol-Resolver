"""
Tests against a real IDA, on a C++ server built for every target a cross compiler
is installed for, then stripped (see real_ida.py). Every symbol must resolve, in
every build, to where the unstripped build's symbol table puts what it describes.

The server is the README's: it reads a request (recvfrom), after prompting for it,
and hands it to the function that parses it, which counts it in a global. Around
it is the C++ a real server has: classes with virtual functions, exceptions,
lambdas, templates, and objects initialized at startup or on first use.
"""
import pytest
from elfresolver.exceptions import AmbiguousSymbolError, SymbolNotFoundError
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from real_ida import EXECUTABLES, REAL_IDA, Program, limitation, module_fixture

pytestmark = REAL_IDA

SOURCE = r"""
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

// Neither inlined nor cloned, as a helper with many callers would be.
#define KEEP __attribute__((noipa))

namespace net {

static int requests_served;

class Request {
public:
    explicit Request(std::string text) : text_(std::move(text)) {}
    KEEP int words() const;
    const std::string& text() const { return text_; }
private:
    std::string text_;
};

int Request::words() const {
    int count = 0;
    bool in_word = false;
    for (char c : text_) {
        if (c == ' ') {
            in_word = false;
        } else if (!in_word) {
            in_word = true;
            ++count;
        }
    }
    return count;
}

class Handler {
public:
    virtual ~Handler() = default;
    virtual const char* name() const = 0;
    virtual int handle(const Request& request) = 0;
};

class EchoHandler final : public Handler {
public:
    const char* name() const override;
    int handle(const Request& request) override;
};

class CountHandler final : public Handler {
public:
    const char* name() const override;
    int handle(const Request& request) override;
private:
    int total_ = 0;
};

const char* EchoHandler::name() const { return "echo handler"; }
int EchoHandler::handle(const Request& request) { std::printf("echo: %s\n", request.text().c_str()); return 0; }
const char* CountHandler::name() const { return "count handler"; }
int CountHandler::handle(const Request& request) { total_ += request.words(); return total_; }

KEEP std::unique_ptr<Handler> make_handler(const char* kind) {
    if (std::strcmp(kind, "echo") == 0)
        return std::make_unique<EchoHandler>();
    if (std::strcmp(kind, "count") == 0)
        return std::make_unique<CountHandler>();
    throw std::invalid_argument("unknown handler kind");
}

KEEP void parse_request(const char* text, long length) {
    requests_served++;
    Request request(std::string(text, length));
    std::unique_ptr<Handler> handler = make_handler(request.words() > 1 ? "count" : "echo");
    std::printf("request #%d by the %s: %d\n", requests_served, handler->name(), handler->handle(request));
}

KEEP void read_request(int fd) {
    static char buffer[512];
    std::puts("enter input");
    long length = recvfrom(fd, buffer, sizeof buffer, 0, nullptr, nullptr);
    if (length > 0)
        parse_request(buffer, length);
}

// Lambdas, called through a std::function, and through a template.

KEEP int visit_words(const std::string& text, const std::function<void(const std::string&)>& visit) {
    std::string word;
    int visited = 0;
    for (char c : text + " ") {
        if (c != ' ') {
            word += c;
        } else if (!word.empty()) {
            visit(word);
            ++visited;
            word.clear();
        }
    }
    return visited;
}

KEEP void print_words(const std::string& text) {
    visit_words(text, [](const std::string& word) { std::printf("word: %s\n", word.c_str()); });
}

template <typename Visit>
KEEP int for_each_digit(int number, Visit visit) {
    int digits = 0;
    do {
        visit(number % 10);
        number /= 10;
        ++digits;
    } while (number != 0);
    return digits;
}

KEEP int digit_sum(int number) {
    int sum = 0;
    for_each_digit(number, [&sum](int digit) { sum += digit; });
    std::printf("digit sum of %d: %d\n", number, sum);
    return sum;
}

// A template instantiated twice: its __PRETTY_FUNCTION__ tells the instances apart.

template <typename T>
KEEP T clamped(T value, T low, T high) {
    if (value < low || value > high)
        std::printf("%s: clamping\n", __PRETTY_FUNCTION__);
    return std::min(std::max(value, low), high);
}

// Objects initialized at startup, and on first use.

class Registry {
public:
    KEEP explicit Registry(const char* name);
    KEEP ~Registry();
    KEEP void add(const char* handler) { handlers_.push_back(handler); }
private:
    std::vector<std::string> handlers_;
    const char* name_;
};

Registry::Registry(const char* name) : name_(name) { std::printf("registry %s opened\n", name); }
Registry::~Registry() { std::printf("registry %s closed\n", name_); }

static Registry startup_registry("startup");

KEEP Registry& lazy_registry() {
    static Registry instance("lazy");
    return instance;
}

// Two bases with virtual functions: the second's are reached through this-adjusting thunks.

class Named {
public:
    virtual ~Named() = default;
    virtual const char* label() const = 0;
};

class Counted {
public:
    virtual ~Counted() = default;
    virtual int count() const = 0;
};

class Inventory final : public Named, public Counted {
public:
    const char* label() const override;
    int count() const override;
};

const char* Inventory::label() const { return "inventory label"; }
int Inventory::count() const { std::puts("counting the inventory"); return 42; }

KEEP int count_of(const Counted& counted) { return counted.count(); }

KEEP void must_not_fail(int code) noexcept {
    if (code != 0) {
        std::fputs("fatal: giving up\n", stderr);
        std::terminate();
    }
}

}  // namespace net

int main(int argc, char** argv) {
    net::read_request(0);
    net::print_words(argc > 1 ? argv[1] : "two words");
    net::digit_sum(argc * 1234);
    std::printf("%d %f\n", net::clamped(argc, 0, 10), net::clamped(argc * 0.5, 0.0, 1.0));
    net::lazy_registry().add("echo");
    net::Inventory inventory;
    std::printf("%s %d\n", inventory.label(), net::count_of(inventory));
    net::must_not_fail(argc - 1);
    return 0;
}
"""

SERVER = Program("server", SOURCE)
server = module_fixture(SERVER, EXECUTABLES)

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
PARSER = Function().called_by(READER)
COUNTER = GlobalVar().referenced_by(PARSER)


# The README's symbols.

def test_the_reader_is_found_by_its_import_and_its_prompt(server):
    server.resolves(READER, to="net::read_request(int)")


def test_the_parser_is_found_by_its_caller(server):
    server.resolves(PARSER, to="net::parse_request(char const*, long)")


def test_the_counter_is_found_by_the_function_counting_in_it(server):
    server.resolves(COUNTER, to="net::requests_served")


def test_a_symbol_nothing_matches_raises(server):
    symbol = Function().calls(PLTEntry("sendto"))
    with pytest.raises(SymbolNotFoundError) as raised:
        server.resolve(symbol)
    assert str(raised.value) == f"Nothing matches {symbol!r}"


def test_an_import_with_many_callers_is_ambiguous(server):
    """puts is called from several functions: resolve() refuses to pick one."""
    with pytest.raises(AmbiguousSymbolError) as raised:
        server.resolve(Function().calls(PLTEntry("puts")))
    assert len(raised.value.matches) >= 2


# Exceptions.

def _thrower(server):
    """make_handler, or its .cold part: GCC may move a throw, a cold path, out of the function."""
    return [name for name in server.symbols.names("net::make_handler(char const*)")]


def test_a_function_is_found_by_the_exception_it_throws(server):
    symbol = Function().calls(PLTEntry("__cxa_throw")).references(String("unknown handler kind"))
    server.resolves_to_one_of(symbol, _thrower(server))


def test_a_mangled_import_is_found_by_its_demangled_name(server):
    server.resolves_to_one_of(
        Function().calls(PLTEntry("std::invalid_argument::invalid_argument(char const*)")), _thrower(server),
    )


def test_a_mangled_import_is_found_by_its_name_without_parameters(server):
    server.resolves_to_one_of(Function().calls(PLTEntry("std::invalid_argument::invalid_argument")), _thrower(server))


def test_a_mangled_import_is_found_by_its_mangled_name(server):
    server.resolves_to_one_of(Function().calls(PLTEntry("_ZNSt16invalid_argumentC1EPKc")), _thrower(server))


def test_a_versioned_cxx_import_is_found_without_its_version(server):
    """std::terminate is linked as _ZSt9terminatev@GLIBCXX_3.4."""
    found = server.resolve(PLTEntry("std::terminate()"))
    assert found.name == "std::terminate()"


def test_a_noexcept_function_is_found_by_its_terminate(server):
    symbol = Function().calls(PLTEntry("std::terminate")).references(String("fatal: giving up\n"))
    server.resolves_to_one_of(symbol, server.symbols.names("net::must_not_fail(int)"))


# Virtual functions, their vtables, and their RTTI.

def test_a_virtual_function_is_found_by_its_string(server):
    server.resolves(Function().references(String("echo handler")), to="net::EchoHandler::name() const")


def test_a_vtable_is_found_by_a_virtual_function_in_it(server):
    symbol = GlobalVar().references(Function().references(String("echo handler")))
    server.resolves_within(symbol, to="vtable for net::EchoHandler")


def test_the_vtables_of_two_classes_are_told_apart(server):
    echo = server.resolve(GlobalVar().references(Function().references(String("echo handler"))))
    count = server.resolve(GlobalVar().references(Function().references(String("count handler"))))
    assert echo.address in server.symbols.range_of("vtable for net::EchoHandler")
    assert count.address in server.symbols.range_of("vtable for net::CountHandler")


def test_a_class_is_found_by_its_typeinfo_name(server):
    """A stripped C++ binary still holds its classes' mangled names, for RTTI."""
    symbol = GlobalVar().references(String("N3net11EchoHandlerE"))
    server.resolves_within(symbol, to="typeinfo for net::EchoHandler")


@pytest.mark.xfail(reason=(
    "IDA types a stripped binary's typeinfo and vtables one pointer to an item: the global holding the "
    "name's pointer is a slot inside the typeinfo, which nothing refers to (the vtable refers to its start)"
))
def test_a_vtable_is_found_through_its_typeinfo(server):
    symbol = GlobalVar().references(GlobalVar().references(String("N3net11CountHandlerE")))
    server.resolves_within(symbol, to="vtable for net::CountHandler")


def test_a_virtual_function_may_be_copied_where_it_is_devirtualized(server):
    """
    At -O2, GCC copies Inventory::count into the thunk adjusting `this` for its
    second base, and into count_of, which it devirtualized speculatively: every
    copy refers to its string, and nothing else does.
    """
    copies = server.resolve_all(Function().references(String("counting the inventory")))
    names = {name for match in copies for name in server.symbols.at(match.address)}
    assert "net::Inventory::count() const" in names
    assert names <= {
        "net::Inventory::count() const", "non-virtual thunk to net::Inventory::count() const",
        "net::count_of(net::Counted const&)",
    }, names


def test_a_this_adjusting_thunk_calls_its_override_or_is_a_copy_of_it(server):
    count = Function().references(String("counting the inventory"))
    found = server.resolve_all(Function().calls(count)) + server.resolve_all(count)
    thunk = server.symbols.address("non-virtual thunk to net::Inventory::count() const")
    assert thunk in {match.address for match in found}


# Lambdas.

def test_a_lambda_called_through_a_std_function_is_found_by_its_string(server):
    """The lambda's body is its operator(), or the std::function invoker it was inlined into."""
    found = server.resolve(Function().references(String("word: %s\n")))
    names = server.symbols.at(found.address)
    assert any("net::print_words" in name and "{lambda" in name for name in names), names


def test_a_template_called_with_a_lambda_is_found_by_its_caller(server):
    symbol = Function().called_by(Function().references(String("digit sum of %d: %d\n")))
    found = server.resolve(symbol)
    names = server.symbols.at(found.address)
    assert any("net::for_each_digit<net::digit_sum(int)::{lambda(int)#1}>" in name for name in names), names


def test_a_function_called_through_its_callers_callee_is_found(server):
    """Two hops of calls: read_request calls parse_request, which calls make_handler."""
    symbol = Function().called_by(PARSER).calls(PLTEntry("__cxa_throw"))
    server.resolves_to_one_of(symbol, server.symbols.names("net::make_handler(char const*)"))


# Templates.

def test_a_template_instance_is_found_by_its_pretty_function(server):
    symbol = Function().references(String("T net::clamped(T, T, T) [with T = int]"))
    found = server.resolve(symbol)
    assert server.symbols.at(found.address) == ["int net::clamped<int>(int, int, int)"]


def test_a_pretty_function_is_a_string_literal_like_any(server):
    """__PRETTY_FUNCTION__ is a literal of its own; the format string around it, another."""
    server.resolve(String("T net::clamped(T, T, T) [with T = double]"))


def test_every_instance_of_a_template_is_found_by_a_pattern(server, request):
    limitation(request, when=server.target.triplet == "arm-linux-gnueabihf", reason=(
        "IDA leaves some of armhf's PC-relative loads unresolved (ldr from a literal pool, then add pc, "
        "two instructions apart): the double instance's __PRETTY_FUNCTION__ has no reference to it"
    ))
    symbol = Function().references(String().matching(r"^T net::clamped\(T, T, T\) \[with T = "))
    server.resolves_all(symbol, to=["int net::clamped<int>(int, int, int)", "double net::clamped<double>(double, double, double)"])


# Objects initialized at startup, and on first use.

def test_a_constructor_is_found_by_its_string(server):
    server.resolves(Function().references(String("registry %s opened\n")), to="net::Registry::Registry(char const*)")


def test_a_function_local_static_is_guarded(server):
    symbol = Function().calls(PLTEntry("__cxa_guard_acquire"))
    server.resolves_to_one_of(symbol, server.symbols.names("net::lazy_registry()"))


def test_a_function_local_static_and_its_guard_are_globals(server, request):
    limitation(request, when=server.target.name == "aarch64-O2", reason=(
        "GCC addresses aarch64's statics through a section anchor (adrp, add, then add the offset): "
        "IDA refers only to the anchor, the first static, and never to `instance`"
    ))
    lazy = Function().calls(Function().references(String("registry %s opened\n"))).calls(PLTEntry("__cxa_guard_acquire"))
    found = {name for match in server.resolve_all(GlobalVar().referenced_by(lazy)) for name in server.symbols.around(match.address)}
    assert {"net::lazy_registry()::instance", "guard variable for net::lazy_registry()::instance"} <= found, found


def test_the_constructor_is_called_at_startup_and_on_first_use(server):
    callers = server.resolve_all(Function().calls(Function().references(String("registry %s opened\n"))))
    names = [server.symbols.at(match.address) for match in callers]
    assert len(callers) == 2, names
    assert any(any("lazy_registry" in name for name in at) for at in names), names
