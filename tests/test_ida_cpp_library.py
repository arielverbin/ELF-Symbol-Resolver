"""
Tests against a real IDA, on a C++ shared object built for every target a cross
compiler is installed for, then stripped (see real_ida.py). Stripping keeps the
names it exports (in .dynsym): this is where a symbol is found by its C++ name,
mangled or demangled, as GNU's tools show it (nm -C, c++filt).
"""
import pytest
from elfresolver.exceptions import AmbiguousSymbolError
from elfresolver.symbols import Function, GlobalVar, PLTEntry, String
from real_ida import REAL_IDA, SHARED_OBJECTS, Program, limitation, module_fixture

pytestmark = REAL_IDA

SOURCE = r"""
#include <cmath>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace geo {

struct Point {
    double x, y;
    double length() const;
    bool operator==(const Point& other) const;
    explicit operator bool() const;
};

int instances = 0;

double Point::length() const { return std::sqrt(x * x + y * y); }
bool Point::operator==(const Point& other) const { return x == other.x && y == other.y; }
Point::operator bool() const { return x != 0 || y != 0; }

Point operator+(const Point& a, const Point& b) { return {a.x + b.x, a.y + b.y}; }
double distance(const Point& a, const Point& b) { return Point{a.x - b.x, a.y - b.y}.length(); }

Point scale(Point p, int factor) { return {p.x * factor, p.y * factor}; }
Point scale(Point p, double factor) { return {p.x * factor, p.y * factor}; }

template <typename T>
T sum(const T* values, int count) {
    T total{};
    for (int i = 0; i < count; ++i)
        total += values[i];
    return total;
}
template int sum<int>(const int*, int);
template double sum<double>(const double*, int);

template <typename T>
class Box {
public:
    Box(T width, T height) : width_(width), height_(height) {}
    T area() const;
private:
    T width_, height_;
};
template <typename T> T Box<T>::area() const { return width_ * height_; }
template class Box<int>;

class Shape {
public:
    Shape();
    virtual ~Shape();
    virtual double area() const = 0;
    virtual const char* kind() const;
};
Shape::Shape() { ++instances; }
Shape::~Shape() { --instances; }
const char* Shape::kind() const { return "a shape"; }

class Polygon : public Shape {
public:
    explicit Polygon(std::vector<Point> corners);
    ~Polygon() override;
    double area() const override;
    const char* kind() const override;
    double perimeter() const;
private:
    std::vector<Point> corners_;
};
Polygon::Polygon(std::vector<Point> corners) : corners_(std::move(corners)) {}
Polygon::~Polygon() = default;
double Polygon::area() const {
    double twice = 0;
    for (std::size_t i = 0; i < corners_.size(); ++i) {
        const Point& a = corners_[i];
        const Point& b = corners_[(i + 1) % corners_.size()];
        twice += a.x * b.y - b.x * a.y;
    }
    return std::fabs(twice) / 2;
}
const char* Polygon::kind() const { return "a polygon"; }
double Polygon::perimeter() const {
    double total = 0;
    for (std::size_t i = 0; i < corners_.size(); ++i)
        total += distance(corners_[i], corners_[(i + 1) % corners_.size()]);
    return total;
}

struct Scaler {
    double factor;
    Point operator()(Point p) const;
};
Point Scaler::operator()(Point p) const { return scale(p, factor); }

void must_be_positive(double value) {
    if (value <= 0)
        throw std::domain_error("not positive");
}

std::string describe(const Shape& shape) { return std::string(shape.kind()) + " of area " + std::to_string(shape.area()); }

std::map<std::string, int> histogram(const std::vector<std::string>& words) {
    std::map<std::string, int> counts;
    for (const std::string& word : words)
        ++counts[word];
    return counts;
}

void apply(const std::function<void(Point&)>& change, std::vector<Point>& points) {
    for (Point& point : points)
        change(point);
}

namespace {
int hidden_helper(int value) { return value * 7; }
}

int uses_hidden(int value) { return hidden_helper(value) + 1; }

}  // namespace geo

extern "C" const char* geo_version() { return "geo 1.0"; }
"""

LIBRARY = Program("geometry", SOURCE)
library = module_fixture(LIBRARY, SHARED_OBJECTS)


# Names, as GNU's tools show them.

def test_an_exported_function_is_found_by_its_demangled_name(library):
    library.resolves(Function("geo::Point::length() const"), to="geo::Point::length() const")


def test_an_exported_function_is_found_by_its_name_without_parameters(library):
    library.resolves(Function("geo::Point::length"), to="geo::Point::length() const")


def test_an_exported_function_is_found_by_its_mangled_name(library):
    library.resolves(Function("_ZNK3geo5Point6lengthEv"), to="geo::Point::length() const")


def test_overloads_are_ambiguous_by_their_name_alone(library):
    with pytest.raises(AmbiguousSymbolError) as raised:
        library.resolve(Function("geo::scale"))
    found = {name for match in raised.value.matches for name in library.symbols.at(match.address)}
    assert found == {"geo::scale(geo::Point, int)", "geo::scale(geo::Point, double)"}


def test_an_overload_is_found_by_its_parameters(library):
    library.resolves(Function("geo::scale(geo::Point, double)"), to="geo::scale(geo::Point, double)")


def test_a_function_template_instance_is_found_as_gnu_shows_it(library):
    """GNU shows a function template's instance with its return type first."""
    library.resolves(Function("int geo::sum<int>(int const*, int)"), to="int geo::sum<int>(int const*, int)")


def test_a_function_template_instance_is_found_without_its_return_type(library):
    library.resolves(Function("geo::sum<int>"), to="int geo::sum<int>(int const*, int)")
    library.resolves(Function("geo::sum<double>(double const*, int)"), to="double geo::sum<double>(double const*, int)")


def test_every_instance_of_a_function_template_is_found_by_a_pattern(library):
    library.resolves_all(
        Function().matching(r"^geo::sum<"),
        to=["int geo::sum<int>(int const*, int)", "double geo::sum<double>(double const*, int)"],
    )


def test_a_class_template_member_is_found(library):
    library.resolves(Function("geo::Box<int>::area() const"), to="geo::Box<int>::area() const")


def test_operators_are_found_by_their_names(library):
    library.resolves(Function("geo::operator+"), to="geo::operator+(geo::Point const&, geo::Point const&)")
    library.resolves(Function("geo::Point::operator=="), to="geo::Point::operator==(geo::Point const&) const")
    library.resolves(Function("geo::Scaler::operator()"), to="geo::Scaler::operator()(geo::Point) const")


def test_a_conversion_operator_is_found_by_its_name(library):
    library.resolves(Function("geo::Point::operator bool"), to="geo::Point::operator bool() const")


def test_a_constructor_is_found_by_its_class(library):
    """GCC emits the complete and the base object constructor at one address."""
    library.resolves(Function("geo::Polygon::Polygon"), to="geo::Polygon::Polygon(std::vector<geo::Point, std::allocator<geo::Point> >)")


def test_a_destructor_is_ambiguous_between_its_deleting_and_complete_variants(library):
    """Both demangle to geo::Polygon::~Polygon(): the mangled name tells them apart."""
    with pytest.raises(AmbiguousSymbolError):
        library.resolve(Function("geo::Polygon::~Polygon()"))
    deleting = library.resolve(Function("_ZN3geo7PolygonD0Ev"))
    assert "geo::Polygon::~Polygon()" in library.symbols.at(deleting.address)


def test_an_abi_tagged_function_is_found_without_its_tag(library):
    """A function returning a std::string has [abi:cxx11] in its name."""
    library.resolves(Function("geo::describe"), to="geo::describe[abi:cxx11](geo::Shape const&)")


def test_a_long_parameter_list_is_matched_as_gnu_spaces_it(library):
    name = "geo::apply(std::function<void (geo::Point&)> const&, std::vector<geo::Point, std::allocator<geo::Point> >&)"
    library.resolves(Function(name), to=name)


def test_a_template_instance_returning_a_template_is_found_without_its_return_type(library):
    """std::to_string's helper, which the library exports: its return type, a std::string, has spaces of its own."""
    name = "__gnu_cxx::__to_xstring<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, char>"
    library.resolves(Function(name), to=library.symbols.only_name(name + "("))


def test_an_extern_c_function_is_found_by_its_name_and_its_string(library):
    library.resolves(Function("geo_version"), to="geo_version")
    library.resolves(Function().references(String("geo 1.0")), to="geo_version")


# Calls, references and exceptions, between exported functions.

def test_an_exported_function_is_called_by_another(library):
    """In a shared object, a call to an exported function goes through the library's own PLT: it may be interposed."""
    library.resolves(Function().calls(Function("geo::distance")), to="geo::Polygon::perimeter() const")


def test_an_exported_function_calls_another(library):
    library.resolves(Function().called_by(Function("geo::distance")), to="geo::Point::length() const")


def test_an_exported_global_is_found_by_its_name(library):
    library.resolves(GlobalVar("geo::instances"), to="geo::instances")


def test_the_functions_counting_instances_refer_to_them_through_the_got(library):
    found = {match.address for match in library.resolve_all(Function().references(GlobalVar("geo::instances")))}
    constructor = library.symbols.address("geo::Shape::Shape()")
    destructors = {address for address, _ in library.symbols.symbols["geo::Shape::~Shape()"]}
    assert constructor in found
    assert found - {constructor} <= destructors and found & destructors


def test_an_exception_thrown_by_an_exported_function(library):
    symbol = Function().calls(PLTEntry("__cxa_throw")).references(String("not positive"))
    library.resolves_to_one_of(symbol, library.symbols.names("geo::must_be_positive(double)"))


def test_a_function_in_an_anonymous_namespace_is_found_by_its_caller(library):
    """Stripping removes its name, so its caller finds it; unless the compiler inlined it there."""
    callees = library.resolve_all(Function().called_by(Function("geo::uses_hidden")))
    hidden = library.symbols.names("(anonymous namespace)::hidden_helper")
    assert {match.address for match in callees} == {library.symbols.address(name) for name in hidden}


# Virtual functions, vtables and typeinfo, by their exported names.

def test_a_vtable_is_found_by_its_name(library):
    library.resolves(GlobalVar("vtable for geo::Polygon"), to="vtable for geo::Polygon")


def test_a_vtable_is_found_by_a_virtual_function_in_it(library):
    library.resolves_within(GlobalVar().references(Function("geo::Polygon::kind() const")), to="vtable for geo::Polygon")


def test_a_typeinfo_is_found_by_its_name_and_by_its_class_name(library):
    library.resolves(GlobalVar("typeinfo for geo::Polygon"), to="typeinfo for geo::Polygon")
    library.resolves_within(GlobalVar().references(String("N3geo7PolygonE")), to="typeinfo for geo::Polygon")


def test_the_virtual_functions_in_a_vtable_are_found_through_it(library, request):
    limitation(request, reason=(
        "IDA types a vtable one pointer to an item, even with its symbol's size known: the vtable "
        "is its first slot (the offset to the object's top), which holds no pointer"
    ))
    found = {name for match in library.resolve_all(Function().referenced_by(GlobalVar("vtable for geo::Polygon")))
             for name in library.symbols.at(match.address)}
    assert {"geo::Polygon::area() const", "geo::Polygon::kind() const"} <= found
