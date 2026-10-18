"""Tests for what IDA's side reads names and strings as: the names imports answer to, and C strings in raw bytes."""
import pytest
from elfresolver.ida.names import SymName
from elfresolver.ida.symbols.string import IDAString


@pytest.mark.parametrize(("demangled", "without"), [
    ("recvfrom", "recvfrom"),
    ("ns::parse(char const*, unsigned long)", "ns::parse"),
    ("ns::Box<int>::get(int) const", "ns::Box<int>::get"),
    ("std::function<void (int)>::operator()(int) const", "std::function<void (int)>::operator()"),
])
def test_without_parameters(demangled, without):
    assert SymName.without_parameters(demangled) == without


@pytest.mark.skipif(SymName._cxa_demangle() is None, reason="No C++ runtime to demangle with")
def test_a_mangled_name_answers_to_every_form():
    assert SymName("_ZN2ns5parseEPKc").forms == ("_ZN2ns5parseEPKc", "ns::parse(char const*)", "ns::parse")


def test_a_plain_name_answers_to_itself():
    assert SymName("recvfrom").demangled is None
    assert SymName("recvfrom").forms == ("recvfrom",)


RODATA = b"\x01\x02\0enter input\0%s: %d\n\0\xff\xfe\0"


def test_c_strings_are_printable_runs_ending_in_a_nul():
    assert list(IDAString.c_strings(RODATA)) == [(3, "enter input"), (15, "%s: %d\n")]


def test_a_literal_starts_inside_a_run_of_text_where_something_refers_to_it():
    """A merged tail ('input' in 'enter input'), or text right after data with no NUL between (a double's '@')."""
    data = b"\0\x00\x00\x00@N3geo7PolygonE\0enter input\0"
    referenced = {5, 26}.__contains__
    assert list(IDAString.c_strings(data, referenced)) == [(4, "@N3geo7PolygonE"), (5, "N3geo7PolygonE"), (20, "enter input"), (26, "input")]


def test_a_literal_after_unprintable_bytes_is_found_where_something_refers_to_it():
    data = b"\x01\x02text\0"
    assert list(IDAString.c_strings(data)) == []
    assert list(IDAString.c_strings(data, {2}.__contains__)) == [(2, "text")]


def test_c_string_at_reads_from_any_offset():
    assert IDAString.c_string_at(RODATA, 3) == "enter input"
    assert IDAString.c_string_at(RODATA, 9) == "input"   # the tail of a longer literal
    assert IDAString.c_string_at(RODATA, 0) is None      # not printable
