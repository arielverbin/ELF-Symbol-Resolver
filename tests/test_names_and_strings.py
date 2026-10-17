"""Tests for what IDA's side reads names and strings as: the names imports answer to, and C strings in raw bytes."""
import pytest
from elfresolver.ida.symbols.string import c_string_at, c_strings
from elfresolver.ida.symbols.symbol import name_forms, without_parameters, without_version


@pytest.mark.parametrize(("demangled", "without"), [
    ("recvfrom", "recvfrom"),
    ("ns::parse(char const*, unsigned long)", "ns::parse"),
    ("ns::Box<int>::get(int) const", "ns::Box<int>::get"),
    ("std::function<void (int)>::operator()(int) const", "std::function<void (int)>::operator()"),
])
def test_without_parameters(demangled, without):
    assert without_parameters(demangled) == without


def test_without_version():
    assert without_version("recvfrom@GLIBC_2.2.5") == "recvfrom"
    assert without_version("recvfrom") == "recvfrom"


def test_a_mangled_name_answers_to_every_form():
    assert name_forms("_ZN2ns5parseEPKc", "ns::parse(char const*)") == ("_ZN2ns5parseEPKc", "ns::parse(char const*)", "ns::parse")


def test_a_plain_name_answers_to_itself():
    assert name_forms("recvfrom", None) == ("recvfrom",)


RODATA = b"\x01\x02\0enter input\0%s: %d\n\0\xff\xfe\0"


def test_c_strings_are_printable_runs_ending_in_a_nul():
    assert list(c_strings(RODATA)) == [(3, "enter input"), (15, "%s: %d\n")]


def test_c_string_at_reads_from_any_offset():
    assert c_string_at(RODATA, 3) == "enter input"
    assert c_string_at(RODATA, 9) == "input"   # the tail of a longer literal
    assert c_string_at(RODATA, 0) is None      # not printable
