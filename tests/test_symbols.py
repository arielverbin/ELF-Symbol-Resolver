"""
Tests for the symbols: the values a resolver is asked to find.

  * Every constraint method returns a new symbol, leaving the one it's called on as it was.
  * A name given to a symbol's constructor is matched whole, and literally.
  * Symbols are equal, and hash alike, when their kinds and constraints are.
  * A symbol's repr is the expression that builds it.
  * Arguments a constraint can't take fail where they are written.
"""
import re
import pytest
from elfresolver import Function, GlobalVar, PLTEntry, String
from elfresolver.constraints import Calls, Matching, References

READER = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))


def _exactly(name: str) -> Matching:
    return Matching(rf"\A{re.escape(name)}\Z")


def test_a_constraint_method_returns_a_new_symbol():
    function = Function()
    calling = function.calls(PLTEntry("recvfrom"))
    assert function.constraints == ()
    assert calling.constraints == (Calls(PLTEntry("recvfrom")),)


def test_constraints_keep_the_order_they_were_added_in():
    assert READER.constraints == (Calls(PLTEntry("recvfrom")), References(String("enter input")))


def test_a_name_is_the_first_constraint():
    assert String("enter input").matching("input").constraints == (_exactly("enter input"), Matching("input"))


def test_equal_symbols_hash_alike():
    again = Function().calls(PLTEntry("recvfrom")).references(String("enter input"))
    assert again == READER
    assert hash(again) == hash(READER)
    assert len({READER, again}) == 1


def test_symbols_of_other_kinds_differ():
    """Even a PLTEntry, a Function too, differs from a Function with the same constraints."""
    assert Function("recvfrom") != PLTEntry("recvfrom")
    assert GlobalVar() != String()


def test_symbols_with_other_constraints_differ():
    assert READER != Function().calls(PLTEntry("recvfrom"))
    assert PLTEntry("recvfrom") != PLTEntry("recv")


def test_repr_goes_one_level_deep_naming_the_symbols_in_it_by_their_ids():
    parser = Function().called_by(READER)
    symbol = GlobalVar().referenced_by(parser).matching("^g_")
    assert repr(symbol) == f"GlobalVar({hex(id(symbol))}).referenced_by({hex(id(parser))}).matching('^g_')"
    assert repr(parser) == f"Function({hex(id(parser))}).called_by({hex(id(READER))})"


def test_every_symbol_has_an_id_of_its_own():
    """Equal symbols are still told apart in the logs: each step of a chain is a symbol of its own."""
    assert PLTEntry("recvfrom").id != PLTEntry("recvfrom").id
    function = Function()
    assert function.calls(READER).id != function.id


def test_a_plt_entry_is_a_function():
    """It has a function's constraint methods, and can be called."""
    assert isinstance(PLTEntry("recvfrom"), Function)
    assert PLTEntry().called_by(READER).constraints[0].caller == READER


@pytest.mark.parametrize("build", [
    lambda: Function().calls(String("enter input")),
    lambda: Function().called_by(GlobalVar()),
    lambda: Function().references("enter input"),
])
def test_an_argument_of_the_wrong_kind_raises_where_it_is_written(build):
    with pytest.raises(TypeError, match=r"takes a (Function|Symbol), not"):
        build()


def test_a_malformed_pattern_raises_where_it_is_written():
    with pytest.raises(re.error):
        String().matching("enter (input")
