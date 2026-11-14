from decimal import Decimal

import pytest

from sentrycove.sfv import InnerList, Item, SFVError, Token, parse_dictionary, serialize_inner_list, serialize_item


def test_parse_signature_input_inner_list_with_params():
    d = parse_dictionary('sig1=("@authority" "signature-agent");created=1700000000;keyid="abc";tag="web-bot-auth"')
    member = d["sig1"]
    assert isinstance(member, InnerList)
    assert [i.value for i in member.items] == ["@authority", "signature-agent"]
    assert member.params == {"created": 1700000000, "keyid": "abc", "tag": "web-bot-auth"}


def test_round_trip_is_canonical():
    raw = '("@authority" "x";key="sig1");created=1;alg="ed25519";flag;n=-3'
    parsed = parse_dictionary(f"a={raw}")["a"]
    assert serialize_inner_list(parsed) == raw


def test_multiple_members_and_whitespace():
    d = parse_dictionary('a=1,  b="two" , c=?0, d, e=tok/en, f=:aGVsbG8=:')
    assert d["a"] == Item(1)
    assert d["b"] == Item("two")
    assert d["c"] == Item(False)
    assert d["d"] == Item(True)
    assert d["e"].value == "tok/en" and isinstance(d["e"].value, Token)
    assert d["f"] == Item(b"hello")


def test_string_escapes():
    d = parse_dictionary(r'a="say \"hi\" \\ bye"')
    assert d["a"].value == 'say "hi" \\ bye'
    assert serialize_item(d["a"]) == r'"say \"hi\" \\ bye"'


def test_bool_serializes_as_boolean_not_integer():
    assert serialize_item(Item(True)) == "?1"
    assert serialize_item(Item(1)) == "1"


def test_decimal():
    d = parse_dictionary("a=1.50")
    assert d["a"].value == Decimal("1.50")
    assert serialize_item(d["a"]) == "1.5"


@pytest.mark.parametrize(
    "bad",
    [
        'a="unterminated',
        "a=(1 2",
        "A=1",
        "a=1,",
        "a=1 b=2",
        'a="bad\\x"',
        "a=:not base64!:",
        "a=?2",
        "a=1234567890123456",
        "a=(1,2)",
        "a=é",
    ],
)
def test_malformed_input_raises(bad):
    with pytest.raises(SFVError):
        parse_dictionary(bad)


def test_empty_dictionary():
    assert parse_dictionary("") == {}
