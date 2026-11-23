"""The strict reader refuses every input two readers could read differently, and canonical bytes are one per value."""

import pytest

from signet.strict import FormatError, canonical, loads


@pytest.mark.parametrize("text, why", [
    ('{"a": 1, "a": 2}', "twice"),
    ('{"a": 1.5}', "fractional"),
    ('{"a": 1e3}', "fractional"),
    ('{"a": NaN}', "NaN"),
    ('{"a": Infinity}', "Infinity"),
    ('{"a": 9007199254740992}', "outside"),
    ('[1, 2]', "top level"),
    ('{"a": ', "not valid JSON"),
])
def test_refusals_name_why(text, why):
    with pytest.raises(FormatError, match=why):
        loads(text)


def test_duplicate_key_spelled_with_an_escape_is_refused():
    with pytest.raises(FormatError, match="twice"):
        loads('{"a": 1, "\\u0061": 2}')


def test_bytes_that_are_not_utf8_are_refused():
    with pytest.raises(FormatError, match="UTF-8"):
        loads(b'{"a": "\xff"}')


def test_size_limit():
    with pytest.raises(FormatError, match="limit"):
        loads(b'{"a": "' + b"x" * 100 + b'"}', max_bytes=50)


def test_depth_limit():
    deep = '{"a": ' * 20 + "1" + "}" * 20
    with pytest.raises(FormatError, match="deeper"):
        loads(deep, max_depth=16)


def test_a_plain_object_reads():
    assert loads('{"b": [1, true, null, "x"], "a": {}}') == {"a": {}, "b": [1, True, None, "x"]}


def test_canonical_is_sorted_compact_ascii():
    assert canonical({"b": "é", "a": [1, None]}) == b'{"a":[1,null],"b":"\\u00e9"}'


def test_canonical_refuses_a_lone_surrogate():
    with pytest.raises(FormatError, match="surrogate"):
        canonical({"a": "\ud83d"})


def test_canonical_refuses_a_subclass_and_a_float():
    class S(str):
        pass
    with pytest.raises(FormatError):
        canonical({"a": S("x")})
    with pytest.raises(FormatError):
        canonical({"a": 1.0})
