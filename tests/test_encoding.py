import pytest

from nlip_warrant.encoding import b64url_decode, b64url_encode, canonical_json, digest
from nlip_warrant.errors import EncodingError


def test_canonical_json_sorts_keys_and_strips_whitespace():
    assert (
        canonical_json({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()
    )


def test_canonical_json_is_stable_across_key_order():
    assert digest({"x": 1, "y": {"b": 2, "a": 1}}) == digest({"y": {"a": 1, "b": 2}, "x": 1})


@pytest.mark.parametrize("bad", [1.5, {"a": 0.1}, [2**53], {1: "x"}, {"a": object()}])
def test_canonical_json_rejects_ambiguous_values(bad):
    with pytest.raises(EncodingError):
        canonical_json(bad)


def test_b64url_roundtrip():
    data = bytes(range(256))
    text = b64url_encode(data)
    assert "=" not in text
    assert b64url_decode(text) == data


@pytest.mark.parametrize("bad", ["", "a", "ab+c", "ab/c", "abc="])
def test_b64url_rejects_non_url_alphabet(bad):
    with pytest.raises(EncodingError):
        b64url_decode(bad)
