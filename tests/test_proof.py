import pytest

from nlip_warrant import Denied, Reason, ReplayCache
from nlip_warrant.encoding import b64url_encode, canonical_json
from nlip_warrant.proof import make_proof, parse_proof, verify_proof

from .conftest import key

WID = "11" * 32
MSG = "22" * 32


def _verify(token, signer, *, replay=None, now=1000, **kw):
    args = dict(
        expected_signer=signer.key_id,
        expected_wid=WID,
        audience="nlip://b",
        msg_digest=MSG,
        now=now,
        window=60,
        replay=ReplayCache(60) if replay is None else replay,
    )
    args.update(kw)
    return verify_proof(token, **args)


def test_valid_proof():
    a = key("a")
    token = make_proof(a, wid=WID, aud="nlip://b", msg_digest=MSG, now=1000)
    payload = _verify(token, a)
    assert payload.aud == "nlip://b"
    assert parse_proof(token)[0] == payload


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"expected_wid": "33" * 32}, Reason.BAD_PROOF),
        ({"audience": "nlip://elsewhere"}, Reason.WRONG_AUDIENCE),
        ({"msg_digest": "44" * 32}, Reason.BAD_PROOF),
        ({"now": 1061}, Reason.STALE_PROOF),
        ({"now": 939}, Reason.STALE_PROOF),
    ],
)
def test_binding_violations(overrides, reason):
    a = key("a")
    token = make_proof(a, wid=WID, aud="nlip://b", msg_digest=MSG, now=1000)
    with pytest.raises(Denied) as info:
        _verify(token, a, **overrides)
    assert info.value.reason is reason


def test_wrong_signer():
    token = make_proof(key("mallory"), wid=WID, aud="nlip://b", msg_digest=MSG, now=1000)
    with pytest.raises(Denied) as info:
        _verify(token, key("a"))
    assert info.value.reason is Reason.BAD_PROOF


def test_replay_is_rejected():
    a = key("a")
    cache = ReplayCache(60)
    token = make_proof(a, wid=WID, aud="nlip://b", msg_digest=MSG, now=1000)
    _verify(token, a, replay=cache)
    with pytest.raises(Denied) as info:
        _verify(token, a, replay=cache, now=1001)
    assert info.value.reason is Reason.REPLAYED


@pytest.mark.parametrize(
    "token",
    [
        "x",
        "nlipp1." + "A" * 3000,
        "nlipp1.!!",
        "nlipp1." + b64url_encode(canonical_json([1])),
        "nlipp1." + b64url_encode(canonical_json({"p": {}, "s": "x"})),
        "nlipp1." + b64url_encode(canonical_json({"p": {}, "s": 1})),
    ],
)
def test_malformed_proofs(token):
    with pytest.raises(Denied) as info:
        parse_proof(token)
    assert info.value.reason is Reason.BAD_PROOF


def test_replay_cache_evicts_old_entries_and_fails_closed_when_full():
    cache = ReplayCache(window=10, capacity=2)
    assert cache.check_and_add("w", "n1", ts=0, now=0)
    assert cache.check_and_add("w", "n2", ts=0, now=0)
    assert not cache.check_and_add("w", "n3", ts=0, now=0)  # full: refuse rather than forget
    assert cache.check_and_add("w", "n3", ts=100, now=100)  # old ones aged out
    assert len(cache) == 1
