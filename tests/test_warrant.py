import json

import pytest

from nlip_warrant import Caveats, EncodingError, Warrant, WarrantError
from nlip_warrant.encoding import b64url_encode, canonical_json
from nlip_warrant.warrant import MAX_WIRE_BYTES

from .conftest import gbp


def test_issue_and_roundtrip(env):
    w = env.chain()
    assert w.depth == 3
    assert w.holder == env.c.key_id
    again = Warrant.decode(w.encode())
    assert again.block_ids == w.block_ids
    assert all(b.signature_valid() for b in again.blocks)
    assert again.blocks[1].payload.parent == again.blocks[0].block_id


def test_effective_caveats_are_the_meet(env):
    eff = env.chain().effective_caveats()
    assert eff.actions == ("invoice.pay",)
    assert eff.max_amount == gbp(1500)
    assert eff.counterparties == ("acme",)
    assert eff.purpose == "q4"
    assert eff.max_depth == 1


def test_child_expiry_is_capped_by_parent(env):
    w = env.root(ttl=100).attenuate(env.a, env.b.key_id, Caveats(), now=env.clock.now(), ttl=10_000)
    assert w.leaf.payload.exp == w.root.payload.exp


def test_only_the_holder_can_attenuate(env):
    with pytest.raises(WarrantError, match="current holder"):
        env.root().attenuate(env.mallory, env.mallory.key_id, Caveats(), now=0, ttl=10)


def test_honest_attenuation_refuses_to_widen(env):
    with pytest.raises(WarrantError, match="max_amount"):
        env.root().attenuate(env.a, env.b.key_id, Caveats(max_amount=gbp(9999)), now=0, ttl=10)


@pytest.mark.parametrize("ttl", [0, -5])
def test_ttl_must_be_positive(env, ttl):
    with pytest.raises(WarrantError):
        env.root(ttl=ttl)
    with pytest.raises(WarrantError):
        env.root().attenuate(env.a, env.b.key_id, Caveats(), now=env.clock.now(), ttl=ttl)


def _wrap(obj: object) -> str:
    return "nlipw1." + b64url_encode(canonical_json(obj))


@pytest.mark.parametrize(
    "token",
    [
        "x" * (MAX_WIRE_BYTES + 1),
        "jwt.abc",
        "nlipw1.***",
        _wrap([]),
        _wrap({"p": {}, "s": ""}),
        _wrap([{"p": {}}]),
        _wrap([{"p": {}, "s": 5}]),
        _wrap([{"p": {"v": 1}, "s": "sig"}]),
        "nlipw1." + b64url_encode(b"not json"),
    ],
)
def test_decode_rejects_malformed_tokens(token):
    with pytest.raises(EncodingError):
        Warrant.decode(token)


def test_decode_rejects_unknown_payload_fields(env):
    blocks = json.loads(json.dumps([b.wire() for b in env.root().blocks]))
    blocks[0]["p"]["admin"] = True
    with pytest.raises(EncodingError):
        Warrant.decode(_wrap(blocks))
