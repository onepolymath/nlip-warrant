import json

import pytest

from nlip_warrant import Caveats, Denied, Reason, Revocation, Verifier, Warrant
from nlip_warrant.encoding import b64url_decode, b64url_encode, canonical_json
from nlip_warrant.verify import effective_caveats
from nlip_warrant.warrant import BlockPayload, SignedBlock

from .conftest import ROOT, gbp


def _forge(parent: Warrant, signer, sub, caveats: Caveats, **overrides) -> Warrant:
    now = parent.leaf.payload.iat
    fields = dict(
        jti="f" * 22,
        parent=parent.leaf.block_id,
        iss=signer.key_id,
        sub=sub,
        iat=now,
        nbf=now,
        exp=parent.leaf.payload.exp,
        caveats=caveats,
    )
    fields.update(overrides)
    payload = BlockPayload(**fields)
    return Warrant((*parent.blocks, SignedBlock(payload, signer.sign(payload.signing_input()))))


def _reason(env, warrant, **kw) -> Reason:
    with pytest.raises(Denied) as info:
        env.verifier.verify(warrant, **kw)
    return info.value.reason


def test_valid_chain_verifies(env):
    w = env.chain()
    v = env.verifier.verify(w)
    assert v.holder == env.c.key_id
    assert v.root_id == w.root.block_id
    assert v.caveats == effective_caveats(w)
    assert v.expires_at == w.leaf.payload.exp


def test_untrusted_root(env):
    w = Warrant.issue(env.mallory, env.a.key_id, ROOT, now=env.clock.now(), ttl=60)
    assert _reason(env, w) is Reason.UNTRUSTED_ROOT


def test_root_with_parent_is_rejected(env):
    w = env.root()
    forged = _forge(w, env.alice, env.a.key_id, Caveats())
    root_like = Warrant((forged.leaf,))
    assert _reason(env, root_like) is Reason.BROKEN_CHAIN


def test_tampered_caveats_break_the_signature(env):
    w = env.chain()
    blocks = json.loads(b64url_decode(w.encode()[7:]))
    blocks[2]["p"]["caveats"]["max_amount"]["minor"] = 10**9
    tampered = Warrant.decode("nlipw1." + b64url_encode(canonical_json(blocks)))
    assert _reason(env, tampered) is Reason.BAD_SIGNATURE


def test_splicing_a_block_from_another_chain_is_detected(env):
    other = env.root()
    w = env.chain()
    spliced = Warrant((w.blocks[0], other.blocks[0]))
    assert _reason(env, spliced) is Reason.BROKEN_CHAIN


def test_block_not_issued_by_the_holder(env):
    w = env.root()
    forged = _forge(w, env.mallory, env.mallory.key_id, Caveats())
    assert _reason(env, forged) is Reason.BROKEN_CHAIN


def test_dropping_a_middle_block_is_detected(env):
    w = env.chain()
    assert _reason(env, Warrant((w.blocks[0], w.blocks[2]))) is Reason.BROKEN_CHAIN


def test_holder_signed_widening_is_rejected(env):
    w = env.root()
    forged = _forge(w, env.a, env.b.key_id, Caveats(max_amount=gbp(50_000)))
    assert _reason(env, forged) is Reason.WIDENED


def test_widened_validity_window_is_rejected(env):
    w = env.root(ttl=60)
    later = _forge(w, env.a, env.b.key_id, Caveats(), exp=w.leaf.payload.exp + 1)
    assert _reason(env, later) is Reason.WIDENED
    earlier = _forge(w, env.a, env.b.key_id, Caveats(), nbf=w.leaf.payload.nbf - 1)
    assert _reason(env, earlier) is Reason.WIDENED


def test_depth_caveat_is_enforced(env):
    w = env.root(Caveats(max_depth=0))
    forged = _forge(w, env.a, env.b.key_id, Caveats())
    assert _reason(env, forged) is Reason.DEPTH_EXCEEDED


def test_hard_chain_length_limit(env):
    verifier = Verifier({env.alice.key_id}, env.revocations, env.clock, max_depth=2)
    with pytest.raises(Denied) as info:
        verifier.verify(env.chain())
    assert info.value.reason is Reason.DEPTH_EXCEEDED


def test_validity_window(env):
    w = env.root(ttl=100)
    assert _reason(env, w, at=w.root.payload.nbf - 60) is Reason.NOT_YET_VALID
    assert _reason(env, w, at=w.root.payload.exp + 5) is Reason.EXPIRED
    env.verifier.verify(w, at=w.root.payload.nbf - 5)  # within leeway


def test_nbf_after_exp_is_malformed(env):
    payload = BlockPayload(
        jti="j" * 22, iss=env.alice.key_id, sub=env.a.key_id, iat=0, nbf=10, exp=5
    )
    w = Warrant((SignedBlock(payload, env.alice.sign(payload.signing_input())),))
    assert _reason(env, w) is Reason.MALFORMED


@pytest.mark.parametrize("index", [0, 1, 2])
def test_revoking_any_block_kills_the_subtree(env, index):
    w = env.chain()
    issuer = {0: env.alice, 1: env.a, 2: env.b}[index]
    env.revocations.publish(Revocation.create(issuer, w.block_ids[index], at=0))
    assert _reason(env, w) is Reason.REVOKED


def test_ancestor_may_revoke_a_descendant(env):
    w = env.chain()
    env.revocations.publish(Revocation.create(env.alice, w.block_ids[2], at=0))
    assert _reason(env, w) is Reason.REVOKED


def test_descendant_or_stranger_cannot_revoke_upstream(env):
    w = env.chain()
    env.revocations.publish(Revocation.create(env.mallory, w.block_ids[0], at=0))
    env.revocations.publish(Revocation.create(env.b, w.block_ids[0], at=0))
    env.verifier.verify(w)


def test_check_live_catches_expiry_and_late_revocation(env):
    w = env.chain()
    v = env.verifier.verify(w)
    env.verifier.check_live(v)
    env.revocations.publish(Revocation.create(env.a, w.block_ids[1], at=0))
    with pytest.raises(Denied) as info:
        env.verifier.check_live(v)
    assert info.value.reason is Reason.REVOKED
    with pytest.raises(Denied) as info:
        env.verifier.check_live(v, at=v.expires_at + 10)
    assert info.value.reason is Reason.EXPIRED
