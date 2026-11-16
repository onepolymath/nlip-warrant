import pytest
from nlip_sdk.nlip import NLIP_Factory

from nlip_warrant import (
    Caveats,
    Denied,
    Mode,
    Reason,
    Revocation,
    ToolCall,
    WarrantError,
    WarrantGuard,
    current_authority,
)
from nlip_warrant.nlip import WARRANT_SUBFORMAT, attach_warrant, extract_one

from .conftest import gbp


def _msg(text: str = "pay INV-1"):
    return NLIP_Factory.create_text(text)


def _pay(amount: int = 100, to: str = "acme") -> ToolCall:
    return ToolCall(action="invoice.pay", amount=gbp(amount), counterparty=to, purpose="q4")


def _deny(fn, *args, **kw) -> Reason:
    with pytest.raises(Denied) as info:
        fn(*args, **kw)
    return info.value.reason


def test_delegation_flow_across_three_agents(env):
    alice = env.guard(env.alice, "nlip://alice")
    a, b = env.guard(env.a, "nlip://a"), env.guard(env.b, "nlip://b")

    m1 = alice.present(_msg(), env.root(), audience="nlip://a")
    auth_a = a.ingress(m1)
    assert auth_a.mode is Mode.DELEGATION
    assert auth_a.sender == env.alice.key_id

    m2 = a.delegate(
        _msg(),
        auth_a,
        to=env.b.key_id,
        audience="nlip://b",
        caveats=Caveats(max_amount=gbp(500)),
        ttl=60,
        label="a→b",
    )
    auth_b = b.ingress(m2)
    assert auth_b.verified.caveats.max_amount == gbp(500)
    b.authorize(_pay(400), auth_b)
    assert _deny(b.authorize, _pay(600), auth_b) is Reason.AMOUNT_EXCEEDED

    decisions = [(e.body["boundary"], e.body["decision"]) for e in b.audit.entries]
    assert decisions == [("ingress", "allow"), ("tool", "allow"), ("tool", "deny")]
    assert b.audit.entries[-1].body["sco"] == ["7.2.3", "7.3.2"]
    assert a.audit.entries[-1].body["boundary"] == "egress"


def test_invocation_mode_at_a_service(env):
    a = env.guard(env.a, "nlip://a")
    service = env.guard(env.b, "nlip://b")
    w = env.root()
    auth = service.ingress(a.present(_msg(), w, audience="nlip://b"))
    assert auth.mode is Mode.INVOCATION
    assert auth.sender == env.a.key_id


def test_ingress_denials_are_audited(env):
    a = env.guard(env.a, "nlip://a")
    assert _deny(a.ingress, _msg()) is Reason.MISSING_WARRANT
    assert _deny(a.ingress, attach_warrant(_msg(), env.root().encode())) is Reason.BAD_PROOF
    from nlip_warrant.nlip import attach_proof

    assert _deny(a.ingress, attach_proof(attach_warrant(_msg(), "junk"), "p")) is Reason.MALFORMED
    assert [e.body["decision"] for e in a.audit.entries] == ["deny"] * 3
    assert a.audit.entries[0].body["sco"] == ["7.2.2"]


def test_wrong_audience_is_refused(env):
    alice = env.guard(env.alice, "nlip://alice")
    outsider = env.guard(env.a, "nlip://not-listed")
    m = alice.present(_msg(), env.root(), audience="nlip://not-listed")
    assert _deny(outsider.ingress, m) is Reason.WRONG_AUDIENCE


def test_proof_addressed_elsewhere_is_refused(env):
    alice = env.guard(env.alice, "nlip://alice")
    a = env.guard(env.a, "nlip://a")
    m = alice.present(_msg(), env.root(), audience="nlip://b")
    assert _deny(a.ingress, m) is Reason.WRONG_AUDIENCE


def test_message_tampering_after_signing_is_refused(env):
    alice = env.guard(env.alice, "nlip://alice")
    a = env.guard(env.a, "nlip://a")
    m = alice.present(_msg("pay £10"), env.root(), audience="nlip://a")
    m.content = "pay £10,000"
    assert _deny(a.ingress, m) is Reason.BAD_PROOF


def test_egress_refuses_widening_and_foreign_warrants(env):
    alice = env.guard(env.alice, "nlip://alice")
    a, b = env.guard(env.a, "nlip://a"), env.guard(env.b, "nlip://b")
    auth = a.ingress(alice.present(_msg(), env.root(), audience="nlip://a"))
    with pytest.raises(Denied) as info:
        a.delegate(
            _msg(),
            auth,
            to=env.b.key_id,
            audience="nlip://b",
            caveats=Caveats(max_amount=gbp(99_999)),
            ttl=60,
        )
    assert info.value.reason is Reason.WIDENED
    with pytest.raises(Denied) as info:
        b.delegate(_msg(), auth, to=env.c.key_id, audience="nlip://c", caveats=Caveats(), ttl=60)
    assert info.value.reason is Reason.BROKEN_CHAIN
    assert a.audit.entries[-1].body["decision"] == "deny"


def test_present_requires_a_relationship_to_the_warrant(env):
    with pytest.raises(WarrantError):
        env.guard(env.mallory, "nlip://m").present(_msg(), env.root(), audience="nlip://a")


def test_tool_boundary_rechecks_revocation_at_time_of_use(env):
    alice = env.guard(env.alice, "nlip://alice")
    a = env.guard(env.a, "nlip://a")
    w = env.root()
    auth = a.ingress(alice.present(_msg(), w, audience="nlip://a"))
    a.authorize(_pay(), auth)
    env.revocations.publish(Revocation.create(env.alice, w.root.block_id, at=0))
    assert _deny(a.authorize, _pay(), auth) is Reason.REVOKED


def test_protect_decorator_uses_the_bound_authority(env):
    alice = env.guard(env.alice, "nlip://alice")
    a: WarrantGuard = env.guard(env.a, "nlip://a")
    paid: list[int] = []

    @a.protect(_pay)
    def pay(amount: int = 100, to: str = "acme") -> str:
        paid.append(amount)
        return "ok"

    assert _deny(pay, 10, "acme") is Reason.NO_SESSION_WARRANT
    auth = a.ingress(alice.present(_msg(), env.root(), audience="nlip://a"))
    assert current_authority() is None
    with a.bound(auth):
        assert current_authority() is auth
        assert pay(10, "acme") == "ok"
        assert _deny(pay, 10, "mallory") is Reason.COUNTERPARTY_NOT_ALLOWED
    assert current_authority() is None
    assert paid == [10]


def test_budget_is_tracked_across_messages(env):
    alice = env.guard(env.alice, "nlip://alice")
    a = env.guard(env.a, "nlip://a")
    w = env.root()  # £8,000 budget, £5,000 cap
    for _ in range(2):
        auth = a.ingress(alice.present(_msg(), w, audience="nlip://a"))
        a.authorize(_pay(4000), auth)
    auth = a.ingress(alice.present(_msg(), w, audience="nlip://a"))
    assert _deny(a.authorize, _pay(1), auth) is Reason.BUDGET_EXCEEDED


def test_delegated_message_carries_exactly_one_fresh_warrant(env):
    alice = env.guard(env.alice, "nlip://alice")
    a = env.guard(env.a, "nlip://a")
    auth = a.ingress(alice.present(_msg(), env.root(), audience="nlip://a"))
    out = a.delegate(
        alice.present(_msg(), env.root(), audience="nlip://x"),
        auth,
        to=env.b.key_id,
        audience="nlip://b",
        caveats=Caveats(),
        ttl=60,
    )
    token = extract_one(out, WARRANT_SUBFORMAT)
    assert token is not None
    assert token != env.root().encode()
