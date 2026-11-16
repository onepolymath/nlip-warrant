import pytest
from nlip_sdk.nlip import NLIP_Factory, NLIP_SubMessage

from nlip_warrant import Denied, Reason
from nlip_warrant.nlip import (
    PROOF_SUBFORMAT,
    WARRANT_SUBFORMAT,
    attach_proof,
    attach_warrant,
    echo_tokens,
    extract_one,
    message_digest,
    structured,
)


def msg():
    m = NLIP_Factory.create_text("pay it")
    m.add_json({"id": "INV-1", "amount": 1.5}, label="invoice")
    return m


def test_attach_and_extract_replace_existing_tokens():
    m = attach_warrant(msg(), "w1")
    attach_warrant(m, "w2")
    attach_proof(m, "p1")
    assert extract_one(m, WARRANT_SUBFORMAT) == "w2"
    assert extract_one(m, PROOF_SUBFORMAT) == "p1"
    assert extract_one(msg(), WARRANT_SUBFORMAT) is None


def test_ambiguous_or_non_string_tokens_are_refused():
    m = msg()
    m.add_submessage(NLIP_SubMessage(format="token", subformat="warrant", content="a"))
    m.add_submessage(NLIP_SubMessage(format="token", subformat="WARRANT", content="b"))
    with pytest.raises(Denied) as info:
        extract_one(m, WARRANT_SUBFORMAT)
    assert info.value.reason is Reason.MALFORMED
    m2 = msg()
    m2.add_submessage(NLIP_SubMessage(format="token", subformat="warrant", content={"x": 1}))
    with pytest.raises(Denied):
        extract_one(m2, WARRANT_SUBFORMAT)


def test_digest_covers_everything_but_the_proof():
    m = attach_warrant(msg(), "w")
    d = message_digest(m)
    assert message_digest(attach_proof(m, "p")) == d
    m.submessages[0].content["amount"] = 2.5
    assert message_digest(m) != d


def test_structured_lookup():
    assert structured(msg(), "invoice") == {"id": "INV-1", "amount": 1.5}
    assert structured(msg(), "missing") is None


def test_echo_tokens_returns_peer_tokens_once():
    req = attach_proof(attach_warrant(msg(), "w"), "p")
    req.add_conversation_token("conv-1")
    rsp = NLIP_Factory.create_text("ok")
    echo_tokens(req, rsp)
    echo_tokens(req, rsp)
    tokens = [(s.subformat, s.content) for s in rsp.submessages if s.format.value == "token"]
    assert sorted(tokens) == [("conversation", "conv-1"), ("warrant", "w"), ("warrant_proof", "p")]
