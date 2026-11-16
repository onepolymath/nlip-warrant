import pytest

from nlip_warrant import Caveats, Denied, Money, Reason, SpendLedger, ToolCall

from .conftest import gbp

CAVEATS = Caveats(
    actions=("invoice.pay",), max_amount=gbp(100), counterparties=("acme",), purpose="q4"
)


def call(**kw) -> ToolCall:
    base = dict(action="invoice.pay", amount=gbp(50), counterparty="acme", purpose="q4")
    base.update(kw)
    return ToolCall(**base)


def test_allowed_call_passes():
    from nlip_warrant.policy import check_call

    check_call(CAVEATS, call())
    check_call(Caveats(), ToolCall(action="anything"))


@pytest.mark.parametrize(
    ("kw", "reason"),
    [
        ({"action": "funds.transfer"}, Reason.ACTION_NOT_ALLOWED),
        ({"purpose": "holiday"}, Reason.PURPOSE_MISMATCH),
        ({"purpose": None}, Reason.PURPOSE_MISMATCH),
        ({"counterparty": "mallory"}, Reason.COUNTERPARTY_NOT_ALLOWED),
        ({"amount": gbp(101)}, Reason.AMOUNT_EXCEEDED),
        ({"amount": None}, Reason.AMOUNT_EXCEEDED),
        ({"amount": Money(currency="USD", minor=1)}, Reason.CURRENCY_MISMATCH),
    ],
)
def test_each_caveat_is_enforced(kw, reason):
    from nlip_warrant.policy import check_call

    with pytest.raises(Denied) as info:
        check_call(CAVEATS, call(**kw))
    assert info.value.reason is reason


def test_ledger_charges_every_budgeted_block(env):
    w = env.chain()  # root budget £8,000
    v = env.verifier.verify(w)
    ledger = SpendLedger()
    ledger.reserve(v, None)
    for _ in range(5):
        ledger.reserve(v, gbp(1500))
    assert ledger.spent(w.root.block_id) == 750_000
    with pytest.raises(Denied) as info:
        ledger.reserve(v, gbp(1500))
    assert info.value.reason is Reason.BUDGET_EXCEEDED
    assert ledger.spent(w.root.block_id) == 750_000  # refused reservations are not charged
    with pytest.raises(Denied) as info:
        ledger.reserve(v, Money(currency="EUR", minor=1))
    assert info.value.reason is Reason.CURRENCY_MISMATCH
