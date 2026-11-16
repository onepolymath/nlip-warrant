import pytest
from pydantic import ValidationError

from nlip_warrant.caveats import Caveats, Money, action_covered, meet, narrowing_violations

from .conftest import gbp


@pytest.mark.parametrize(
    ("action", "patterns", "ok"),
    [
        ("invoice.pay", ["invoice.pay"], True),
        ("invoice.pay", ["invoice.*"], True),
        ("invoice.*", ["invoice.*"], True),
        ("invoice.pay", ["*"], True),
        ("invoicex.pay", ["invoice.*"], False),
        ("funds.transfer", ["invoice.*", "ledger.read"], False),
    ],
)
def test_action_covered(action, patterns, ok):
    assert action_covered(action, patterns) is ok


def test_lists_are_normalised():
    c = Caveats(actions=("b", "a", "a"))
    assert c.actions == ("a", "b")
    with pytest.raises(ValidationError):
        Caveats(counterparties=("",))
    with pytest.raises(ValidationError):
        Caveats(unknown=1)  # type: ignore[call-arg]


def test_money_validation_and_str():
    assert str(Money(currency="GBP", minor=123456)) == "1,234.56 GBP"
    with pytest.raises(ValidationError):
        Money(currency="gbp", minor=1)
    with pytest.raises(ValidationError):
        Money(currency="GBP", minor=-1)


def test_wire_omits_unset_fields():
    assert Caveats(purpose="p").wire() == {"purpose": "p"}


def test_narrowing_accepts_subsets_and_inheritance():
    parent = Caveats(
        actions=("invoice.*",),
        max_amount=gbp(10),
        counterparties=("a", "b"),
        purpose="p",
        audiences=("x",),
        max_depth=2,
        budget=gbp(20),
    )
    child = Caveats(
        actions=("invoice.pay",),
        max_amount=gbp(5),
        counterparties=("a",),
        purpose="p",
        audiences=("x",),
        max_depth=1,
        budget=gbp(20),
    )
    assert narrowing_violations(parent, child) == []
    assert narrowing_violations(parent, Caveats()) == []
    assert narrowing_violations(Caveats(), child) == []


@pytest.mark.parametrize(
    ("child", "field"),
    [
        (Caveats(actions=("funds.transfer",)), "actions"),
        (Caveats(max_amount=gbp(11)), "max_amount"),
        (Caveats(max_amount=Money(currency="EUR", minor=1)), "max_amount"),
        (Caveats(budget=gbp(21)), "budget"),
        (Caveats(counterparties=("a", "z")), "counterparties"),
        (Caveats(audiences=("y",)), "audiences"),
        (Caveats(purpose="other"), "purpose"),
        (Caveats(max_depth=2), "max_depth"),
    ],
)
def test_narrowing_flags_each_widened_field(child, field):
    parent = Caveats(
        actions=("invoice.*",),
        max_amount=gbp(10),
        budget=gbp(20),
        counterparties=("a", "b"),
        purpose="p",
        audiences=("x",),
        max_depth=2,
    )
    assert narrowing_violations(parent, child) == [field]


def test_exhausted_depth_forbids_any_child():
    assert narrowing_violations(Caveats(max_depth=0), Caveats()) == ["max_depth"]


def test_meet_intersects_and_inherits():
    parent = Caveats(
        actions=("invoice.*", "ledger.read"),
        max_amount=gbp(10),
        counterparties=("a", "b"),
        max_depth=3,
    )
    child = Caveats(
        actions=("invoice.pay",),
        max_amount=gbp(20),
        counterparties=("b", "c"),
        purpose="p",
        audiences=("x",),
    )
    m = meet(parent, child)
    assert m.actions == ("invoice.pay",)
    assert m.max_amount == gbp(10)
    assert m.counterparties == ("b",)
    assert m.purpose == "p"
    assert m.audiences == ("x",)
    assert m.max_depth == 2
    assert meet(Caveats(max_depth=3), Caveats(max_depth=1)).max_depth == 1
    assert meet(Caveats(), Caveats(max_depth=1)).max_depth == 1
    assert meet(Caveats(actions=("a.b",)), Caveats(actions=("a.*",))).actions == ("a.b",)


def test_meet_of_incompatible_currencies_authorises_nothing():
    m = meet(Caveats(max_amount=gbp(10)), Caveats(max_amount=Money(currency="EUR", minor=5)))
    assert m.max_amount == Money(currency="GBP", minor=0)
