"""Caveats: the constraints a warrant places on whoever holds it.

A field left as ``None`` means *inherit* (no additional restriction at this hop). The effective
authority of a chain is the meet (intersection) of every block's caveats, and a block may only
narrow what its parent allowed. :func:`narrowing_violations` reports any attempt to widen.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Money(BaseModel):
    """An amount in integer minor units (pence, cents), so no float ever reaches a signature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    currency: str = Field(pattern=r"^[A-Z]{3}$")
    minor: int = Field(ge=0, le=2**53 - 1)

    def __str__(self) -> str:
        return f"{self.minor / 100:,.2f} {self.currency}"


class Caveats(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    actions: tuple[str, ...] | None = None
    """Tool or capability names. ``"invoice.*"`` covers ``"invoice.pay"``; ``"*"`` covers all."""
    max_amount: Money | None = None
    """Upper bound for any single call."""
    budget: Money | None = None
    """Upper bound on the cumulative amount spent under this block (tracked by the gateway)."""
    counterparties: tuple[str, ...] | None = None
    """Allow-list of payees / recipients."""
    purpose: str | None = None
    """The single purpose this authority was granted for (purpose binding)."""
    audiences: tuple[str, ...] | None = None
    """Agents or services at which this warrant may be received or exercised."""
    max_depth: int | None = Field(default=None, ge=0, le=16)
    """How many further delegations are permitted below this block."""

    @field_validator("actions", "counterparties", "audiences")
    @classmethod
    def _sorted_unique(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        if any(not item for item in value):
            raise ValueError("empty strings are not allowed")
        return tuple(sorted(set(value)))

    def wire(self) -> dict[str, object]:
        """The canonical, signable representation (``None`` fields are omitted)."""
        return self.model_dump(mode="json", exclude_none=True)


def action_covered(action: str, patterns: Iterable[str]) -> bool:
    """Whether ``action`` (itself possibly a wildcard pattern) is covered by any of ``patterns``."""
    for pattern in patterns:
        if pattern in ("*", action):
            return True
        if pattern.endswith(".*") and action.startswith(pattern[:-1]):
            return True
    return False


def _money_le(child: Money, parent: Money) -> bool:
    return child.currency == parent.currency and child.minor <= parent.minor


def narrowing_violations(parent: Caveats, child: Caveats) -> list[str]:
    """Fields on which ``child`` claims more authority than the *effective* ``parent``."""
    out: list[str] = []
    if (
        child.actions is not None
        and parent.actions is not None
        and not all(action_covered(a, parent.actions) for a in child.actions)
    ):
        out.append("actions")
    for name in ("max_amount", "budget"):
        c, p = getattr(child, name), getattr(parent, name)
        if c is not None and p is not None and not _money_le(c, p):
            out.append(name)
    for name in ("counterparties", "audiences"):
        c, p = getattr(child, name), getattr(parent, name)
        if c is not None and p is not None and not set(c) <= set(p):
            out.append(name)
    if child.purpose is not None and parent.purpose is not None and child.purpose != parent.purpose:
        out.append("purpose")
    if parent.max_depth is not None and (
        parent.max_depth < 1
        or (child.max_depth is not None and child.max_depth > parent.max_depth - 1)
    ):
        out.append("max_depth")
    return out


def _meet_list(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if a is None:
        return b
    if b is None:
        return a
    return tuple(sorted(set(a) & set(b)))


def _meet_actions(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if a is None:
        return b
    if b is None:
        return a
    kept = {x for x in b if action_covered(x, a)} | {x for x in a if action_covered(x, b)}
    return tuple(sorted(kept))


def _meet_money(a: Money | None, b: Money | None) -> Money | None:
    if a is None:
        return b
    if b is None:
        return a
    if a.currency != b.currency:
        return Money(currency=a.currency, minor=0)  # incompatible currencies authorise nothing
    return a if a.minor <= b.minor else b


def meet(parent: Caveats, child: Caveats) -> Caveats:
    """Effective caveats after applying ``child`` beneath ``parent``."""
    if parent.max_depth is None:
        depth = child.max_depth
    else:
        inherited = max(parent.max_depth - 1, 0)
        depth = inherited if child.max_depth is None else min(child.max_depth, inherited)
    purpose = parent.purpose if parent.purpose is not None else child.purpose
    return Caveats(
        actions=_meet_actions(parent.actions, child.actions),
        max_amount=_meet_money(parent.max_amount, child.max_amount),
        budget=_meet_money(parent.budget, child.budget),
        counterparties=_meet_list(parent.counterparties, child.counterparties),
        purpose=purpose,
        audiences=_meet_list(parent.audiences, child.audiences),
        max_depth=depth,
    )
