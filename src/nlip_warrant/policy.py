"""Type-3 policy: checks a concrete, structured tool call against effective caveats."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from .caveats import Caveats, Money, action_covered
from .errors import Denied
from .reasons import Reason
from .verify import VerifiedWarrant


class ToolCall(BaseModel):
    """The boundary-visible description of a tool invocation (arguments, never reasoning)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(min_length=1, max_length=120)
    amount: Money | None = None
    counterparty: str | None = None
    purpose: str | None = None
    args: Mapping[str, str | int | bool | None] = Field(default_factory=dict)


def check_call(caveats: Caveats, call: ToolCall) -> None:
    """Stateless checks. Raises :class:`Denied` on the first violated caveat."""
    if caveats.actions is not None and not action_covered(call.action, caveats.actions):
        raise Denied(Reason.ACTION_NOT_ALLOWED, f"{call.action!r} is not delegated")
    if caveats.purpose is not None and call.purpose != caveats.purpose:
        raise Denied(Reason.PURPOSE_MISMATCH, f"purpose {call.purpose!r} != {caveats.purpose!r}")
    if caveats.counterparties is not None and call.counterparty not in caveats.counterparties:
        raise Denied(Reason.COUNTERPARTY_NOT_ALLOWED, f"{call.counterparty!r} not allow-listed")
    for cap in (caveats.max_amount, caveats.budget):
        if cap is not None and call.amount is not None and call.amount.currency != cap.currency:
            raise Denied(Reason.CURRENCY_MISMATCH, f"{call.amount.currency} != {cap.currency}")
    if caveats.max_amount is not None:
        if call.amount is None:
            raise Denied(Reason.AMOUNT_EXCEEDED, "amount-capped action called without an amount")
        if call.amount.minor > caveats.max_amount.minor:
            raise Denied(Reason.AMOUNT_EXCEEDED, f"{call.amount} > cap {caveats.max_amount}")


class SpendLedger:
    """Local state recorded from earlier interactions: cumulative spend per delegation block.

    A ``budget`` caveat on block *b* bounds the total spent by *b*'s whole subtree, so every
    block on the chain is charged. Reservation is atomic across the chain.
    """

    def __init__(self) -> None:
        self._spent: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def spent(self, block_id: str) -> int:
        with self._lock:
            return self._spent.get(block_id, 0)

    def reserve(self, verified: VerifiedWarrant, amount: Money | None) -> None:
        if amount is None:
            return
        with self._lock:
            for block in verified.warrant.blocks:
                budget = block.payload.caveats.budget
                if budget is None:
                    continue
                if budget.currency != amount.currency:
                    raise Denied(Reason.CURRENCY_MISMATCH, f"{amount.currency} != budget currency")
                if self._spent[block.block_id] + amount.minor > budget.minor:
                    remaining = budget.minor - self._spent[block.block_id]
                    raise Denied(
                        Reason.BUDGET_EXCEEDED,
                        f"{amount} exceeds remaining budget "
                        f"{Money(currency=budget.currency, minor=remaining)}",
                    )
            for block_id in verified.block_ids:
                self._spent[block_id] += amount.minor
