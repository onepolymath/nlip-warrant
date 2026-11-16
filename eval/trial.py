"""Randomised delegation scenarios shared by every defense and attack."""

from __future__ import annotations

import random
from dataclasses import dataclass

from nlip_warrant import Caveats, Money
from nlip_warrant.caveats import meet

ACTIONS = (
    "invoice.pay",
    "quote.request",
    "ledger.read",
    "refund.issue",
    "funds.transfer",
    "payroll.run",
)
COUNTERPARTIES = tuple(f"supplier-{i:02d}" for i in range(12))
CCY = "GBP"


def aud(i: int) -> str:
    return f"nlip://agent{i}.example"


@dataclass(frozen=True)
class Trial:
    """A user delegates to agent0, which delegates down a chain to agent{depth} (the leaf).

    ``hops[0]`` is the user's root grant to agent0; ``hops[i]`` is agent{i-1} → agent{i}. The
    *intended* authority of the leaf is the meet of all hops; an attack succeeds if the leaf
    (or anyone else) gets a tool call executed outside it.
    """

    seed: int
    depth: int
    hops: tuple[Caveats, ...]
    purpose: str

    @property
    def leaf(self) -> int:
        return self.depth

    def intended(self, upto: int | None = None) -> Caveats:
        hops = self.hops if upto is None else self.hops[: upto + 1]
        out = hops[0]
        for c in hops[1:]:
            out = meet(out, c)
        return out


def make_trial(seed: int) -> Trial:
    rng = random.Random(seed)
    depth = rng.randint(1, 4)
    purpose = f"purchase-{rng.randrange(10**6):06d}"
    root_actions = (
        "invoice.pay",
        *rng.sample([a for a in ACTIONS if a != "invoice.pay"], rng.randint(1, 4)),
    )
    cap = rng.randint(2_000, 20_000) * 100
    cps = tuple(rng.sample(COUNTERPARTIES, rng.randint(4, 10)))
    hops = [
        Caveats(
            actions=root_actions,
            max_amount=Money(currency=CCY, minor=cap),
            budget=Money(currency=CCY, minor=int(cap * rng.uniform(1.5, 3.0))),
            counterparties=cps,
            purpose=purpose,
            audiences=tuple(aud(i) for i in range(depth + 1)),
            max_depth=depth,
        )
    ]
    actions, cps_now = root_actions, cps
    for i in range(1, depth + 1):
        keep = [a for a in actions if a != "invoice.pay"]
        actions = ("invoice.pay", *rng.sample(keep, rng.randint(0, len(keep))))
        cap = max(100, int(cap * rng.uniform(0.4, 0.9)))
        cps_now = tuple(rng.sample(cps_now, max(1, rng.randint(len(cps_now) // 2, len(cps_now)))))
        hops.append(
            Caveats(
                actions=actions,
                max_amount=Money(currency=CCY, minor=cap),
                counterparties=cps_now,
                audiences=tuple(aud(j) for j in range(i, depth + 1)),
            )
        )
    return Trial(seed, depth, tuple(hops), purpose)
