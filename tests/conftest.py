from __future__ import annotations

import hashlib
from dataclasses import dataclass

import pytest

from nlip_warrant import (
    Caveats,
    FrozenClock,
    KeyPair,
    MemoryRevocationStore,
    Money,
    Verifier,
    Warrant,
    WarrantGuard,
)


def key(name: str) -> KeyPair:
    return KeyPair.from_seed(hashlib.sha256(name.encode()).digest(), name)


def gbp(pounds: int) -> Money:
    return Money(currency="GBP", minor=pounds * 100)


ROOT = Caveats(
    actions=("invoice.*", "ledger.read"),
    max_amount=gbp(5000),
    budget=gbp(8000),
    counterparties=("acme", "globex", "initech"),
    purpose="q4",
    audiences=("nlip://a", "nlip://b", "nlip://c"),
    max_depth=3,
)


@dataclass
class Env:
    clock: FrozenClock
    revocations: MemoryRevocationStore
    verifier: Verifier
    alice: KeyPair
    a: KeyPair
    b: KeyPair
    c: KeyPair
    mallory: KeyPair

    def root(self, caveats: Caveats = ROOT, ttl: int = 3600) -> Warrant:
        return Warrant.issue(
            self.alice, self.a.key_id, caveats, now=self.clock.now(), ttl=ttl, label="alice→a"
        )

    def chain(self) -> Warrant:
        """alice → a → b → c, narrowing at every hop."""
        now = self.clock.now()
        w = self.root().attenuate(
            self.a,
            self.b.key_id,
            Caveats(
                actions=("invoice.pay",), max_amount=gbp(2000), counterparties=("acme", "globex")
            ),
            now=now,
            ttl=1800,
            label="a→b",
        )
        return w.attenuate(
            self.b,
            self.c.key_id,
            Caveats(max_amount=gbp(1500), counterparties=("acme",), audiences=("nlip://c",)),
            now=now,
            ttl=600,
            label="b→c",
        )

    def guard(self, kp: KeyPair, audience: str) -> WarrantGuard:
        return WarrantGuard(kp, audience, self.verifier)


@pytest.fixture
def env() -> Env:
    clock = FrozenClock()
    revocations = MemoryRevocationStore()
    alice = key("alice")
    return Env(
        clock,
        revocations,
        Verifier({alice.key_id}, revocations, clock),
        alice,
        key("a"),
        key("b"),
        key("c"),
        key("mallory"),
    )
