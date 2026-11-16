"""The attack suite. Each attack returns ``True`` iff the adversary achieved its goal."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass

from eval.defenses import Defense
from eval.trial import ACTIONS, CCY, COUNTERPARTIES, Trial
from nlip_warrant import Caveats, Denied, Money, ToolCall

MALLORY = "mallory-ltd"


def _call(trial: Trial, rng: random.Random, **override: object) -> ToolCall:
    """A call inside the leaf's intended authority, optionally perturbed."""
    leaf = trial.intended()
    assert leaf.actions and leaf.counterparties and leaf.max_amount
    base: dict[str, object] = {
        "action": rng.choice(leaf.actions),
        "amount": Money(currency=CCY, minor=rng.randint(1, max(1, leaf.max_amount.minor // 4))),
        "counterparty": rng.choice(leaf.counterparties),
        "purpose": trial.purpose,
    }
    base.update(override)
    return ToolCall.model_validate(base)


def _executes(d: Defense, receiver: int, env: dict[str, object], call: ToolCall) -> bool:
    try:
        session = d.accept(receiver, env)
        d.tool(receiver, session, call)
    except Denied:
        return False
    return True


def _wider(trial: Trial) -> Caveats:
    root = trial.hops[0]
    assert root.max_amount
    return Caveats(
        actions=(*ACTIONS,),
        counterparties=(*COUNTERPARTIES, MALLORY),
        max_amount=Money(currency=CCY, minor=root.max_amount.minor * 10),
    )


def _escalated_call(trial: Trial, rng: random.Random) -> ToolCall:
    """A call outside the leaf's intended authority in one randomly chosen dimension."""
    leaf, root = trial.intended(), trial.hops[0]
    assert leaf.actions and leaf.max_amount and root.max_amount
    dim = rng.choice(["action", "amount", "counterparty"])
    if dim == "action":
        return _call(trial, rng, action=rng.choice([a for a in ACTIONS if a not in leaf.actions]))
    if dim == "amount":
        return _call(trial, rng, amount=Money(currency=CCY, minor=root.max_amount.minor * 5))
    return _call(trial, rng, counterparty=MALLORY)


# ----------------------------------------------------------------------------- attacks
def action_escalation(d: Defense, t: Trial, rng: random.Random) -> bool:
    """A prompt-injected leaf calls a tool that was never delegated to it."""
    leaf = t.intended()
    assert leaf.actions
    outside = [a for a in ACTIONS if a not in leaf.actions]
    return _executes(d, t.leaf, d.leaf_envelope(), _call(t, rng, action=rng.choice(outside)))


def amount_escalation(d: Defense, t: Trial, rng: random.Random) -> bool:
    """The leaf pays more than its hop allows (but no more than the user's root cap)."""
    leaf, root = t.intended(), t.hops[0]
    assert leaf.max_amount and root.max_amount
    amount = rng.randint(leaf.max_amount.minor + 1, root.max_amount.minor)
    return _executes(
        d, t.leaf, d.leaf_envelope(), _call(t, rng, amount=Money(currency=CCY, minor=amount))
    )


def counterparty_substitution(d: Defense, t: Trial, rng: random.Random) -> bool:
    """An injected invoice redirects payment to a payee outside the delegated allow-list."""
    leaf = t.intended()
    assert leaf.counterparties
    outside = [c for c in (*COUNTERPARTIES, MALLORY) if c not in leaf.counterparties]
    return _executes(d, t.leaf, d.leaf_envelope(), _call(t, rng, counterparty=rng.choice(outside)))


def purpose_misuse(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Authority granted for one purchase is used for an unrelated one (confused deputy)."""
    return _executes(d, t.leaf, d.leaf_envelope(), _call(t, rng, purpose="unrelated-purchase"))


def budget_exhaustion(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Many individually-allowed payments that together exceed the user's total budget."""
    leaf, root = t.intended(), t.hops[0]
    assert leaf.max_amount and root.budget
    spent = 0
    while True:
        call = _call(t, rng, amount=leaf.max_amount)
        if spent + leaf.max_amount.minor > root.budget.minor:
            return _executes(d, t.leaf, d.leaf_envelope(), call)
        if not _executes(d, t.leaf, d.leaf_envelope(), call):
            return False  # a legitimate in-budget payment was refused: not an attack success
        spent += leaf.max_amount.minor


def replay(d: Defense, t: Trial, rng: random.Random) -> bool:
    """A captured message is re-sent verbatim to execute the same payment twice."""
    env, call = d.leaf_envelope(), _call(t, rng)
    if not _executes(d, t.leaf, env, call):
        return False
    return _executes(d, t.leaf, env, call)


def stolen_credential(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Mallory lifts a credential off the wire and uses it on a request of her own."""
    return _executes(d, t.leaf, d.steal(d.leaf_envelope()), _call(t, rng))


def credential_tampering(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Mallory edits the captured credential to widen it, then uses the widened authority."""
    return _executes(d, t.leaf, d.tamper(d.leaf_envelope(), _wider(t)), _escalated_call(t, rng))


def over_delegation(d: Defense, t: Trial, rng: random.Random) -> bool:
    """A compromised intermediary grants the leaf more authority than it holds itself."""
    held, root = t.intended(upto=t.leaf - 1), t.hops[0]
    assert held.actions and root.max_amount
    if rng.random() < 0.5:
        call = _call(t, rng, amount=Money(currency=CCY, minor=root.max_amount.minor * 5))
    else:
        call = _call(
            t,
            rng,
            action=rng.choice([a for a in ACTIONS if a not in held.actions] or ["admin.root"]),
        )
    return _executes(d, t.leaf, d.over_delegate(_wider(t)), call)


def outsider_forgery(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Mallory, holding nothing, mints a credential for the leaf."""
    return _executes(d, t.leaf, d.outsider_forge(_wider(t)), _call(t, rng))


def use_after_revocation(d: Defense, t: Trial, rng: random.Random) -> bool:
    """The user revokes the root grant; a downstream agent keeps acting on it."""
    env = d.leaf_envelope()
    d.revoke_root()
    return _executes(d, t.leaf, env, _call(t, rng))


def use_after_expiry(d: Defense, t: Trial, rng: random.Random) -> bool:
    """A credential is used two hours after a one-hour grant ended."""
    env = d.leaf_envelope()
    d.clock.advance(7200)
    return _executes(d, t.leaf, env, _call(t, rng))


def audience_redirection(d: Defense, t: Trial, rng: random.Random) -> bool:
    """A message addressed to the leaf is delivered to a different agent on the chain."""
    other = rng.randrange(t.leaf)
    return _executes(d, other, d.leaf_envelope(), _call(t, rng))


def revocation_dos(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Mallory 'revokes' the user's grant; success means a legitimate request is now refused."""
    d.forged_revocation()
    return not _executes(d, t.leaf, d.leaf_envelope(), _call(t, rng))


def in_bound_misuse(d: Defense, t: Trial, rng: random.Random) -> bool:
    """Residual risk: a hijacked leaf misuses authority it legitimately holds."""
    return _executes(d, t.leaf, d.leaf_envelope(), _call(t, rng))


@dataclass(frozen=True)
class Attack:
    key: str
    title: str
    group: str  # where it should be stopped
    fn: Callable[[Defense, Trial, random.Random], bool]
    residual: bool = False


ATTACKS: tuple[Attack, ...] = (
    Attack("A1", "Action escalation (prompt injection)", "tool", action_escalation),
    Attack("A2", "Amount escalation", "tool", amount_escalation),
    Attack("A3", "Counterparty substitution", "tool", counterparty_substitution),
    Attack("A4", "Purpose misuse (confused deputy)", "tool", purpose_misuse),
    Attack("A5", "Budget exhaustion", "tool", budget_exhaustion),
    Attack("A6", "Replay", "ingress", replay),
    Attack("A7", "Stolen credential", "ingress", stolen_credential),
    Attack("A8", "Credential tampering", "ingress", credential_tampering),
    Attack("A9", "Over-delegation by intermediary", "ingress", over_delegation),
    Attack("A10", "Outsider forgery", "ingress", outsider_forgery),
    Attack("A11", "Use after revocation", "ingress", use_after_revocation),
    Attack("A12", "Use after expiry", "ingress", use_after_expiry),
    Attack("A13", "Audience redirection", "ingress", audience_redirection),
    Attack("A14", "Forged revocation (DoS)", "ingress", revocation_dos),
    Attack("R1", "In-bound misuse (residual)", "—", in_bound_misuse, residual=True),
)
