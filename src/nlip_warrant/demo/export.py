"""Serialise a finished scenario into the JSON snapshot rendered by the web dashboard.

Everything in the snapshot is the real artefact (signed blocks, revocations, audit entries,
checkpoints) so the dashboard can re-verify signatures and hash chains in the browser.
"""

from __future__ import annotations

from typing import Any

from nlip_warrant.audit import verify_entries
from nlip_warrant.demo.scenario import AUD, World
from nlip_warrant.errors import Denied
from nlip_warrant.nlip import WARRANT_SUBFORMAT
from nlip_warrant.verify import Verifier
from nlip_warrant.warrant import Warrant

ROLES = {
    "alice": ("Alice", "User · root authority"),
    "concierge": ("Concierge", "Planner agent"),
    "procurement": ("Procurement", "Router agent"),
    "payments": ("Payments", "Tool-executing agent"),
    "mallory": ("Mallory", "Attacker"),
}


def _warrant_json(warrant: Warrant, world: World, verifier: Verifier) -> dict[str, Any]:
    try:
        verifier.verify(warrant)
        status, reason = "active", None
    except Denied as denied:
        status, reason = denied.reason.value, denied.detail
    return {
        "leaf": warrant.leaf.block_id,
        "root": warrant.root.block_id,
        "status": status,
        "status_detail": reason,
        "effective": warrant.effective_caveats().wire(),
        "token_bytes": len(warrant.encode()),
        "blocks": [
            {"id": b.block_id, "payload": b.payload.wire(), "sig": b.signature}
            for b in warrant.blocks
        ],
    }


def snapshot(world: World, results: dict[str, Any] | None = None) -> dict[str, Any]:
    names = {kp.key_id: name for name, kp in world.keys.items()}
    verifier = Verifier({world.keys["alice"].key_id}, world.revocations, world.clock)

    seen: dict[str, Warrant] = {}
    for root in world.roots:
        seen.setdefault(root.leaf.block_id, root)
    for captured in world.network.tap:
        for sub in captured.body.get("submessages", []):
            if sub.get("format") == "token" and sub.get("subformat") == WARRANT_SUBFORMAT:
                try:
                    w = Warrant.decode(str(sub["content"]))
                except Exception:  # noqa: S112 - forged tokens are skipped on purpose
                    continue
                if all(b.signature_valid() for b in w.blocks):
                    seen.setdefault(w.leaf.block_id, w)

    revocations = []
    for rev in world.revocations.log:
        chain_issuers = {
            b.payload.iss
            for w in seen.values()
            for i, b in enumerate(w.blocks)
            if rev.block_id in w.block_ids[: i + 1]
        }
        revocations.append(
            {
                **rev.model_dump(mode="json"),
                "by_name": names.get(rev.by, "?"),
                "honoured": rev.by in chain_issuers,
            }
        )

    audit = {}
    for name, log in world.audits.items():
        entries = [e.to_json() for e in log.entries]
        cp = world.checkpoints.get(name)
        audit[name] = {
            "entries": entries,
            "checkpoint": cp.to_json() if cp else None,
            "verified": verify_entries(entries, cp).ok,
        }

    return {
        "schema": "nlip-warrant/demo-snapshot@1",
        "clock": {"start": world.start, "end": world.clock.now()},
        "agents": [
            {
                "id": name,
                "name": ROLES[name][0],
                "role": ROLES[name][1],
                "key": kp.key_id,
                "audience": AUD.get(name),
            }
            for name, kp in world.keys.items()
        ],
        "warrants": [_warrant_json(w, world, verifier) for w in seen.values()],
        "revocations": revocations,
        "events": [
            {
                "step": e.step,
                "kind": e.kind,
                "title": e.title,
                "narrative": e.narrative,
                "expect": e.expect,
                "outcome": e.outcome,
                "reason": e.reason,
                "blocked_at": e.blocked_at,
                "results": e.results,
                "audit_refs": e.audit_refs,
                "t": e.t,
            }
            for e in world.events
        ],
        "bank": world.bank.transfers,
        "audit": audit,
        "results": results,
    }
