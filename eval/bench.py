"""Micro- and end-to-end latency of the Security Extension, plus wire overhead.

uv run python -m eval.bench --iterations 2000
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import platform
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from nlip_sdk.nlip import NLIP_Factory, NLIP_Message
from nlip_server.server import NLIP_Application, NLIP_Session, setup_server

from nlip_warrant import (
    Caveats,
    FrozenClock,
    KeyPair,
    Money,
    SystemClock,
    ToolCall,
    Verifier,
    Warrant,
    WarrantGuard,
)
from nlip_warrant.encoding import b64url_encode, canonical_json
from nlip_warrant.server import GuardedApplication

RESULTS = Path(__file__).parent / "results"
GBP = "GBP"
CAVEATS = Caveats(
    actions=("invoice.pay", "quote.request"),
    max_amount=Money(currency=GBP, minor=500_000),
    counterparties=("acme", "globex"),
    purpose="bench",
)


def _stats(samples_ns: list[int]) -> dict[str, float]:
    us = sorted(s / 1000 for s in samples_ns)
    return {
        "median_us": round(statistics.median(us), 1),
        "p95_us": round(us[int(0.95 * (len(us) - 1))], 1),
        "mean_us": round(statistics.fmean(us), 1),
        "n": len(us),
    }


def _time(fn: Callable[[], object], n: int) -> dict[str, float]:
    for _ in range(min(50, n)):
        fn()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return _stats(samples)


def chain(depth: int, clock: FrozenClock) -> tuple[KeyPair, list[KeyPair], Warrant]:
    user = KeyPair.generate("user")
    agents = [KeyPair.generate(f"a{i}") for i in range(depth)]
    w = Warrant.issue(user, agents[0].key_id, CAVEATS, now=clock.now(), ttl=3600)
    for i in range(1, depth):
        w = w.attenuate(agents[i - 1], agents[i].key_id, Caveats(), now=clock.now(), ttl=3600)
    return user, agents, w


def micro(iterations: int, max_depth: int) -> list[dict[str, Any]]:
    rows = []
    for depth in range(1, max_depth + 1):
        clock = FrozenClock()
        user, agents, w = chain(depth, clock)
        verifier = Verifier({user.key_id}, clock=clock, max_depth=max_depth)
        token = w.encode()
        sender = agents[-2] if depth > 1 else user
        receiver = WarrantGuard(agents[-1], "nlip://bench", verifier)
        presenter = WarrantGuard(sender, "nlip://sender", verifier)
        msgs = []
        for _ in range(iterations + 60):
            m = NLIP_Factory.create_text("pay invoice INV-1 please")
            m.add_json({"id": "INV-1", "amount": 1000}, label="invoice")
            msgs.append(presenter.present(m, w, audience="nlip://bench"))
        it = iter(msgs)
        auth = receiver.ingress(next(it))
        call = ToolCall(
            action="invoice.pay",
            amount=Money(currency=GBP, minor=1000),
            counterparty="acme",
            purpose="bench",
        )
        proof_bytes = len(
            next(s.content for s in msgs[0].submessages or [] if s.subformat == "warrant_proof")
        )
        rows.append(
            {
                "depth": depth,
                "warrant_bytes": len(token),
                "proof_bytes": proof_bytes,
                "decode_verify": _time(lambda: verifier.verify(Warrant.decode(token)), iterations),
                "ingress": _time(lambda: receiver.ingress(next(it)), iterations),
                "tool": _time(lambda: receiver.authorize(call, auth), iterations),
            }
        )
    return rows


def bearer_baseline(iterations: int) -> dict[str, float]:
    key = os.urandom(32)
    body = b64url_encode(canonical_json({"sub": "a0", "scope": ["invoice.pay"], "exp": 2**31}))
    mac = hmac.new(key, body.encode(), hashlib.sha256).digest()

    def check() -> None:
        good = hmac.new(key, body.encode(), hashlib.sha256).digest()
        assert hmac.compare_digest(mac, good)
        json.loads(json.dumps({"sub": "a0"}))

    return _time(check, iterations)


class _Echo(NLIP_Session):  # type: ignore[misc]
    def execute(self, msg: NLIP_Message) -> NLIP_Message:
        return NLIP_Factory.create_text("ok")


class _App(NLIP_Application):  # type: ignore[misc]
    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    def create_session(self) -> NLIP_Session:
        return _Echo()


async def _http(requests: int, depth: int) -> dict[str, Any]:
    clock = SystemClock()
    user = KeyPair.generate("user")
    agents = [KeyPair.generate(f"a{i}") for i in range(depth)]
    w = Warrant.issue(user, agents[0].key_id, CAVEATS, now=clock.now(), ttl=3600)
    for i in range(1, depth):
        w = w.attenuate(agents[i - 1], agents[i].key_id, Caveats(), now=clock.now(), ttl=3600)
    verifier = Verifier({user.key_id}, clock=clock)
    guard = WarrantGuard(agents[-1], "nlip://bench", verifier)
    presenter = WarrantGuard(agents[-2] if depth > 1 else user, "nlip://s", verifier)
    out: dict[str, Any] = {}
    for label, app in (
        ("plain", setup_server(_App())),
        ("guarded", setup_server(GuardedApplication(_App(), guard))),
    ):
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://b") as client:
                samples = []
                for i in range(requests + 50):
                    m = NLIP_Factory.create_text("pay invoice INV-1 please")
                    if label == "guarded":
                        presenter.present(m, w, audience="nlip://bench")
                    body = m.model_dump(mode="json", exclude_none=True)
                    t0 = time.perf_counter_ns()
                    r = await client.post("/nlip/", json=body)
                    dt = time.perf_counter_ns() - t0
                    assert r.status_code == 200 and r.json()["content"] == "ok", r.text
                    if i >= 50:
                        samples.append(dt)
                out[label] = _stats(samples)
    out["overhead_median_us"] = round(out["guarded"]["median_us"] - out["plain"]["median_us"], 1)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--http-requests", type=int, default=1000)
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()
    cpu = next(
        (
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        ),
        platform.processor(),
    )
    result: dict[str, Any] = {
        "platform": {
            "python": platform.python_version(),
            "machine": platform.machine(),
            "cpu": cpu,
            "cores": os.cpu_count(),
        },
        "micro": micro(args.iterations, args.max_depth),
        "bearer_hmac": bearer_baseline(args.iterations),
        "http": {f"depth{d}": asyncio.run(_http(args.http_requests, d)) for d in (1, 3)},
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "bench.json").write_text(json.dumps(result, indent=1) + "\n")
    for r in result["micro"]:
        print(
            f"depth {r['depth']}: warrant {r['warrant_bytes']} B, verify "
            f"{r['decode_verify']['median_us']} us, ingress {r['ingress']['median_us']} us, "
            f"tool {r['tool']['median_us']} us"
        )
    print("http:", json.dumps(result["http"]))


if __name__ == "__main__":
    main()
