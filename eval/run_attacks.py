"""Run every attack against every defense over N randomised trials.

uv run python -m eval.run_attacks --trials 300
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import time
from pathlib import Path
from typing import Any

from eval.attacks import ATTACKS, _call, _executes
from eval.defenses import DEFENSES
from eval.trial import make_trial
from nlip_warrant import FrozenClock

RESULTS = Path(__file__).parent / "results"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def run(trials: int, seed: int) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    legit: dict[str, dict[str, int]] = {}
    for defense_cls in DEFENSES:
        for attack in ATTACKS:
            success = 0
            for i in range(trials):
                trial = make_trial(seed * 1_000_003 + i)
                defense = defense_cls(trial, FrozenClock())
                rng = random.Random(f"{seed}/{attack.key}/{i}")
                success += attack.fn(defense, trial, rng)
            lo, hi = wilson(success, trials)
            rows.append(
                {
                    "defense": defense_cls.name,
                    "family": defense_cls.family,
                    "attack": attack.key,
                    "title": attack.title,
                    "group": attack.group,
                    "residual": attack.residual,
                    "trials": trials,
                    "successes": success,
                    "success_rate": success / trials,
                    "ci95": [lo, hi],
                }
            )
        # False alarms: legitimate in-bound requests over fresh trials, several per chain.
        ok = total = 0
        for i in range(trials):
            trial = make_trial(seed * 7_919 + i)
            defense = defense_cls(trial, FrozenClock())
            rng = random.Random(f"{seed}/legit/{i}")
            for _ in range(5):
                total += 1
                ok += _executes(defense, trial.leaf, defense.leaf_envelope(), _call(trial, rng))
                defense.clock.advance(rng.randint(0, 30))
        legit[defense_cls.name] = {"requests": total, "refused": total - ok}
    return {"rows": rows, "legit": legit}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=300)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()
    started = time.perf_counter()
    result = run(args.trials, args.seed)
    elapsed = time.perf_counter() - started
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "attacks.csv").open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "defense",
                "attack",
                "title",
                "trials",
                "successes",
                "success_rate",
                "ci_lo",
                "ci_hi",
            ],
        )
        writer.writeheader()
        for r in result["rows"]:
            writer.writerow(
                {k: r[k] for k in ("defense", "attack", "title", "trials", "successes")}
                | {
                    "success_rate": f"{r['success_rate']:.4f}",
                    "ci_lo": f"{r['ci95'][0]:.4f}",
                    "ci_hi": f"{r['ci95'][1]:.4f}",
                }
            )
    meta = {"trials": args.trials, "seed": args.seed, "elapsed_s": round(elapsed, 1)}
    (args.out / "attacks.json").write_text(json.dumps({"meta": meta, **result}, indent=1) + "\n")
    names = [d.name for d in DEFENSES]
    print(f"{'attack':<42}" + "".join(f"{n[:14]:>16}" for n in names))
    for attack in ATTACKS:
        cells = [r for r in result["rows"] if r["attack"] == attack.key]
        print(
            f"{attack.key + ' ' + attack.title:<42}"
            + "".join(f"{c['success_rate'] * 100:>15.1f}%" for c in cells)
        )
    print(
        "false refusals: "
        + ", ".join(f"{k}: {v['refused']}/{v['requests']}" for k, v in result["legit"].items())
    )
    print(f"done in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
