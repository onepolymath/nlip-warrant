"""Turn raw results into the README table, the paper's LaTeX tables/figures and web data.

uv run python -m eval.report
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from eval.attacks import ATTACKS
from eval.defenses import DEFENSES

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "eval" / "results"
PAPER = ROOT / "paper"
SHORT = {
    "No authorization": "None",
    "Static API keys": "API key",
    "OAuth bearer (forwarded)": "OAuth",
    "OAuth + token exchange": "OAuth+TE",
    "Warrant, no PoP": "W/o PoP",
    "Warrant, ingress only": "W/o T3",
    "NLIP-Warrant": "Ours",
}


def _matrix(attacks: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    out: dict[str, dict[str, dict[str, Any]]] = {}
    for row in attacks["rows"]:
        out.setdefault(row["attack"], {})[row["defense"]] = row
    return out


def summary(attacks: dict[str, Any], bench: dict[str, Any]) -> dict[str, Any]:
    m = _matrix(attacks)
    scored = [a for a in ATTACKS if not a.residual]
    per_defense = {}
    for d in DEFENSES:
        blocked = sum(1 for a in scored if m[a.key][d.name]["success_rate"] == 0.0)
        mean_success = sum(m[a.key][d.name]["success_rate"] for a in scored) / len(scored)
        legit = attacks["legit"][d.name]
        per_defense[d.name] = {
            "short": SHORT[d.name],
            "family": d.family,
            "classes_fully_blocked": blocked,
            "classes": len(scored),
            "mean_attack_success": round(mean_success, 4),
            "false_refusals": legit["refused"],
            "legit_requests": legit["requests"],
        }
    return {
        "meta": attacks["meta"],
        "defenses": per_defense,
        "attacks": [
            {
                "key": a.key,
                "title": a.title,
                "group": a.group,
                "residual": a.residual,
                "success": {d.name: round(m[a.key][d.name]["success_rate"], 4) for d in DEFENSES},
                "ci95": {d.name: [round(x, 4) for x in m[a.key][d.name]["ci95"]] for d in DEFENSES},
            }
            for a in ATTACKS
        ],
        "latency": {
            "platform": bench["platform"],
            "by_depth": [
                {
                    "depth": r["depth"],
                    "warrant_bytes": r["warrant_bytes"],
                    "proof_bytes": r["proof_bytes"],
                    "verify_us": r["decode_verify"]["median_us"],
                    "ingress_us": r["ingress"]["median_us"],
                    "ingress_p95_us": r["ingress"]["p95_us"],
                    "tool_us": r["tool"]["median_us"],
                }
                for r in bench["micro"]
            ],
            "bearer_hmac_us": bench["bearer_hmac"]["median_us"],
            "http": bench["http"],
        },
    }


def markdown(s: dict[str, Any]) -> str:
    names = list(s["defenses"])
    head = "| Attack | " + " | ".join(s["defenses"][n]["short"] for n in names) + " |"
    sep = "|---|" + "---:|" * len(names)
    lines = [head, sep]
    for a in s["attacks"]:
        cells = []
        for n in names:
            v = a["success"][n] * 100
            cells.append(f"**{v:.0f}%**" if n == "NLIP-Warrant" else f"{v:.0f}%")
        label = f"{a['key']} {a['title']}" + (" †" if a["residual"] else "")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines.append(
        "| **Classes fully blocked** | "
        + " | ".join(
            f"{s['defenses'][n]['classes_fully_blocked']}/{s['defenses'][n]['classes']}"
            for n in names
        )
        + " |"
    )
    lines.append(
        "| **False refusals** | "
        + " | ".join(
            f"{s['defenses'][n]['false_refusals']}/{s['defenses'][n]['legit_requests']}"
            for n in names
        )
        + " |"
    )
    return "\n".join(lines) + "\n"


def latex_attacks(s: dict[str, Any]) -> str:
    names = list(s["defenses"])
    cols = "l" + "r" * len(names)
    out = [
        r"\begin{tabular}{@{}" + cols + r"@{}}",
        r"\toprule",
        "Attack & "
        + " & ".join(rf"\textsf{{{s['defenses'][n]['short']}}}" for n in names)
        + r" \\",
        r"\midrule",
    ]
    for a in s["attacks"]:
        if a["residual"]:
            out.append(r"\midrule")
        cells = []
        for n in names:
            v = round(a["success"][n] * 100)
            txt = f"{v}"
            if n == "NLIP-Warrant":
                txt = rf"\textbf{{{v}}}"
            cells.append(txt)
        title = a["title"].replace("&", r"\&")
        out.append(f"{a['key']} {title} & " + " & ".join(cells) + r" \\")
    out.append(r"\midrule")
    out.append(
        r"Classes blocked & "
        + " & ".join(
            f"{s['defenses'][n]['classes_fully_blocked']}/{s['defenses'][n]['classes']}"
            for n in names
        )
        + r" \\"
    )
    out.append(
        r"False refusals & "
        + " & ".join(f"{s['defenses'][n]['false_refusals']}" for n in names)
        + r" \\"
    )
    out += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(out) + "\n"


def latex_latency(s: dict[str, Any]) -> str:
    out = [
        r"\begin{tabular}{@{}rrrrr@{}}",
        r"\toprule",
        r"Depth & Warrant (B) & Verify ($\mu$s) & Ingress ($\mu$s) & Tool ($\mu$s) \\",
        r"\midrule",
    ]
    for r in s["latency"]["by_depth"]:
        if r["depth"] in (1, 2, 3, 4, 6, 8):
            out.append(
                f"{r['depth']} & {r['warrant_bytes']:,} & {r['verify_us']:.0f} & "
                f"{r['ingress_us']:.0f} & {r['tool_us']:.0f} \\\\"
            )
    out += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(out).replace(",", "{,}") + "\n"


def macros(s: dict[str, Any]) -> str:
    """Numbers quoted in the paper's prose, so text and tables can never disagree."""
    ours = s["defenses"]["NLIP-Warrant"]
    lat = s["latency"]
    d1 = lat["by_depth"][0]
    d3 = next(r for r in lat["by_depth"] if r["depth"] == 3)
    best_base = min(
        (v["mean_attack_success"], k) for k, v in s["defenses"].items() if v["family"] == "baseline"
    )
    vals = {
        "Trials": s["meta"]["trials"],
        "Classes": ours["classes"],
        "OursBlocked": ours["classes_fully_blocked"],
        "OursFalse": ours["false_refusals"],
        "LegitRequests": ours["legit_requests"],
        "BestBaselineName": SHORT[best_base[1]],
        "BestBaselineSuccess": f"{best_base[0] * 100:.0f}",
        "BestBaselineBlocked": s["defenses"][best_base[1]]["classes_fully_blocked"],
        "IngressOne": f"{d1['ingress_us']:.0f}",
        "IngressThree": f"{d3['ingress_us']:.0f}",
        "VerifyOne": f"{d1['verify_us']:.0f}",
        "ToolUs": f"{d3['tool_us']:.0f}",
        "WarrantOne": f"{d1['warrant_bytes']}",
        "WarrantThree": f"{d3['warrant_bytes']:,}".replace(",", "{,}"),
        "PerHopBytes": f"{lat['by_depth'][1]['warrant_bytes'] - d1['warrant_bytes']}",
        "HttpPlain": f"{lat['http']['depth3']['plain']['median_us'] / 1000:.2f}",
        "HttpGuarded": f"{lat['http']['depth3']['guarded']['median_us'] / 1000:.2f}",
        "HttpOverhead": f"{lat['http']['depth3']['overhead_median_us'] / 1000:.2f}",
        "Cpu": lat["platform"]["cpu"].replace("_", r"\_"),
        "BearerUs": f"{lat['bearer_hmac_us']:.0f}",
    }
    return "".join(rf"\newcommand{{\res{k}}}{{{v}}}" + "\n" for k, v in vals.items())


def figures(s: dict[str, Any]) -> None:
    plt.rcParams.update(
        {
            "font.size": 8,
            "font.family": "serif",
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    depth = [r["depth"] for r in s["latency"]["by_depth"]]
    fig, ax = plt.subplots(figsize=(3.3, 1.9))
    ax.plot(
        depth,
        [r["ingress_us"] for r in s["latency"]["by_depth"]],
        "o-",
        ms=3,
        label="ingress (decode, verify chain, proof, audit)",
        color="#4338ca",
    )
    ax.plot(
        depth,
        [r["verify_us"] for r in s["latency"]["by_depth"]],
        "s--",
        ms=3,
        label="chain verification only",
        color="#0891b2",
    )
    ax.plot(
        depth,
        [r["tool_us"] for r in s["latency"]["by_depth"]],
        "^:",
        ms=3,
        label="Type-3 tool check",
        color="#059669",
    )
    ax.set_xlabel("delegation depth (blocks)")
    ax.set_ylabel(r"median latency ($\mu$s)")
    ax.legend(frameon=False, fontsize=6.5, loc="upper left")
    ax.grid(alpha=0.25)
    fig.tight_layout(pad=0.3)
    (PAPER / "figures").mkdir(parents=True, exist_ok=True)
    fig.savefig(PAPER / "figures" / "latency.pdf")
    plt.close(fig)


def main() -> None:
    attacks = json.loads((RESULTS / "attacks.json").read_text())
    bench = json.loads((RESULTS / "bench.json").read_text())
    s = summary(attacks, bench)
    (RESULTS / "summary.json").write_text(json.dumps(s, indent=1) + "\n")
    (RESULTS / "RESULTS.md").write_text(
        f"# Results\n\nAttack success rate over {s['meta']['trials']} randomised trials per "
        "cell (lower is better). † residual risk, outside the threat model.\n\n" + markdown(s)
    )
    gen = PAPER / "generated"
    gen.mkdir(parents=True, exist_ok=True)
    (gen / "attacks.tex").write_text(latex_attacks(s))
    (gen / "latency.tex").write_text(latex_latency(s))
    (gen / "results.tex").write_text(macros(s))
    figures(s)
    print(markdown(s))


if __name__ == "__main__":
    main()
