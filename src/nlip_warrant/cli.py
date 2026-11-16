"""``nlip-warrant`` command line: run the demo, inspect tokens, verify audit logs."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from .audit import verify_entries
from .errors import EncodingError
from .warrant import Warrant

_GREEN, _RED, _DIM, _BOLD, _RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def _style(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def cmd_demo(args: argparse.Namespace) -> int:
    # Imported lazily: the demo pulls in FastAPI, which `inspect` and `verify-log` do not need.
    from .demo.export import snapshot  # noqa: PLC0415
    from .demo.scenario import run  # noqa: PLC0415

    world = run(args.seed)
    color = sys.stdout.isatty() and not args.no_color
    print(_style("NLIP-Warrant · procurement scenario", _BOLD, color))
    for e in world.events:
        ok = e.as_expected
        mark = _style("✓" if ok else "✗", _GREEN if ok else _RED, color)
        verdict = "ALLOWED" if e.outcome == "allow" else "BLOCKED"
        where = f" at {e.blocked_at} ({e.reason})" if e.outcome == "block" else ""
        tint = _GREEN if e.outcome == "allow" else _RED
        print(f" {mark} {e.step:>2}. {e.title:<42} {_style(verdict, tint, color)}{where}")
    paid = sum(t["amount"] for t in world.bank.transfers) / 100
    print(
        _style(
            f"    money moved: £{paid:,.2f} in {len(world.bank.transfers)} legitimate "
            "payments, £0.00 to the attacker",
            _DIM,
            color,
        )
    )
    failures = [e for e in world.events if not e.as_expected]
    if args.export:
        results = json.loads(Path(args.results).read_text()) if args.results else None
        Path(args.export).parent.mkdir(parents=True, exist_ok=True)
        Path(args.export).write_text(json.dumps(snapshot(world, results), indent=1) + "\n")
        print(_style(f"    snapshot written to {args.export}", _DIM, color))
    return 1 if failures else 0


def cmd_inspect(args: argparse.Namespace) -> int:
    raw: str = args.token
    token = sys.stdin.read().strip() if raw == "-" else raw
    try:
        warrant = Warrant.decode(token)
    except EncodingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = []
    for i, block in enumerate(warrant.blocks):
        p = block.payload
        out.append(
            {
                "index": i,
                "id": block.block_id,
                "label": p.label,
                "iss": p.iss,
                "sub": p.sub,
                "exp": datetime.fromtimestamp(p.exp, UTC).isoformat(),
                "caveats": p.caveats.wire(),
                "signature_valid": block.signature_valid(),
            }
        )
    print(
        json.dumps(
            {
                "depth": warrant.depth,
                "effective": warrant.effective_caveats().wire(),
                "blocks": out,
            },
            indent=2,
        )
    )
    return 0


def cmd_verify_log(args: argparse.Namespace) -> int:
    lines = Path(args.path).read_text().splitlines()
    report = verify_entries([json.loads(line) for line in lines if line.strip()])
    if report.ok:
        print(f"ok: {report.entries} entries, hash chain intact")
        return 0
    print(f"TAMPERED at seq {report.first_bad_seq}: {report.problem}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nlip-warrant", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the multi-agent procurement scenario")
    demo.add_argument("--seed", default="nlip-warrant-demo", help="key-derivation seed")
    demo.add_argument("--export", help="write the dashboard snapshot JSON here")
    demo.add_argument("--results", help="evaluation summary JSON to embed in the snapshot")
    demo.add_argument("--no-color", action="store_true")
    demo.set_defaults(fn=cmd_demo)

    inspect = sub.add_parser("inspect", help="decode a warrant token ('-' reads stdin)")
    inspect.add_argument("token")
    inspect.set_defaults(fn=cmd_inspect)

    verify = sub.add_parser("verify-log", help="verify a JSONL audit log's hash chain")
    verify.add_argument("path")
    verify.set_defaults(fn=cmd_verify_log)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.fn(args)
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
