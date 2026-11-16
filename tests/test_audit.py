import json
from typing import Any

import pytest

from nlip_warrant import AuditLog, verify_entries
from nlip_warrant.audit import GENESIS, Checkpoint

from .conftest import key


def _log(n: int = 5, sink=None) -> AuditLog:
    log = AuditLog(sink)
    for i in range(n):
        log.append({"i": i, "decision": "allow" if i % 2 else "deny"})
    return log


def _raw(log: AuditLog) -> list[dict[str, Any]]:
    return [e.to_json() for e in log.entries]


def test_intact_log_verifies():
    log = _log()
    report = verify_entries(_raw(log))
    assert report.ok
    assert report.entries == 5
    assert log.entries[0].prev == GENESIS
    assert log.head == log.entries[-1].hash
    assert AuditLog().head == GENESIS


def test_editing_an_entry_is_detected():
    raw = _raw(_log())
    raw[2]["body"]["decision"] = "allow"
    report = verify_entries(raw)
    assert not report.ok
    assert report.first_bad_seq == 2


@pytest.mark.parametrize("mutate", ["delete", "swap", "insert", "relink", "nobody"])
def test_structural_tampering_is_detected(mutate):
    raw = _raw(_log())
    if mutate == "delete":
        del raw[1]
    elif mutate == "swap":
        raw[1], raw[2] = raw[2], raw[1]
    elif mutate == "insert":
        raw.insert(2, dict(raw[2]))
    elif mutate == "relink":
        raw[3]["prev"] = "f" * 64
    else:
        raw[0]["body"] = "x"
    assert not verify_entries(raw).ok


def test_truncation_is_only_detected_with_a_checkpoint():
    log = _log()
    cp = log.checkpoint(key("auditor"), ts=99)
    raw = _raw(log)
    assert verify_entries(raw, cp).ok
    assert verify_entries(raw[:-1]).ok  # undetectable without an anchor...
    report = verify_entries(raw[:-1], cp)  # ...but caught against the signed head
    assert not report.ok
    assert "truncated" in str(report.problem)


def test_rewritten_history_with_valid_hashes_fails_against_checkpoint():
    log = _log()
    cp = log.checkpoint(key("auditor"), ts=99)
    forged = AuditLog()
    for e in log.entries:
        forged.append({**e.body, "decision": "allow"})
    assert verify_entries(_raw(forged)).ok
    assert not verify_entries(_raw(forged), cp).ok


def test_forged_checkpoint_is_rejected():
    log = _log()
    cp = log.checkpoint(key("auditor"), ts=99)
    bad = Checkpoint(cp.seq, cp.head, cp.ts + 1, cp.by, cp.sig)
    assert not verify_entries(_raw(log), bad).ok
    assert cp.to_json()["seq"] == 4


def test_jsonl_sink_round_trip(tmp_path):
    path = tmp_path / "logs" / "audit.jsonl"
    log = _log(3, AuditLog.jsonl_sink(path))
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    assert lines == _raw(log)
    assert verify_entries(lines).ok
