"""Hash-chained, tamper-evident audit log (Schneier-Kelsey / Crosby-Wallach style).

Each entry commits to its predecessor:
``hash_i = sha256(domain || prev_hash || canonical(body_i))``.
Editing, deleting, inserting or re-ordering any entry breaks every later hash. Truncating the
tail is only detectable against an anchored head, so the log can emit Ed25519-signed
checkpoints that are meant to be published out of band.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .encoding import canonical_json, sha256_hex
from .keys import KeyId, KeyPair, verify_signature

GENESIS = "0" * 64
ENTRY_DOMAIN = b"nlip-warrant/v1/audit\x00"
CHECKPOINT_DOMAIN = b"nlip-warrant/v1/checkpoint\x00"


def entry_hash(prev: str, body: Mapping[str, Any]) -> str:
    return sha256_hex(ENTRY_DOMAIN + prev.encode() + canonical_json(body))


@dataclass(frozen=True, slots=True)
class AuditEntry:
    seq: int
    prev: str
    hash: str
    body: Mapping[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {"seq": self.seq, "prev": self.prev, "hash": self.hash, "body": dict(self.body)}


@dataclass(frozen=True, slots=True)
class Checkpoint:
    seq: int
    head: str
    ts: int
    by: KeyId
    sig: str

    def signing_input(self) -> bytes:
        return CHECKPOINT_DOMAIN + canonical_json(
            {"seq": self.seq, "head": self.head, "ts": self.ts, "by": self.by}
        )

    def to_json(self) -> dict[str, Any]:
        return {"seq": self.seq, "head": self.head, "ts": self.ts, "by": self.by, "sig": self.sig}


@dataclass(frozen=True, slots=True)
class AuditReport:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    problem: str | None = None


class AuditLog:
    """Append-only log. ``sink`` (e.g. :meth:`jsonl_sink`) receives every entry as it is written."""

    def __init__(self, sink: Callable[[AuditEntry], None] | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._sink = sink

    @staticmethod
    def jsonl_sink(path: str | Path) -> Callable[[AuditEntry], None]:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)

        def write(entry: AuditEntry) -> None:
            with target.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_json(), sort_keys=True) + "\n")

        return write

    def append(self, body: Mapping[str, Any]) -> AuditEntry:
        with self._lock:
            prev = self._entries[-1].hash if self._entries else GENESIS
            entry = AuditEntry(len(self._entries), prev, entry_hash(prev, body), dict(body))
            self._entries.append(entry)
            if self._sink is not None:
                self._sink(entry)
            return entry

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    @property
    def head(self) -> str:
        with self._lock:
            return self._entries[-1].hash if self._entries else GENESIS

    def checkpoint(self, key: KeyPair, *, ts: int) -> Checkpoint:
        with self._lock:
            seq = len(self._entries) - 1
            head = self._entries[-1].hash if self._entries else GENESIS
        unsigned = Checkpoint(seq, head, ts, key.key_id, "")
        return Checkpoint(seq, head, ts, key.key_id, key.sign(unsigned.signing_input()))


def verify_entries(
    entries: Iterable[Mapping[str, Any]], checkpoint: Checkpoint | None = None
) -> AuditReport:
    """Recompute the chain from raw JSON entries (as read back from storage)."""
    items = list(entries)
    prev = GENESIS
    count = 0
    for expected_seq, raw in enumerate(items):
        count += 1
        if raw.get("seq") != expected_seq:
            return AuditReport(False, count, expected_seq, "sequence gap or re-ordering")
        if raw.get("prev") != prev:
            return AuditReport(False, count, expected_seq, "broken link to previous entry")
        body = raw.get("body")
        if not isinstance(body, Mapping) or entry_hash(prev, body) != raw.get("hash"):
            return AuditReport(False, count, expected_seq, "entry content does not match its hash")
        prev = str(raw["hash"])
    if checkpoint is not None:
        if not verify_signature(checkpoint.by, checkpoint.signing_input(), checkpoint.sig):
            return AuditReport(False, count, None, "checkpoint signature invalid")
        if count - 1 < checkpoint.seq:
            return AuditReport(False, count, count, "log truncated before signed checkpoint")
        # The entry at checkpoint.seq must hash to the signed head.
        recomputed = _hash_at(items, checkpoint.seq)
        if recomputed != checkpoint.head:
            return AuditReport(False, count, checkpoint.seq, "head differs from signed checkpoint")
    return AuditReport(True, count)


def _hash_at(entries: Iterable[Mapping[str, Any]], seq: int) -> str | None:
    for raw in entries:
        if raw.get("seq") == seq:
            return str(raw.get("hash"))
    return None
