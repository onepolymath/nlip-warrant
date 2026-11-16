"""Signed revocations.

Anyone may *publish* a revocation, but a verifier only honours it when it is signed by the
issuer of the revoked block or by the issuer of one of its ancestors. A stranger therefore
cannot revoke someone else's warrant (a cheap denial-of-service), while a user can revoke an
entire delegation subtree with one statement.
"""

from __future__ import annotations

import sqlite3
import threading
from collections import defaultdict
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .encoding import canonical_json
from .keys import KeyId, KeyPair, verify_signature

REVOCATION_DOMAIN = b"nlip-warrant/v1/revocation\x00"


class Revocation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    block_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    by: KeyId
    at: int = Field(ge=0)
    reason: str = Field(default="", max_length=200)
    sig: str = ""

    def signing_input(self) -> bytes:
        body = self.model_dump(mode="json", exclude={"sig"})
        return REVOCATION_DOMAIN + canonical_json(body)

    @classmethod
    def create(cls, key: KeyPair, block_id: str, *, at: int, reason: str = "") -> Revocation:
        unsigned = cls(block_id=block_id, by=key.key_id, at=at, reason=reason)
        return unsigned.model_copy(update={"sig": key.sign(unsigned.signing_input())})

    def signature_valid(self) -> bool:
        return verify_signature(self.by, self.signing_input(), self.sig)


class RevocationStore(Protocol):
    def publish(self, revocation: Revocation) -> bool:
        """Record a revocation. Returns ``False`` (and stores nothing) if its signature is bad."""
        ...

    def revokers(self, block_id: str) -> frozenset[KeyId]:
        """Keys that have validly signed a revocation of ``block_id``."""
        ...


class MemoryRevocationStore:
    def __init__(self) -> None:
        self._by_block: dict[str, set[KeyId]] = defaultdict(set)
        self._lock = threading.Lock()
        self.log: list[Revocation] = []

    def publish(self, revocation: Revocation) -> bool:
        if not revocation.signature_valid():
            return False
        with self._lock:
            self._by_block[revocation.block_id].add(revocation.by)
            self.log.append(revocation)
        return True

    def revokers(self, block_id: str) -> frozenset[KeyId]:
        with self._lock:
            return frozenset(self._by_block.get(block_id, ()))


class SqliteRevocationStore:
    """Durable store, safe to share between agent processes on one host (WAL mode)."""

    def __init__(self, path: str | Path) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS revocation ("
            " block_id TEXT NOT NULL, by_key TEXT NOT NULL, at INTEGER NOT NULL,"
            " reason TEXT NOT NULL, sig TEXT NOT NULL, PRIMARY KEY (block_id, by_key))"
        )
        self._lock = threading.Lock()

    def publish(self, revocation: Revocation) -> bool:
        if not revocation.signature_valid():
            return False
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO revocation VALUES (?, ?, ?, ?, ?)",
                (
                    revocation.block_id,
                    revocation.by,
                    revocation.at,
                    revocation.reason,
                    revocation.sig,
                ),
            )
        return True

    def revokers(self, block_id: str) -> frozenset[KeyId]:
        with self._lock:
            rows = self._db.execute(
                "SELECT by_key FROM revocation WHERE block_id = ?", (block_id,)
            ).fetchall()
        return frozenset(str(r[0]) for r in rows)

    def close(self) -> None:
        self._db.close()
