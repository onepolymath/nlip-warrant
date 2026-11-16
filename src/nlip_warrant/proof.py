"""Proof of possession: binds a presented warrant to one specific message, sender and receiver.

The warrant alone is not enough to act. Each message also carries a short proof, signed by the
*sender*, over ``(warrant leaf, audience, timestamp, nonce, message digest)``. A stolen or
echoed warrant (ECMA-430 section 6.2 requires peers to echo token submessages back) is useless
without the sender's private key, and a captured message cannot be replayed or redirected.
"""

from __future__ import annotations

import json
import secrets
import threading
from collections import OrderedDict

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .encoding import b64url_decode, b64url_encode, canonical_json
from .errors import Denied, EncodingError
from .keys import KeyId, KeyPair, verify_signature
from .reasons import Reason

PROOF_PREFIX = "nlipp1."
PROOF_DOMAIN = b"nlip-warrant/v1/proof\x00"


class ProofPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: int = Field(default=1, ge=1, le=1)
    wid: str = Field(pattern=r"^[0-9a-f]{64}$", description="block id of the warrant leaf")
    aud: str = Field(min_length=1, max_length=200)
    ts: int = Field(ge=0)
    nonce: str = Field(min_length=16, max_length=64)
    msg: str = Field(pattern=r"^[0-9a-f]{64}$", description="sha256 of the bound message")

    def signing_input(self) -> bytes:
        return PROOF_DOMAIN + canonical_json(self.model_dump(mode="json"))


def make_proof(sender: KeyPair, *, wid: str, aud: str, msg_digest: str, now: int) -> str:
    payload = ProofPayload(
        wid=wid, aud=aud, ts=now, nonce=secrets.token_urlsafe(16), msg=msg_digest
    )
    body = canonical_json(
        {"p": payload.model_dump(mode="json"), "s": sender.sign(payload.signing_input())}
    )
    return PROOF_PREFIX + b64url_encode(body)


def parse_proof(token: str) -> tuple[ProofPayload, str]:
    if not token.startswith(PROOF_PREFIX) or len(token) > 2048:
        raise Denied(Reason.BAD_PROOF, "not an nlipp1 proof")
    try:
        raw = json.loads(b64url_decode(token[len(PROOF_PREFIX) :]))
        if not isinstance(raw, dict) or set(raw) != {"p", "s"} or not isinstance(raw["s"], str):
            raise Denied(Reason.BAD_PROOF, "malformed proof envelope")
        return ProofPayload.model_validate(raw["p"]), raw["s"]
    except (ValueError, ValidationError, EncodingError) as exc:
        raise Denied(Reason.BAD_PROOF, f"malformed proof: {exc}") from exc


class ReplayCache:
    """Bounded, time-windowed set of seen ``(warrant leaf, nonce)`` pairs.

    Entries only need to outlive the freshness window: anything older is rejected as stale
    before the cache is consulted, so eviction never re-opens a replay.
    """

    def __init__(self, window: int, capacity: int = 100_000) -> None:
        self.window = window
        self.capacity = capacity
        self._seen: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._lock = threading.Lock()

    def check_and_add(self, wid: str, nonce: str, ts: int, now: int) -> bool:
        """Return ``False`` if this pair was already seen within the window."""
        with self._lock:
            horizon = now - 2 * self.window
            while self._seen and next(iter(self._seen.values())) < horizon:
                self._seen.popitem(last=False)
            key = (wid, nonce)
            if key in self._seen:
                return False
            if len(self._seen) >= self.capacity:
                # Fail closed: refusing fresh traffic is safer than forgetting nonces early.
                return False
            self._seen[key] = ts
            return True

    def __len__(self) -> int:
        return len(self._seen)


def verify_proof(
    token: str,
    *,
    expected_signer: KeyId,
    expected_wid: str,
    audience: str,
    msg_digest: str,
    now: int,
    window: int,
    replay: ReplayCache,
) -> ProofPayload:
    payload, signature = parse_proof(token)
    if not verify_signature(expected_signer, payload.signing_input(), signature):
        raise Denied(Reason.BAD_PROOF, "proof is not signed by the sender of this warrant")
    if payload.wid != expected_wid:
        raise Denied(Reason.BAD_PROOF, "proof is bound to a different warrant")
    if payload.aud != audience:
        raise Denied(Reason.WRONG_AUDIENCE, f"proof addressed to {payload.aud!r}")
    if payload.msg != msg_digest:
        raise Denied(Reason.BAD_PROOF, "proof is bound to a different message")
    if abs(now - payload.ts) > window:
        raise Denied(Reason.STALE_PROOF, "proof timestamp outside the freshness window")
    if not replay.check_and_add(payload.wid, payload.nonce, payload.ts, now):
        raise Denied(Reason.REPLAYED, "proof nonce already used")
    return payload
