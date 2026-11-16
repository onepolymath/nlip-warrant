"""Denial reasons and their mapping onto ECMA-434 security countermeasures and objectives."""

from __future__ import annotations

from enum import StrEnum


class Reason(StrEnum):
    """Why a boundary refused a message or a tool call. Values are stable wire identifiers."""

    MISSING_WARRANT = "missing_warrant"
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    UNTRUSTED_ROOT = "untrusted_root"
    BROKEN_CHAIN = "broken_chain"
    WIDENED = "attenuation_widened"
    DEPTH_EXCEEDED = "depth_exceeded"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    WRONG_AUDIENCE = "wrong_audience"
    BAD_PROOF = "bad_proof"
    STALE_PROOF = "stale_proof"
    REPLAYED = "replayed"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    AMOUNT_EXCEEDED = "amount_exceeded"
    BUDGET_EXCEEDED = "budget_exceeded"
    CURRENCY_MISMATCH = "currency_mismatch"
    COUNTERPARTY_NOT_ALLOWED = "counterparty_not_allowed"
    PURPOSE_MISMATCH = "purpose_mismatch"
    NO_SESSION_WARRANT = "no_session_warrant"


#: ECMA-434 (1st ed., Dec. 2025) clauses that each reason helps satisfy:
#: 7.2.1 client authentication; 7.2.2 client authorization;
#: 7.2.3 privilege-misuse prevention (confused deputy); 7.2.4 traceable, auditable behaviour;
#: 7.2.5 client throttling and DoS; 7.3.2 runtime agent behaviour controls.
SCO_MAP: dict[Reason, tuple[str, ...]] = {
    Reason.MISSING_WARRANT: ("7.2.2",),
    Reason.MALFORMED: ("7.2.2",),
    Reason.BAD_SIGNATURE: ("7.2.1", "7.2.2"),
    Reason.UNTRUSTED_ROOT: ("7.2.1", "7.2.2"),
    Reason.BROKEN_CHAIN: ("7.2.2", "7.2.3"),
    Reason.WIDENED: ("7.2.3",),
    Reason.DEPTH_EXCEEDED: ("7.2.3",),
    Reason.NOT_YET_VALID: ("7.2.2",),
    Reason.EXPIRED: ("7.2.2",),
    Reason.REVOKED: ("7.2.2",),
    Reason.WRONG_AUDIENCE: ("7.2.1", "7.2.3"),
    Reason.BAD_PROOF: ("7.2.1",),
    Reason.STALE_PROOF: ("7.2.1",),
    Reason.REPLAYED: ("7.2.1", "7.2.5"),
    Reason.ACTION_NOT_ALLOWED: ("7.2.3", "7.3.2"),
    Reason.AMOUNT_EXCEEDED: ("7.2.3", "7.3.2"),
    Reason.BUDGET_EXCEEDED: ("7.2.4", "7.3.2"),
    Reason.CURRENCY_MISMATCH: ("7.3.2",),
    Reason.COUNTERPARTY_NOT_ALLOWED: ("7.2.3", "7.3.2"),
    Reason.PURPOSE_MISMATCH: ("7.2.3",),
    Reason.NO_SESSION_WARRANT: ("7.2.2", "7.3.2"),
}
