"""The NLIP-Warrant Security Extension (SE).

One :class:`WarrantGuard` per agent enforces delegated authority at three control points of the
SafeOSE / ECMA-434 architecture, using only boundary-visible data:

* **ingress** (Type-1 from a user client, Type-2 from another agent): verify the warrant chain
  and the sender's proof on every inbound NLIP message, then bind the verified authority to the
  session;
* **egress** (Type-2): attach an *attenuated* child warrant plus a fresh proof to outbound
  delegations, so authority only ever shrinks as it crosses agents;
* **tool boundary** (Type-3): check each structured tool call against the effective caveats,
  re-check expiry and revocation at time of use, and charge cumulative budgets.

Every decision, allow or deny, is appended to a hash-chained audit log.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ParamSpec, TypeVar

from nlip_sdk.nlip import NLIP_Message

from .audit import AuditLog
from .caveats import Caveats
from .errors import Denied, EncodingError, WarrantError
from .keys import KeyId, KeyPair
from .nlip import (
    PROOF_SUBFORMAT,
    WARRANT_SUBFORMAT,
    attach_proof,
    attach_warrant,
    extract_one,
    message_digest,
)
from .policy import SpendLedger, ToolCall, check_call
from .proof import ReplayCache, make_proof, verify_proof
from .reasons import SCO_MAP, Reason
from .verify import VerifiedWarrant, Verifier
from .warrant import Warrant

P = ParamSpec("P")
R = TypeVar("R")


class Boundary(StrEnum):
    INGRESS = "ingress"
    EGRESS = "egress"
    TOOL = "tool"


class Mode(StrEnum):
    DELEGATION = "delegation"  # the warrant names *this* agent as its new holder
    INVOCATION = "invocation"  # the holder exercises the warrant at this service


@dataclass(frozen=True, slots=True)
class SessionAuthority:
    """What ingress established for one inbound message."""

    verified: VerifiedWarrant
    sender: KeyId
    mode: Mode


_current: ContextVar[SessionAuthority | None] = ContextVar("nlip_warrant_authority", default=None)


def current_authority() -> SessionAuthority | None:
    return _current.get()


class WarrantGuard:
    def __init__(
        self,
        identity: KeyPair,
        audience: str,
        verifier: Verifier,
        *,
        audit: AuditLog | None = None,
        ledger: SpendLedger | None = None,
        proof_window: int = 60,
        replay: ReplayCache | None = None,
    ) -> None:
        self.identity = identity
        self.audience = audience
        self.verifier = verifier
        self.audit = audit if audit is not None else AuditLog()
        self.ledger = ledger if ledger is not None else SpendLedger()
        self.proof_window = proof_window
        self.replay = replay if replay is not None else ReplayCache(proof_window)

    # ------------------------------------------------------------------ helpers
    @property
    def now(self) -> int:
        return self.verifier.clock.now()

    def _record(
        self,
        boundary: Boundary,
        *,
        allow: bool,
        reason: Reason | None = None,
        detail: str = "",
        verified: VerifiedWarrant | None = None,
        call: ToolCall | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "ts": self.now,
            "agent": self.audience,
            "boundary": boundary.value,
            "decision": "allow" if allow else "deny",
        }
        if reason is not None:
            body["reason"] = reason.value
            body["sco"] = list(SCO_MAP[reason])
        if detail:
            body["detail"] = detail
        if verified is not None:
            body["root"] = verified.root_id
            body["leaf"] = verified.block_ids[-1]
            body["depth"] = len(verified.block_ids)
        if call is not None:
            body["action"] = call.action
            if call.amount is not None:
                body["amount"] = call.amount.model_dump(mode="json")
            if call.counterparty is not None:
                body["counterparty"] = call.counterparty
        if extra:
            body.update(extra)
        self.audit.append(body)

    # ------------------------------------------------------------------ ingress
    def ingress(self, msg: NLIP_Message) -> SessionAuthority:
        """Verify an inbound message. Raises :class:`Denied` (already audited) on failure."""
        verified: VerifiedWarrant | None = None
        digest = message_digest(msg)
        try:
            token = extract_one(msg, WARRANT_SUBFORMAT)
            if token is None:
                raise Denied(Reason.MISSING_WARRANT, "message carries no warrant")
            proof = extract_one(msg, PROOF_SUBFORMAT)
            if proof is None:
                raise Denied(Reason.BAD_PROOF, "message carries no proof of possession")
            try:
                warrant = Warrant.decode(token)
            except EncodingError as exc:
                raise Denied(Reason.MALFORMED, str(exc)) from exc
            verified = self.verifier.verify(warrant)
            leaf = warrant.leaf.payload
            if leaf.sub == self.identity.key_id:
                mode, sender = Mode.DELEGATION, leaf.iss
            else:
                mode, sender = Mode.INVOCATION, leaf.sub
            audiences = verified.caveats.audiences
            if audiences is not None and self.audience not in audiences:
                raise Denied(Reason.WRONG_AUDIENCE, f"{self.audience!r} is not an audience")
            verify_proof(
                proof,
                expected_signer=sender,
                expected_wid=warrant.leaf.block_id,
                audience=self.audience,
                msg_digest=digest,
                now=self.now,
                window=self.proof_window,
                replay=self.replay,
            )
        except Denied as denied:
            self._record(
                Boundary.INGRESS,
                allow=False,
                reason=denied.reason,
                detail=denied.detail,
                verified=verified,
                extra={"msg": digest},
            )
            raise
        self._record(
            Boundary.INGRESS,
            allow=True,
            verified=verified,
            extra={"msg": digest, "mode": mode.value},
        )
        return SessionAuthority(verified, sender, mode)

    @contextmanager
    def bound(self, authority: SessionAuthority) -> Iterator[SessionAuthority]:
        """Make ``authority`` the one Type-3 checks use for the duration of the block."""
        token = _current.set(authority)
        try:
            yield authority
        finally:
            _current.reset(token)

    # ------------------------------------------------------------------ egress
    def delegate(
        self,
        msg: NLIP_Message,
        authority: SessionAuthority,
        *,
        to: KeyId,
        audience: str,
        caveats: Caveats,
        ttl: int,
        label: str | None = None,
    ) -> NLIP_Message:
        """Attenuate the held warrant to ``to`` and bind it to ``msg`` for ``audience``."""
        verified = authority.verified
        try:
            if verified.holder != self.identity.key_id:
                raise Denied(
                    Reason.BROKEN_CHAIN, "cannot delegate a warrant this agent does not hold"
                )
            self.verifier.check_live(verified)
            try:
                child = verified.warrant.attenuate(
                    self.identity, to, caveats, now=self.now, ttl=ttl, label=label
                )
            except WarrantError as exc:
                raise Denied(Reason.WIDENED, str(exc)) from exc
        except Denied as denied:
            self._record(
                Boundary.EGRESS,
                allow=False,
                reason=denied.reason,
                detail=denied.detail,
                verified=verified,
                extra={"to": audience},
            )
            raise
        self._bind(msg, child, audience)
        self._record(
            Boundary.EGRESS,
            allow=True,
            verified=verified,
            extra={"to": audience, "child": child.leaf.block_id},
        )
        return msg

    def present(self, msg: NLIP_Message, warrant: Warrant, *, audience: str) -> NLIP_Message:
        """Attach a warrant this agent holds (or just issued) to ``msg`` for ``audience``.

        Used by the user's client to hand the root warrant to its first agent, and by a holder
        that exercises its warrant at a remote service.
        """
        leaf = warrant.leaf.payload
        if self.identity.key_id not in (leaf.sub, leaf.iss):
            raise WarrantError("this identity can neither present nor hand over that warrant")
        return self._bind(msg, warrant, audience)

    def _bind(self, msg: NLIP_Message, warrant: Warrant, audience: str) -> NLIP_Message:
        attach_warrant(msg, warrant.encode())
        proof = make_proof(
            self.identity,
            wid=warrant.leaf.block_id,
            aud=audience,
            msg_digest=message_digest(msg),
            now=self.now,
        )
        return attach_proof(msg, proof)

    # ------------------------------------------------------------------ tool boundary
    def authorize(self, call: ToolCall, authority: SessionAuthority | None = None) -> None:
        """Type-3 check for one tool call. Raises :class:`Denied` (already audited)."""
        authority = authority or _current.get()
        verified = authority.verified if authority else None
        try:
            if authority is None or verified is None:
                raise Denied(Reason.NO_SESSION_WARRANT, "tool call outside a warranted session")
            self.verifier.check_live(verified)
            check_call(verified.caveats, call)
            self.ledger.reserve(verified, call.amount)
        except Denied as denied:
            self._record(
                Boundary.TOOL,
                allow=False,
                reason=denied.reason,
                detail=denied.detail,
                verified=verified,
                call=call,
            )
            raise
        self._record(Boundary.TOOL, allow=True, verified=verified, call=call)

    def protect(
        self, describe: Callable[P, ToolCall]
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator: guard any Python callable (LangChain tool, AG2 function, plain function).

        ``describe`` maps the call's arguments to the boundary-visible :class:`ToolCall`.
        """

        def decorate(fn: Callable[P, R]) -> Callable[P, R]:
            @functools.wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                self.authorize(describe(*args, **kwargs))
                return fn(*args, **kwargs)

            return wrapper

        return decorate
