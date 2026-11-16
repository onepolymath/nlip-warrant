"""Chain verification: signatures, linkage, narrowing, validity window and revocation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .caveats import Caveats, meet, narrowing_violations
from .clock import Clock, SystemClock
from .errors import Denied
from .keys import KeyId
from .reasons import Reason
from .revocation import MemoryRevocationStore, RevocationStore
from .warrant import Warrant


def effective_caveats(warrant: Warrant) -> Caveats:
    """Meet of every block's caveats. Purely structural; does not check signatures."""
    return warrant.effective_caveats()


@dataclass(frozen=True, slots=True)
class VerifiedWarrant:
    """A warrant whose chain has been fully checked at time ``verified_at``."""

    warrant: Warrant
    caveats: Caveats
    verified_at: int

    @property
    def holder(self) -> KeyId:
        return self.warrant.holder

    @property
    def root_id(self) -> str:
        return self.warrant.root.block_id

    @property
    def block_ids(self) -> tuple[str, ...]:
        return self.warrant.block_ids

    @property
    def expires_at(self) -> int:
        return min(b.payload.exp for b in self.warrant.blocks)


class Verifier:
    """Verifies warrant chains against a set of trusted root issuers.

    Args:
        trusted_roots: Key ids allowed to mint root warrants (e.g. the user's or the
            organisation's authority key). Anything else is refused.
        revocations: Where signed revocations are looked up.
        clock: Time source.
        leeway: Tolerated clock skew in seconds for ``nbf`` / ``exp``.
        max_depth: Hard upper bound on chain length, regardless of caveats.
    """

    def __init__(
        self,
        trusted_roots: Iterable[KeyId],
        revocations: RevocationStore | None = None,
        clock: Clock | None = None,
        *,
        leeway: int = 5,
        max_depth: int = 8,
    ) -> None:
        self.trusted_roots = frozenset(trusted_roots)
        self.revocations: RevocationStore = revocations or MemoryRevocationStore()
        self.clock: Clock = clock or SystemClock()
        self.leeway = leeway
        self.max_depth = max_depth

    def verify(self, warrant: Warrant, *, at: int | None = None) -> VerifiedWarrant:
        now = self.clock.now() if at is None else at
        blocks = warrant.blocks
        if len(blocks) > self.max_depth:
            raise Denied(Reason.DEPTH_EXCEEDED, f"chain length {len(blocks)} > {self.max_depth}")

        root = blocks[0].payload
        if root.iss not in self.trusted_roots:
            raise Denied(Reason.UNTRUSTED_ROOT, "root issuer is not trusted")
        if root.parent is not None:
            raise Denied(Reason.BROKEN_CHAIN, "root block must not have a parent")

        effective: Caveats = root.caveats
        for index, block in enumerate(blocks):
            p = block.payload
            if not block.signature_valid():
                raise Denied(Reason.BAD_SIGNATURE, f"block {index} signature does not verify")
            if p.nbf > p.exp:
                raise Denied(Reason.MALFORMED, f"block {index} has nbf after exp")
            if index > 0:
                prev = blocks[index - 1]
                if p.parent != prev.block_id:
                    raise Denied(Reason.BROKEN_CHAIN, f"block {index} parent hash mismatch")
                if p.iss != prev.payload.sub:
                    raise Denied(Reason.BROKEN_CHAIN, f"block {index} not issued by the holder")
                if p.exp > prev.payload.exp or p.nbf < prev.payload.nbf:
                    raise Denied(Reason.WIDENED, f"block {index} widens the validity window")
                widened = narrowing_violations(effective, p.caveats)
                if widened:
                    reason = Reason.DEPTH_EXCEEDED if widened == ["max_depth"] else Reason.WIDENED
                    raise Denied(reason, f"block {index} widens {', '.join(widened)}")
                effective = meet(effective, p.caveats)
            if now + self.leeway < p.nbf:
                raise Denied(Reason.NOT_YET_VALID, f"block {index} is not valid yet")
            if now - self.leeway >= p.exp:
                raise Denied(Reason.EXPIRED, f"block {index} expired")

        self._check_revocations(warrant)
        return VerifiedWarrant(warrant, effective, now)

    def check_live(self, verified: VerifiedWarrant, *, at: int | None = None) -> None:
        """Cheap time-of-use re-check: expiry and revocation only (signatures are immutable)."""
        now = self.clock.now() if at is None else at
        if now - self.leeway >= verified.expires_at:
            raise Denied(Reason.EXPIRED, "warrant expired since it was presented")
        self._check_revocations(verified.warrant)

    def _check_revocations(self, warrant: Warrant) -> None:
        authorised: set[KeyId] = set()
        for index, block in enumerate(warrant.blocks):
            authorised.add(block.payload.iss)
            revokers = self.revocations.revokers(block.block_id)
            if revokers & authorised:
                raise Denied(Reason.REVOKED, f"block {index} has been revoked")
