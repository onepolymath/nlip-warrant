"""Warrants: append-only chains of Ed25519-signed delegation blocks.

Wire format::

    nlipw1.<base64url(canonical_json([{"p": payload, "s": signature}, ...]))>

Block ``i`` is signed by its ``iss`` key. For ``i > 0``, ``iss`` must equal the ``sub`` (holder)
of block ``i-1`` and ``parent`` must equal the hash of block ``i-1``, so blocks cannot be
re-ordered, dropped from the middle, or spliced in from another chain. Only the current holder
can extend the chain, and only by narrowing it.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from functools import cached_property

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .caveats import Caveats, meet, narrowing_violations
from .encoding import b64url_decode, b64url_encode, canonical_json, digest
from .errors import EncodingError, WarrantError
from .keys import KeyId, KeyPair, verify_signature

PREFIX = "nlipw1."
BLOCK_DOMAIN = b"nlip-warrant/v1/block\x00"
MAX_WIRE_BYTES = 16_384


class BlockPayload(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    v: int = Field(default=1, ge=1, le=1)
    jti: str = Field(min_length=16, max_length=64)
    parent: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    iss: KeyId = Field(min_length=43, max_length=43)
    sub: KeyId = Field(min_length=43, max_length=43)
    iat: int = Field(ge=0)
    nbf: int = Field(ge=0)
    exp: int = Field(ge=0)
    caveats: Caveats = Caveats()
    label: str | None = Field(default=None, max_length=120)

    def wire(self) -> dict[str, object]:
        out = self.model_dump(mode="json", exclude_none=True, exclude={"caveats"})
        out["caveats"] = self.caveats.wire()
        return out

    def signing_input(self) -> bytes:
        return BLOCK_DOMAIN + canonical_json(self.wire())


@dataclass(frozen=True, slots=True)
class SignedBlock:
    payload: BlockPayload
    signature: str

    def wire(self) -> dict[str, object]:
        return {"p": self.payload.wire(), "s": self.signature}

    @property
    def block_id(self) -> str:
        """Content address of the signed block; this is what revocations and children refer to."""
        return digest(self.wire())

    def signature_valid(self) -> bool:
        return verify_signature(self.payload.iss, self.payload.signing_input(), self.signature)


def _sign(key: KeyPair, payload: BlockPayload) -> SignedBlock:
    if key.key_id != payload.iss:
        raise WarrantError("signing key does not match the block issuer")
    return SignedBlock(payload, key.sign(payload.signing_input()))


@dataclass(frozen=True)
class Warrant:
    blocks: tuple[SignedBlock, ...]

    # ----------------------------------------------------------------- construction
    @classmethod
    def issue(
        cls,
        issuer: KeyPair,
        holder: KeyId,
        caveats: Caveats,
        *,
        now: int,
        ttl: int,
        label: str | None = None,
    ) -> Warrant:
        """Mint a root warrant. Every warrant expires: ``ttl`` is mandatory and positive."""
        if ttl <= 0:
            raise WarrantError("ttl must be positive")
        payload = BlockPayload(
            jti=secrets.token_urlsafe(16),
            iss=issuer.key_id,
            sub=holder,
            iat=now,
            nbf=now,
            exp=now + ttl,
            caveats=caveats,
            label=label,
        )
        return cls((_sign(issuer, payload),))

    def attenuate(
        self,
        holder: KeyPair,
        delegate: KeyId,
        caveats: Caveats,
        *,
        now: int,
        ttl: int,
        label: str | None = None,
    ) -> Warrant:
        """Delegate a narrower slice of this warrant to ``delegate``.

        Raises :class:`WarrantError` if ``holder`` is not the current holder or if the new
        caveats would widen the effective authority. (Verifiers re-check both; this just stops
        honest code from minting tokens that will be refused.)
        """
        if holder.key_id != self.leaf.payload.sub:
            raise WarrantError("only the current holder can attenuate a warrant")
        widened = narrowing_violations(self.effective_caveats(), caveats)
        if widened:
            raise WarrantError(f"attenuation would widen: {', '.join(widened)}")
        if ttl <= 0:
            raise WarrantError("ttl must be positive")
        exp = min(now + ttl, self.leaf.payload.exp)
        payload = BlockPayload(
            jti=secrets.token_urlsafe(16),
            parent=self.leaf.block_id,
            iss=holder.key_id,
            sub=delegate,
            iat=now,
            nbf=max(now, self.leaf.payload.nbf),
            exp=exp,
            caveats=caveats,
            label=label,
        )
        return Warrant((*self.blocks, _sign(holder, payload)))

    # ----------------------------------------------------------------- accessors
    @property
    def root(self) -> SignedBlock:
        return self.blocks[0]

    @property
    def leaf(self) -> SignedBlock:
        return self.blocks[-1]

    @property
    def depth(self) -> int:
        return len(self.blocks)

    @property
    def holder(self) -> KeyId:
        return self.leaf.payload.sub

    @cached_property
    def block_ids(self) -> tuple[str, ...]:
        return tuple(b.block_id for b in self.blocks)

    def effective_caveats(self) -> Caveats:
        """Meet of every block's caveats. Purely structural; does not check signatures."""
        caveats = self.root.payload.caveats
        for block in self.blocks[1:]:
            caveats = meet(caveats, block.payload.caveats)
        return caveats

    # ----------------------------------------------------------------- wire format
    def encode(self) -> str:
        return PREFIX + b64url_encode(canonical_json([b.wire() for b in self.blocks]))

    @classmethod
    def decode(cls, token: str) -> Warrant:
        """Parse a wire token. Structure only: call a :class:`~.verify.Verifier` to trust it."""
        if len(token) > MAX_WIRE_BYTES:
            raise EncodingError("warrant exceeds the maximum wire size")
        if not token.startswith(PREFIX):
            raise EncodingError("not an nlipw1 warrant")
        try:
            raw = json.loads(b64url_decode(token[len(PREFIX) :]))
            if not isinstance(raw, list) or not raw:
                raise EncodingError("warrant must be a non-empty list of blocks")
            blocks: list[SignedBlock] = []
            for item in raw:
                if not isinstance(item, dict) or set(item) != {"p", "s"}:
                    raise EncodingError("malformed block envelope")
                if not isinstance(item["s"], str):
                    raise EncodingError("malformed signature")
                blocks.append(SignedBlock(BlockPayload.model_validate(item["p"]), item["s"]))
        except (ValueError, ValidationError) as exc:
            raise EncodingError(f"malformed warrant: {exc}") from exc
        return cls(tuple(blocks))
