"""Ed25519 identities (RFC 8032). A key's *id* is its raw public key, base64url encoded."""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .encoding import b64url_decode, b64url_encode
from .errors import EncodingError

KeyId = str


@dataclass(frozen=True, slots=True)
class KeyPair:
    """A signing identity. ``name`` is a human label only; it is never trusted."""

    private: Ed25519PrivateKey = field(repr=False)
    name: str = ""

    @classmethod
    def generate(cls, name: str = "") -> KeyPair:
        return cls(Ed25519PrivateKey.generate(), name)

    @classmethod
    def from_seed(cls, seed: bytes, name: str = "") -> KeyPair:
        """Deterministic key from a 32-byte seed (tests and reproducible evaluations only)."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed), name)

    @property
    def key_id(self) -> KeyId:
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return b64url_encode(raw)

    def sign(self, message: bytes) -> str:
        return b64url_encode(self.private.sign(message))


def verify_signature(key_id: KeyId, message: bytes, signature: str) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature by ``key_id``."""
    try:
        raw = b64url_decode(key_id)
        sig = b64url_decode(signature)
        if len(raw) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
    except (InvalidSignature, EncodingError, ValueError):
        return False
    return True
