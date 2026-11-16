"""Deterministic encodings shared by signatures, hashes and the audit log.

Every byte string that is signed or hashed is produced by :func:`canonical_json`, a strict
subset of RFC 8785 (JCS): object keys are sorted, there is no insignificant whitespace, and
floating-point numbers are rejected outright so that no two implementations can disagree on
number formatting. Money is therefore always expressed in integer minor units.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence

from .errors import EncodingError

JSONScalar = str | int | bool | None
JSONValue = JSONScalar | Sequence["JSONValue"] | Mapping[str, "JSONValue"]

_MAX_SAFE_INT = 2**53 - 1


def _check(value: object, path: str) -> None:
    if value is None or isinstance(value, str | bool):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise EncodingError(f"integer at {path} exceeds 2^53-1")
        return
    if isinstance(value, float):
        raise EncodingError(f"floats are not allowed in canonical JSON (at {path})")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EncodingError(f"non-string key at {path}")
            _check(item, f"{path}.{key}")
        return
    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _check(item, f"{path}[{index}]")
        return
    raise EncodingError(f"unsupported type {type(value).__name__} at {path}")


def canonical_json(value: object) -> bytes:
    """Serialise ``value`` to canonical UTF-8 JSON bytes (sorted keys, no whitespace)."""
    _check(value, "$")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64url_encode(data: bytes) -> str:
    """Unpadded base64url, as used by JOSE and the warrant wire format."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, rejecting any character outside the URL-safe alphabet."""
    if not text or any(c not in _B64URL for c in text) or len(text) % 4 == 1:
        raise EncodingError("invalid base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: object) -> str:
    """``sha256`` of the canonical JSON form of ``value``, hex encoded."""
    return sha256_hex(canonical_json(value))
