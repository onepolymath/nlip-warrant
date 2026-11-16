"""Exception hierarchy. Every denial carries a machine-readable :class:`~.reasons.Reason`."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .reasons import Reason


class WarrantError(Exception):
    """Base class for every error raised by this package."""


class EncodingError(WarrantError):
    """A value cannot be canonically encoded or decoded."""


class Denied(WarrantError):  # noqa: N818 - reads naturally at call sites: ``except Denied``
    """A security decision went against the request."""

    def __init__(self, reason: Reason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail
