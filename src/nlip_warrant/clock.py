"""Injectable time source so every time-dependent check is deterministic under test."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> int:
        """Current Unix time in whole seconds."""
        ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class FrozenClock:
    """A manually advanced clock for tests, simulations and reproducible evaluations."""

    def __init__(self, start: int = 1_798_761_600) -> None:  # 2027-01-01T00:00:00Z
        self._t = start

    def now(self) -> int:
        return self._t

    def advance(self, seconds: int) -> None:
        self._t += seconds

    def set(self, t: int) -> None:
        self._t = t
