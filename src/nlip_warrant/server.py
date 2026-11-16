"""Drop-in adapters for the reference ``nlip_server`` (FastAPI) implementation.

``GuardedApplication`` wraps *any* ``NLIP_Application``: its sessions run unchanged, but every
inbound message must pass the guard's ingress check first, and every tool the session calls
through :meth:`WarrantGuard.protect` sees the authority bound for that message. Denials are
answered with a spec-conformant NLIP text message (``MessageType="error"``) plus a structured
JSON submessage, and inbound token submessages are echoed as ECMA-430 section 6.2 requires.
"""

from __future__ import annotations

import inspect
from typing import Any

from nlip_sdk.nlip import NLIP_Factory, NLIP_Message
from nlip_server.server import NLIP_Application, NLIP_Session

from .errors import Denied
from .guard import WarrantGuard
from .nlip import echo_tokens
from .reasons import SCO_MAP


def denial_message(denied: Denied) -> NLIP_Message:
    msg = NLIP_Factory.create_text(
        f"Request refused by NLIP-Warrant: {denied.reason.value}", messagetype="error"
    )
    msg.add_json(
        {
            "nlip_warrant": {
                "decision": "deny",
                "reason": denied.reason.value,
                "detail": denied.detail,
                "sco": list(SCO_MAP[denied.reason]),
            }
        },
        label="nlip-warrant/decision",
    )
    return msg


class GuardedSession(NLIP_Session):  # type: ignore[misc]
    def __init__(self, inner: NLIP_Session, guard: WarrantGuard) -> None:
        self.inner = inner
        self.guard = guard

    async def start(self) -> None:
        await _maybe_await(self.inner.start())

    async def stop(self) -> None:
        await _maybe_await(self.inner.stop())

    async def execute(self, msg: NLIP_Message) -> NLIP_Message:
        try:
            authority = self.guard.ingress(msg)
        except Denied as denied:
            return denial_message(denied)
        with self.guard.bound(authority):
            try:
                response = await _maybe_await(self.inner.execute(msg))
            except Denied as denied:  # a Type-3 refusal deep inside the agent
                response = denial_message(denied)
        return echo_tokens(msg, response)


class GuardedApplication(NLIP_Application):  # type: ignore[misc]
    def __init__(self, inner: NLIP_Application, guard: WarrantGuard) -> None:
        self.inner = inner
        self.guard = guard

    async def startup(self) -> None:
        await _maybe_await(self.inner.startup())

    async def shutdown(self) -> None:
        await _maybe_await(self.inner.shutdown())

    def create_session(self) -> NLIP_Session:
        return GuardedSession(self.inner.create_session(), self.guard)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value
