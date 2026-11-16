"""In-process NLIP-over-HTTP network (ECMA-431) with a passive wire tap.

Each agent is a real ``nlip_server`` FastAPI application. Requests are real HTTP POSTs to
``/nlip/`` carried by ``httpx`` through an ASGI transport, so the full routing, validation and
serialisation stack runs, without opening sockets. The tap records every request exactly as it
crossed the wire: that is the attacker's vantage point for the replay and theft attacks.
"""

from __future__ import annotations

from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import FastAPI
from nlip_sdk.nlip import NLIP_Message


@dataclass(frozen=True, slots=True)
class Captured:
    to: str
    body: dict[str, Any]


@dataclass
class Network:
    apps: dict[str, FastAPI] = field(default_factory=dict)
    tap: list[Captured] = field(default_factory=list)
    _stack: AsyncExitStack | None = None

    def register(self, audience: str, app: FastAPI) -> None:
        self.apps[audience] = app

    async def __aenter__(self) -> Network:
        self._stack = AsyncExitStack()
        for app in self.apps.values():
            await self._stack.enter_async_context(app.router.lifespan_context(app))
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def post_raw(self, to: str, body: dict[str, Any]) -> NLIP_Message:
        self.tap.append(Captured(to, body))
        transport = httpx.ASGITransport(app=self.apps[to])
        async with httpx.AsyncClient(transport=transport, base_url="http://agent") as client:
            response = await client.post("/nlip/", json=body)
        response.raise_for_status()
        return NLIP_Message.model_validate(response.json())

    async def send(self, to: str, msg: NLIP_Message) -> NLIP_Message:
        return await self.post_raw(to, msg.model_dump(mode="json", exclude_none=True))
