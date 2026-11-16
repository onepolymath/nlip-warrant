"""The guard as a drop-in for the reference nlip_server, over real HTTP semantics."""

from __future__ import annotations

import httpx
import pytest
from nlip_sdk.nlip import NLIP_Factory, NLIP_Message
from nlip_server.server import NLIP_Application, NLIP_Session, setup_server

from nlip_warrant import Denied, ToolCall
from nlip_warrant.nlip import WARRANT_SUBFORMAT, extract_one, structured
from nlip_warrant.server import GuardedApplication

from .conftest import gbp


class Echo(NLIP_Session):  # type: ignore[misc]
    def __init__(self, guard):
        self.guard = guard
        self.started = self.stopped = False

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    def execute(self, msg: NLIP_Message) -> NLIP_Message:
        amount = int(msg.content.split()[-1])
        self.guard.authorize(
            ToolCall(action="invoice.pay", amount=gbp(amount), counterparty="acme", purpose="q4")
        )
        return NLIP_Factory.create_text(f"paid {amount}")


class EchoApp(NLIP_Application):  # type: ignore[misc]
    def __init__(self, guard):
        self.guard = guard
        self.events: list[str] = []

    async def startup(self):
        self.events.append("startup")

    async def shutdown(self):
        self.events.append("shutdown")

    def create_session(self):
        return Echo(self.guard)


@pytest.fixture
async def setup(env):
    guard = env.guard(env.a, "nlip://a")
    inner = EchoApp(guard)
    app = setup_server(GuardedApplication(inner, guard))
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://a") as client:
            yield env, client, guard, inner
    assert inner.events == ["startup", "shutdown"]


async def _post(client, msg):
    r = await client.post("/nlip/", json=msg.model_dump(mode="json", exclude_none=True))
    assert r.status_code == 200
    return NLIP_Message.model_validate(r.json())


async def test_allowed_request_and_token_echo(setup):
    env, client, _, _ = setup
    alice = env.guard(env.alice, "nlip://alice")
    msg = alice.present(NLIP_Factory.create_text("pay 100"), env.root(), audience="nlip://a")
    rsp = await _post(client, msg)
    assert rsp.content == "paid 100"
    assert extract_one(rsp, WARRANT_SUBFORMAT) == extract_one(msg, WARRANT_SUBFORMAT)


async def test_ingress_denial_is_a_structured_nlip_error(setup):
    _, client, _, _ = setup
    rsp = await _post(client, NLIP_Factory.create_text("pay 100"))
    assert rsp.messagetype == "error"
    decision = structured(rsp, "nlip-warrant/decision")
    assert decision is not None
    assert decision["nlip_warrant"]["reason"] == "missing_warrant"


async def test_tool_denial_inside_the_session(setup):
    env, client, guard, _ = setup
    alice = env.guard(env.alice, "nlip://alice")
    msg = alice.present(NLIP_Factory.create_text("pay 999999"), env.root(), audience="nlip://a")
    rsp = await _post(client, msg)
    decision = structured(rsp, "nlip-warrant/decision")
    assert decision is not None
    assert decision["nlip_warrant"]["reason"] == "amount_exceeded"
    assert guard.audit.entries[-1].body["boundary"] == "tool"
    with pytest.raises(Denied):
        guard.authorize(ToolCall(action="x"))
