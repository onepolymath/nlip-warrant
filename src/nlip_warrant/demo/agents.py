"""Three independently written NLIP agents, each wrapped by its own WarrantGuard.

The agents deliberately differ in style (a planner, a router, a tool executor) and know nothing
about warrants beyond calling ``guard.delegate`` when they hand work on. The payments executor
is intentionally naive: it obeys instructions it finds inside invoice data. It stands in for an
LLM agent that has been successfully prompt-injected, which is the worst case the guard must
contain without seeing any reasoning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from nlip_sdk.nlip import NLIP_Factory, NLIP_Message
from nlip_server.server import NLIP_Application, NLIP_Session

from nlip_warrant.caveats import Caveats, Money
from nlip_warrant.demo.network import Network
from nlip_warrant.errors import Denied
from nlip_warrant.guard import WarrantGuard, current_authority
from nlip_warrant.keys import KeyId
from nlip_warrant.nlip import structured
from nlip_warrant.policy import ToolCall

INJECTION = re.compile(r"wire (?P<minor>\d+) (?P<ccy>[A-Z]{3}) to (?P<to>[\w-]+)", re.IGNORECASE)


def result_message(text: str, payload: dict[str, Any]) -> NLIP_Message:
    msg = NLIP_Factory.create_text(text)
    msg.add_json(payload, label="result")
    return msg


def _authority() -> Any:
    authority = current_authority()
    if authority is None:  # pragma: no cover - GuardedSession always binds one
        raise RuntimeError("no authority bound")
    return authority


# --------------------------------------------------------------------------- payments
@dataclass
class Bank:
    """The external system the payments agent's tools act on."""

    transfers: list[dict[str, Any]] = field(default_factory=list)

    def move(self, kind: str, to: str, amount: Money, ref: str) -> dict[str, Any]:
        record = {
            "kind": kind,
            "to": to,
            "amount": amount.minor,
            "currency": amount.currency,
            "ref": ref,
        }
        self.transfers.append(record)
        return record


class PaymentsTools:
    def __init__(self, guard: WarrantGuard, bank: Bank) -> None:
        self.bank = bank

        @guard.protect(
            lambda inv: ToolCall(
                action="invoice.pay",
                amount=Money(currency=inv["currency"], minor=inv["amount"]),
                counterparty=inv["supplier"],
                purpose=inv.get("purpose"),
                args={"ref": inv["id"]},
            )
        )
        def pay_invoice(inv: dict[str, Any]) -> dict[str, Any]:
            amount = Money(currency=inv["currency"], minor=inv["amount"])
            return self.bank.move("invoice", inv["supplier"], amount, inv["id"])

        @guard.protect(
            lambda to, amount, purpose: ToolCall(
                action="funds.transfer", amount=amount, counterparty=to, purpose=purpose
            )
        )
        def transfer_funds(to: str, amount: Money, purpose: str | None) -> dict[str, Any]:
            return self.bank.move("transfer", to, amount, "ad-hoc")

        self.pay_invoice = pay_invoice
        self.transfer_funds = transfer_funds


class PaymentsSession(NLIP_Session):  # type: ignore[misc]
    def __init__(self, tools: PaymentsTools) -> None:
        self.tools = tools

    def execute(self, msg: NLIP_Message) -> NLIP_Message:
        invoice = structured(msg, "invoice")
        if invoice is None:
            return result_message("No invoice attached.", {"results": []})
        results: list[dict[str, Any]] = []
        try:
            self.tools.pay_invoice(invoice)
            results.append({"tool": "invoice.pay", "status": "done", "ref": invoice["id"]})
        except Denied as d:
            results.append({"tool": "invoice.pay", "status": "refused", "reason": d.reason.value})
        # The naive part: instructions embedded in data are treated as commands.
        for hit in INJECTION.finditer(str(invoice.get("memo", ""))):
            amount = Money(currency=hit["ccy"].upper(), minor=int(hit["minor"]))
            try:
                self.tools.transfer_funds(hit["to"], amount, invoice.get("purpose"))
                results.append({"tool": "funds.transfer", "status": "done", "to": hit["to"]})
            except Denied as d:
                results.append(
                    {
                        "tool": "funds.transfer",
                        "status": "refused",
                        "reason": d.reason.value,
                        "to": hit["to"],
                    }
                )
        done = sum(r["status"] == "done" for r in results)
        return result_message(f"{done}/{len(results)} actions executed.", {"results": results})


class PaymentsApp(NLIP_Application):  # type: ignore[misc]
    def __init__(self, tools: PaymentsTools) -> None:
        self.tools = tools

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    def create_session(self) -> NLIP_Session:
        return PaymentsSession(self.tools)


# --------------------------------------------------------------------------- delegators
@dataclass(frozen=True)
class Hop:
    """Where a delegating agent forwards work, and how much authority it passes on."""

    to_key: KeyId
    to_audience: str
    caveats: Caveats
    ttl: int
    label: str


class DelegatingSession(NLIP_Session):  # type: ignore[misc]
    """Forwards the invoice downstream with an attenuated warrant (procurement / concierge)."""

    def __init__(self, guard: WarrantGuard, network: Network, hop: Hop, role: str) -> None:
        self.guard = guard
        self.network = network
        self.hop = hop
        self.role = role

    async def execute(self, msg: NLIP_Message) -> NLIP_Message:
        invoice = structured(msg, "invoice")
        if invoice is None:
            return result_message(f"{self.role}: nothing to do.", {"results": []})
        out = NLIP_Factory.create_text(f"{self.role}: please settle invoice {invoice['id']}.")
        out.add_json(invoice, label="invoice")
        self.guard.delegate(
            out,
            _authority(),
            to=self.hop.to_key,
            audience=self.hop.to_audience,
            caveats=self.hop.caveats,
            ttl=self.hop.ttl,
            label=self.hop.label,
        )
        downstream = await self.network.send(self.hop.to_audience, out)
        decision = structured(downstream, "nlip-warrant/decision")
        if decision is not None:
            refused = decision["nlip_warrant"]
            return result_message(
                f"{self.role}: {self.hop.to_audience} refused the delegation.",
                {
                    "results": [
                        {
                            "tool": "delegate",
                            "status": "refused",
                            "reason": refused["reason"],
                            "at": self.hop.to_audience,
                        }
                    ]
                },
            )
        payload = structured(downstream, "result") or {"results": []}
        return result_message(str(downstream.content), payload)


class DelegatingApp(NLIP_Application):  # type: ignore[misc]
    def __init__(self, guard: WarrantGuard, network: Network, hop: Hop, role: str) -> None:
        self.args = (guard, network, hop, role)

    async def startup(self) -> None: ...

    async def shutdown(self) -> None: ...

    def create_session(self) -> NLIP_Session:
        return DelegatingSession(*self.args)
