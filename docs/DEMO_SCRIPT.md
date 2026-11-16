# Demo video script (about 4 minutes)

Record it yourself at 1080p: the rules ask for a pitch-and-demo video "recorded and presented by the authors". Have three things open before you start:

1. The dashboard: <https://nlip-warrant.vercel.app>
2. A terminal in the repo with the venv ready (`make install` already run)
3. The paper PDF (`paper/nlip-warrant.pdf`), open at Table 1

Speak plainly. The timings leave about 20 s of slack. Lines in *italics* are things to do on screen. The rest is what to say.

---

## 0:00 to 0:30 · The problem

*Dashboard hero section.*

> Hi, I'm Yusuf Ojo Raifu from the University of Derby. This is NLIP-Warrant, for the SafeOSE '27 hackathon, Area 06 with an Area 03 control point.
>
> AI agents now hand work to other agents. When my assistant asks a payments agent to pay an invoice, today it passes on everything it has: an API key or a forwarded OAuth token. If one agent on that chain reads a poisoned invoice, it can spend whatever that key allows. That's the classic confused deputy, and prompt injection makes it easy to trigger.

## 0:30 to 1:15 · The idea

*Scroll to "Three control points, one guard", then to the delegation chain.*

> NLIP-Warrant adds delegation that can only shrink. A warrant is a chain of Ed25519-signed blocks. Alice grants her Concierge up to five thousand pounds per payment, a four-thousand budget, three suppliers and one purpose. Concierge narrows that to two thousand and two suppliers for Procurement, and Procurement narrows it again to fifteen hundred and one supplier for Payments.
>
> The warrant travels inside standard ECMA-430 messages as token submessages, next to a proof of possession: the sender signs this exact message for this receiver. One guard per agent checks it at ingress, re-attenuates it at egress, and checks every tool call at the Type-3 boundary.

*Click block 0, then block 2 in the inspector. Point at the three green ticks.*

> These signatures are being re-verified right now, in your browser, by an independent TypeScript implementation.

## 1:15 to 2:30 · Live attack run

*Terminal:*

```bash
uv run nlip-warrant demo
```

> This runs three real NLIP agents, each its own reference nlip_server app, talking over HTTP. The payments agent is deliberately naive: it obeys any instruction hidden in an invoice, just like a prompt-injected model.

*While the output scrolls, point at a few lines.*

> Step one is the legitimate purchase, and it goes through. Then the attacks. A replay of that same message is stopped at ingress. An injected "wire money to mallory-ltd" is stopped at the tool boundary because funds.transfer was never delegated. A swapped payee and an inflated amount are stopped the same way. A warrant stolen off the wire fails because the thief can't sign the proof. Edited caveats break the signature. A compromised intermediary that tries to widen its grant is rejected. Mallory's fake revocation is ignored, and the budget holds across invoices. When Alice revokes her grant, every downstream warrant dies with it. Final line: three thousand and seventy-four pounds fifty paid to the right supplier, zero to the attacker.

*Back to the dashboard: "One legitimate purchase, then the attacks". Click **Replay scenario**, then click step 3.*

> The dashboard shows the same recorded run: who decided, where, and which audit entries it wrote.

## 2:30 to 3:05 · Tamper-evident audit

*Audit section. Choose the Payments tab, then set "Simulate tampering" to "flip a decision", and afterwards to "drop the last entry".*

> Every allow and deny goes into a hash-chained log, signed at checkpoints and tagged with the ECMA-434 countermeasure it serves. If I flip a denial into an allow, the chain breaks at that exact entry. If I cut off the tail, the signed checkpoint no longer matches.

## 3:05 to 3:50 · Evaluation

*Evaluation section, or Table 1 of the paper.*

> We tested fourteen attack classes over five hundred randomised delegation chains each, against no auth, static API keys, forwarded OAuth, and OAuth with RFC 8693 token exchange at every hop. Token exchange, the strongest baseline, blocks six of the fourteen: it can't express amounts, payees or purpose, it doesn't cascade revocation, and its tokens can be replayed. NLIP-Warrant blocks all fourteen with zero false refusals in two and a half thousand legitimate requests. The ablations show that both proof of possession and the tool-boundary check are necessary.
>
> One honest row: R1. A hijacked agent can still misuse authority it really holds. Delegation can't fix that, but it bounds it to fifteen hundred pounds per call to one supplier, and every call is attributable.
>
> Cost: about half a millisecond to verify a three-hop chain, and roughly three-quarters of a millisecond per NLIP round trip.

## 3:50 to 4:15 · Close

*GitHub repo page.*

> It's MIT-licensed, strictly typed, and has 138 tests at 99 percent coverage. One command reproduces every number in the paper. It wraps any reference nlip_server app without code changes beyond decorating your tools. Thanks for watching.

---

### Recording checklist

- [ ] Terminal font at least 16 pt and window wide enough that the demo lines don't wrap
- [ ] Browser zoom at 110%, with bookmarks bar and notifications hidden
- [ ] Run `uv run nlip-warrant demo` once beforehand so nothing has to install on camera
- [ ] Export as MP4 (H.264), 3 to 5 minutes, and upload it where reviewers can view it without signing in
