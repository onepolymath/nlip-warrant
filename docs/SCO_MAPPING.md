# Mapping to ECMA-434 security countermeasures (SCOs)

Every audit entry for a denial carries the SCO ids it serves (`reasons.py`, `SCO_MAP`).

| ECMA-434 SCO | Requirement (paraphrased) | NLIP-Warrant mechanism |
|---|---|---|
| 7.2.1 Client authentication | Authenticate NLIP clients | Proof of possession signed by the sender's Ed25519 key over the exact message |
| 7.2.2 Client authorization | Authorize clients before security-sensitive actions such as tool calls | Chain verification at ingress; Type-3 check before every protected tool call |
| 7.2.3 Privilege misuse prevention | Avoid confused-deputy misuse of the agent's privileges | Effective authority is the meet of all grants; purpose and payee caveats; explicit narrowing |
| 7.2.4 Agent behaviours (audit) | Traceable across multi-agent chains, auditable, cost-aware | Hash-chained, checkpoint-signed logs keyed by root/leaf block id and message digest; cumulative budgets |
| 7.2.5 Throttling and DoS | Resist flooding and DoS | Cheap fail-closed rejection order; 16 KiB warrant cap; depth cap; third-party revocations ignored |
| 7.3.1 Prompt injection | Countermeasures for (indirect) prompt injection | Impact containment: injected calls outside the grant are refused at the tool boundary |
| 7.3.2 Runtime behaviour controls | Limit, monitor and validate behaviour at run time | Time-of-use expiry and revocation checks; per-call caps; every decision logged |

## NLIP (ECMA-430) integration notes

- Warrants and proofs travel as `token` submessages with subformats `warrant` and `warrant_proof`. ECMA-430 §6.2 allows application-defined token subformats and reserves only the `authentication` and `conversation` prefixes.
- §6.2 requires an end-point to return tokens it did not create. The guard echoes peers' tokens (`nlip.echo_tokens`).
- Denials are `text` messages with `messagetype: "error"` plus a `structured` submessage labelled `nlip-warrant/decision`.
- **SDK observations (nlip_sdk 0.1.3), documented here and not yet reported upstream (we plan to):** `NLIP_Message.add_token` calls `self.add_submessage(self, submsg)` (passes `self` twice), so custom token subformats fail. We build submessages directly. The SDK's reserved auth subformat is `authorization`, while ECMA-430 §6.2 reserves `authentication`.
