# Threat model

## System

A user (or organisation) delegates a task to an AI agent, which delegates parts of it to other agents over NLIP (ECMA-430, HTTP binding ECMA-431). Eventually some agent calls a tool that has real-world effect: pays, transfers, refunds, reads a ledger. Every agent runs one `WarrantGuard`, which enforces delegated authority at three control points:

| Control point | SafeOSE type | What it checks |
|---|---|---|
| Ingress from a user client | Type-1 | warrant chain, proof of possession, audience, replay, expiry, revocation |
| Ingress from another agent | Type-2 | same as above |
| Egress (delegation) | Type-2 | the child warrant only narrows what this agent holds; fresh proof for the next audience |
| Tool boundary | Type-3 | structured `ToolCall` against effective caveats; time-of-use expiry/revocation; cumulative budget |

## Trust assumptions

- Ed25519 signatures are unforgeable and SHA-256 is collision resistant.
- Each receiving gateway is configured with the root issuers it trusts (e.g. the user's or organisation's authority key), and those keys are not compromised.
- The guard's code and its local state (replay cache, spend ledger, revocation store, audit log) are not tampered with **while running**. Tampering with the log *after the fact* is detected (see G5).
- Clocks agree to within the 5 s leeway. Proofs are valid for 60 s.
- Tools that matter are invoked through the Type-3 boundary with **structured** arguments.
- Out of scope: identity bootstrapping and key rotation (SafeOSE Area 02), confidentiality of message content (use TLS), network-level DoS.

## Adversary

1. **Injects content.** Controls text any agent reads (invoices, web pages, emails, tool results), so any agent may be prompt-injected into requesting arbitrary tool calls. We model the worst case: the payments agent obeys every injected instruction.
2. **Compromises an intermediary.** Fully, including its signing key.
3. **Controls the network.** Observes, replays, reorders, modifies, redirects and injects NLIP messages.
4. **Is an outsider with her own keys** (*Mallory*). She can sign anything with them, including revocations.

## Security goals

| Goal | Statement | Mechanism |
|---|---|---|
| **G1** least privilege | No tool call executes outside the meet of all grants on its chain | effective caveats + Type-3 `authorize` |
| **G2** monotone attenuation | A compromised intermediary cannot grant more than it holds | explicit narrowing check at verify time; hash-linked, signed blocks |
| **G3** binding | Only the holder can use a warrant, only at its audience, only once | per-message proof over leaf id, audience, timestamp, nonce and message digest; replay cache |
| **G4** timeliness | Expiry and revocation apply at time of use and cascade to descendants; third parties cannot revoke | `check_live` at ingress/egress/tool; revocations honoured only from issuers on the chain |
| **G5** accountability | Every decision is recorded; tampering is detectable | hash-chained log with signed checkpoints, SCO tags, root/leaf ids |
| **G6** boundary-only | Decisions use only boundary-visible data | tokens, structured tool arguments, local state and policy; never prompts or reasoning |

## Attack classes evaluated

| # | Attack | Must be stopped at |
|---|---|---|
| A1 | Action escalation (prompt injection) | tool |
| A2 | Amount escalation | tool |
| A3 | Counterparty substitution | tool |
| A4 | Purpose misuse (confused deputy) | tool |
| A5 | Budget exhaustion | tool |
| A6 | Replay | ingress |
| A7 | Stolen credential | ingress |
| A8 | Credential tampering | ingress |
| A9 | Over-delegation by a compromised intermediary | ingress |
| A10 | Outsider forgery | ingress |
| A11 | Use after revocation | ingress / tool |
| A12 | Use after expiry | ingress / tool |
| A13 | Audience redirection | ingress |
| A14 | Forged revocation (denial of service) | revocation check |
| R1 | **Residual:** a hijacked agent misusing authority it legitimately holds | *not preventable by delegation*; bounded and attributable |

Results are in [`eval/results/RESULTS.md`](../eval/results/RESULTS.md).

## Known limitations

- **Budgets are local** to each gateway's ledger. Cross-service budgets need a shared ledger or escrow.
- **Revocation distribution** is in-memory or SQLite. Production needs gossip or a revocation endpoint, and freshness depends on it.
- **Free-text tools** cannot be constrained by caveats. Wrap them behind structured tool calls.
- **Privacy:** warrants reveal the delegation chain (key ids, caveats) to downstream agents.
- **Deterministic agents** in the evaluation. Guarantees do not depend on the model, but utility with real LLM planners is not measured.
