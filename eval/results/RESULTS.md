# Results

Attack success rate over 500 randomised trials per cell (lower is better). † residual risk, outside the threat model.

| Attack | None | API key | OAuth | OAuth+TE | W/o PoP | W/o T3 | Ours |
|---|---:|---:|---:|---:|---:|---:|---:|
| A1 Action escalation (prompt injection) | 100% | 100% | 42% | 0% | 0% | 100% | **0%** |
| A2 Amount escalation | 100% | 100% | 100% | 100% | 0% | 100% | **0%** |
| A3 Counterparty substitution | 100% | 100% | 100% | 100% | 0% | 100% | **0%** |
| A4 Purpose misuse (confused deputy) | 100% | 100% | 100% | 100% | 0% | 100% | **0%** |
| A5 Budget exhaustion | 100% | 100% | 100% | 100% | 0% | 100% | **0%** |
| A6 Replay | 100% | 100% | 100% | 100% | 100% | 0% | **0%** |
| A7 Stolen credential | 100% | 100% | 100% | 100% | 100% | 0% | **0%** |
| A8 Credential tampering | 100% | 100% | 0% | 0% | 0% | 0% | **0%** |
| A9 Over-delegation by intermediary | 100% | 100% | 66% | 49% | 0% | 0% | **0%** |
| A10 Outsider forgery | 100% | 0% | 0% | 0% | 0% | 0% | **0%** |
| A11 Use after revocation | 100% | 100% | 0% | 100% | 0% | 0% | **0%** |
| A12 Use after expiry | 100% | 100% | 0% | 0% | 0% | 0% | **0%** |
| A13 Audience redirection | 100% | 0% | 100% | 0% | 0% | 0% | **0%** |
| A14 Forged revocation (DoS) | 0% | 0% | 0% | 0% | 0% | 0% | **0%** |
| R1 In-bound misuse (residual) † | 100% | 100% | 100% | 100% | 100% | 100% | **100%** |
| **Classes fully blocked** | 1/14 | 3/14 | 5/14 | 6/14 | 12/14 | 9/14 | 14/14 |
| **False refusals** | 0/2500 | 0/2500 | 0/2500 | 0/2500 | 0/2500 | 0/2500 | 0/2500 |
