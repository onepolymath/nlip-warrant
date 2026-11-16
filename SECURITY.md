# Security policy

NLIP-Warrant decides whether one AI agent may act for another, so we treat any bypass of the guard as a security issue.

**Please report privately** through [GitHub security advisories](https://github.com/onepolymath/nlip-warrant/security/advisories/new). Include a minimal warrant, proof and NLIP message that reproduce the problem. Use the demo's seeded keys or freshly generated ones, never production keys.

**In scope:**

- getting `WarrantGuard` to **allow** a request or tool call that the [threat model](docs/THREAT_MODEL.md) says it must refuse (widening, forgery, replay, theft, audience confusion, use after expiry or revocation);
- making an honest request fail through someone else's revocation;
- forging, reordering or truncating an audit log without detection against a signed checkpoint;
- canonicalisation or parsing differences between the Python library and the dashboard's TypeScript verifier.

**Out of scope:** misuse of authority a hijacked agent legitimately holds (residual risk R1, documented in the paper), and the deliberately naive demo agents.

This is research-stage software from a hackathon. It has not had an independent security audit.
