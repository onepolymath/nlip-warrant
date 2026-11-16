# Contributing

Thanks for helping. NLIP-Warrant is small on purpose. Please keep changes focused and well tested.

## Setup

```bash
make install          # uv sync: Python 3.11+ venv with dev tools
cd web && pnpm install  # dashboard (Node 20+, pnpm 9+)
```

## Before you open a pull request

```bash
make lint typecheck cov          # ruff, mypy --strict, pytest with the 95% coverage gate
cd web && pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

If you change anything that affects results, rerun `make reproduce` and commit the regenerated `eval/results/`, `paper/generated/` and `web/public/data/demo.json` together.

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org): `feat(verify): …`, `fix(proof): …`, `docs: …`.
- **Security-relevant code** (`verify`, `proof`, `caveats`, `revocation`, `audit`) must fail closed and needs a test for every new denial path.
- **Wire format**: any change to canonical encoding or signed payloads needs a version bump of the domain-separation tag (`nlip-warrant/v1/…`) and matching changes in `web/lib/crypto.ts`.
- Keep decisions **boundary-only**. The guard may read NLIP messages, structured tool arguments, local state and policy. It must not read prompts, model output or agent internals.

Report vulnerabilities privately. See [SECURITY.md](SECURITY.md).
