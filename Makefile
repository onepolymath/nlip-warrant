.PHONY: install lint typecheck test cov demo eval bench report reproduce paper web clean

TRIALS ?= 500
ITERATIONS ?= 2000

install:            ## install Python deps (uv) and web deps (pnpm)
	uv sync
	cd web && pnpm install --frozen-lockfile

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

test:
	uv run pytest

cov:
	uv run pytest --cov --cov-report=term-missing --cov-report=xml

demo:               ## run the three-agent scenario and refresh the dashboard snapshot
	uv run nlip-warrant demo --export web/public/data/demo.json --results eval/results/summary.json

eval:               ## attack suite: every attack x every defense x $(TRIALS) trials
	uv run python -m eval.run_attacks --trials $(TRIALS)

bench:              ## latency and wire-size benchmarks
	uv run python -m eval.bench --iterations $(ITERATIONS)

report:             ## regenerate RESULTS.md, paper tables/figures and web summary
	uv run python -m eval.report

reproduce: eval bench report demo paper   ## everything in the paper, from scratch

paper:              ## compile paper/main.tex with tectonic (or latexmk if installed)
	cd paper && (command -v tectonic >/dev/null && tectonic -X compile main.tex || latexmk -pdf main.tex)

web:
	cd web && pnpm build

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache coverage.xml .coverage web/.next
