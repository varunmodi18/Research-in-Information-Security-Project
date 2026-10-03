.PHONY: setup test demo eval formal report clean all ci ci-slow bench

# Prefer the project virtualenv when it exists (IMPLEMENTATION_PLAN.md M0-T1).
PYTHON ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
PARAMS ?= demo

setup:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m maka.cli all --params $(PARAMS)

eval:
	$(PYTHON) -m maka.cli eval --all --fixture paper --params $(PARAMS)

formal:
	$(PYTHON) -m maka.cli formal --ban --avispa --params $(PARAMS)

report: eval
	mkdir -p artifacts/submission
	cp -r artifacts/tables artifacts/figures artifacts/transcripts artifacts/submission/ 2>/dev/null || true

# M0-T5: what CI runs on every commit.
# NFR-MNT-01: strict typing on the packages added by IMPLEMENTATION_PLAN.md.
TYPED = src/maka/codec.py src/maka/runtime src/maka/original_rt

ci:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy --strict $(TYPED)
	$(PYTHON) -m pytest -q -m "not slow"

# Checkpoint tasks (⛳) additionally run the slow tests.
ci-slow: ci
	$(PYTHON) -m pytest -q -m slow || [ $$? -eq 5 ]  # 5 = no slow tests collected

bench:
	$(PYTHON) -m eval.bench.primitives --out docs/baseline/primitives
	$(PYTHON) -m eval.bench.legacy --out docs/baseline/legacy_run

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache

all: setup test demo eval formal
