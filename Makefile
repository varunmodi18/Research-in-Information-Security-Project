.PHONY: setup test demo demo-seed demo-reset eval formal report clean all ci ci-slow bench web web-build openapi serve dev e2e

# Prefer the project virtualenv when it exists (IMPLEMENTATION_PLAN.md M0-T1).
PYTHON ?= $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
PARAMS ?= demo

setup:
	$(PYTHON) -m pip install -e ".[dev,server]"

test:
	$(PYTHON) -m pytest -q

demo:
	$(PYTHON) -m maka.cli all --params $(PARAMS)

# M8-T1: console demo state (users + "Vineyard" + "Lab-Paper"); demo-reset keeps users and audit log
demo-seed:
	PYTHONPATH=src $(PYTHON) -m maka_server seed-demo

demo-reset:
	PYTHONPATH=src $(PYTHON) -m maka_server reset-demo

eval:
	$(PYTHON) -m maka.cli eval --all --fixture paper --params $(PARAMS)

formal:
	$(PYTHON) -m maka.cli formal --ban --avispa --params $(PARAMS)

report: eval
	mkdir -p artifacts/submission
	cp -r artifacts/tables artifacts/figures artifacts/transcripts artifacts/submission/ 2>/dev/null || true

# M0-T5: what CI runs on every commit.
# NFR-MNT-01: strict typing on the packages added by IMPLEMENTATION_PLAN.md.
TYPED = src/maka/codec.py src/maka/kdf.py src/maka/runtime src/maka/original_rt src/maka/enhanced src/maka/lab src/maka_server

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

# -- console (IMPLEMENTATION_PLAN.md M3) -------------------------------------------
openapi:
	$(PYTHON) tools/export_openapi.py
	$(PYTHON) tools/gen_api_doc.py
	cd web && npm run gen:api:file

web:
	cd web && npm ci --no-audit --no-fund

web-build: openapi
	cd web && npm run build

serve:
	$(PYTHON) -m maka_server serve

# Backend with auto-reload on :8000 and Vite on :5173 (proxying /api). Needs MAKA_KEK or MAKA_ENV=test.
dev:
	( $(PYTHON) -m uvicorn --factory maka_server.main:create_app --reload --host 127.0.0.1 --port 8000 & \
	  cd web && npm run dev ; kill %1 )

e2e: web-build
	cd web && npx playwright test

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache

all: setup test demo eval formal
