.PHONY: setup test demo eval formal report clean all

PYTHON ?= python3
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

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache

all: setup test demo eval formal
