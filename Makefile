.PHONY: test lint build smoke

test:
	python -m unittest discover -s tests -v

lint:
	ruff check src tests scripts
	python -m compileall -q src tests scripts

build:
	python -m build

smoke:
	python scripts/smoke_test.py
