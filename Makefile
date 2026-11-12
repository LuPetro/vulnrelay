.PHONY: install lint test frontend build audit doctor
PYTHON ?= python3
install:
	$(PYTHON) -c "import sys; assert sys.prefix != sys.base_prefix, 'Activate a virtual environment first'"
	$(PYTHON) -m pip install --require-hashes -r backend/requirements-dev.lock
	$(PYTHON) -m pip install --no-build-isolation --no-deps -e backend
lint:
	ruff check --config backend/pyproject.toml backend scripts
	ruff format --config backend/pyproject.toml --check backend scripts
	$(PYTHON) scripts/check_release.py
	$(PYTHON) scripts/check_locks.py
	$(PYTHON) scripts/check_workflows.py
test:
	pytest backend/tests --cov=vulnrelay --cov-config=backend/pyproject.toml --cov-report=term-missing
frontend:
	cd frontend && npm ci && npm run build && npm test
build:
	$(PYTHON) -m build --no-isolation backend --outdir artifacts/python
	twine check artifacts/python/*
audit:
	pip-audit --disable-pip --no-deps --strict -r backend/requirements.lock
	$(PYTHON) scripts/check_secrets.py
	cd frontend && npm audit --audit-level=high
doctor:
	vulnrelay doctor
