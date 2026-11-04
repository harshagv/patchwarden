# Patchwarden. Needs Python 3.12 (brew install python@3.12) for dev/test, Docker for `make up`.
PYTHON ?= python3.12
VENV   := .venv
BIN    := $(VENV)/bin

.PHONY: help install dev test up down env check-config secret-scan plugin site clean

help:
	@echo "make dev          run the app locally (SQLite, demo sites on, no secrets needed)"
	@echo "make test         run the test suite (offline: demo sites and APIs are mocked)"
	@echo "make env          create .env from .env.example with generated secrets"
	@echo "make up / down    run / stop the full stack with docker compose (PostgreSQL)"
	@echo "make check-config validate settings without starting the server"
	@echo "make secret-scan  scan this folder for high-entropy secrets (gitleaks)"
	@echo "make plugin       build dist/patchwarden.zip (WordPress plugin) for PUBLIC_BASE_URL"
	@echo "make site         rebuild the website's docs page and example screens in site/"

$(BIN)/python: requirements.txt requirements-dev.txt pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -r requirements-dev.txt
	$(BIN)/pip install -q --no-deps -e .
	@touch $(BIN)/python

install: $(BIN)/python

dev: install
	APP_ENV=development $(BIN)/python -m patchwarden --reload

test: install
	@command -v php >/dev/null || echo "NOTE: PHP is not installed (brew install php): the WordPress plugin tests will be skipped."
	APP_ENV=test $(BIN)/python -m pytest

check-config: install
	$(BIN)/python -m patchwarden --check-config

env:
	@$(or $(wildcard $(BIN)/python),$(PYTHON)) scripts/make_env.py

up:
	docker compose up --build

down:
	docker compose down

secret-scan:
	gitleaks dir . --no-banner --redact --verbose

plugin: install
	@mkdir -p dist
	$(BIN)/python -c "from patchwarden.config import load_settings; from patchwarden.wpguard.plugin_zip import build_plugin_zip; open('dist/patchwarden.zip', 'wb').write(build_plugin_zip(load_settings().public_base_url))"
	@echo "dist/patchwarden.zip ready"

site: install
	$(BIN)/python scripts/build_site.py

clean:
	rm -rf $(VENV) .pytest_cache data dist
