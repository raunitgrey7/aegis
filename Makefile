# Aegis — developer & ops entrypoints
.DEFAULT_GOAL := help
PY := python

.PHONY: help install install-dev api web worker test lint eval deck feeds seed up down logs clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install backend + simulator (editable)
	$(PY) -m pip install -e backend -e simulator

install-dev: ## Install with dev extras
	$(PY) -m pip install -e "backend[dev]" -e simulator

api: ## Run the API (http://localhost:8000, docs at /docs)
	uvicorn aegis.main:app --host 0.0.0.0 --port 8000 --reload

web: ## Run the frontend dev server (http://localhost:3000)
	cd frontend && npm run dev

worker: ## Run the streaming detection worker (needs AEGIS_REDIS_URL)
	$(PY) -m aegis.ingestion.worker

test: ## Run the backend test suite
	$(PY) -m pytest backend/tests -q

lint: ## Ruff lint
	ruff check backend simulator

eval: ## Run the full 100+100 benchmark -> evaluation/results/
	$(PY) -m aegis_sim.evaluation --attacks 100 --benign 100 --out evaluation/results

deck: ## Build the pitch deck (needs eval results)
	$(PY) pitch/build_deck.py

feeds: ## Refresh public threat-intel feeds (needs network)
	$(PY) -m aegis.threat_intel.feeds refresh

seed: ## Push a demo attack scenario into a running API
	$(PY) scripts/seed_demo.py

up: ## docker compose up (core services)
	docker compose up --build -d

up-all: ## docker compose up with AI + observability profiles
	docker compose --profile ai --profile observability up --build -d

down: ## docker compose down
	docker compose down

logs: ## Tail compose logs
	docker compose logs -f --tail=100

clean: ## Remove caches and build artifacts
	rm -rf backend/aegis.db .pytest_cache **/__pycache__ frontend/.next
