.DEFAULT_GOAL := help
SHELL := /bin/bash
COMPOSE := docker compose
# The browser container runs as you, so what it writes (node_modules, screenshots) is yours to delete.
E2E_USER := --user $$(id -u):$$(id -g) -e HOME=/tmp
# Where `make test` finds its stores (compose.dev.yml: PostgreSQL on 15434, Redis on 16390).
export DATABASE_URL ?= postgresql://postgres:postgres@127.0.0.1:15434/app
export REDIS_URL ?= redis://127.0.0.1:16390

.PHONY: help env demo down reset logs install lint typecheck stores test check mutate transcripts e2e screenshots

help: ## list the targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

env: ## write .env with fresh random secrets (never overwrites an existing one)
	@if [ -f .env ]; then echo ".env already exists, leaving it alone"; else \
	  { echo "DB_PASSWORD=$$(openssl rand -hex 16)"; echo "API_KEY=change-me"; \
	    echo "AUDIT_CHAIN_SECRET=$$(openssl rand -hex 32)"; echo "WEBHOOK_SECRET=$$(openssl rand -hex 24)"; \
	    echo "TOTP_SECRET=$$(LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c 32)"; } > .env; \
	  echo "wrote .env with fresh random secrets"; fi

demo: env ## build and start PostgreSQL, Redis and the service (http://localhost:8000)
	$(COMPOSE) up --build --wait -d
	@echo; echo "  site + lab + API:  http://localhost:$${APP_PORT:-8000}   (press 'Enter the lab')"; echo "  stop with:         make down"

down: ## stop everything and keep the data
	$(COMPOSE) down

reset: ## stop everything and delete the data
	$(COMPOSE) down -v

logs: ## follow the logs
	$(COMPOSE) logs -f app

install: ## install dependencies for local development
	pnpm install --frozen-lockfile

lint: ## biome
	pnpm lint

typecheck: ## tsc --strict
	pnpm typecheck

stores: ## start the PostgreSQL and Redis the tests use
	docker compose -f compose.dev.yml -p nw-dev up -d --wait

test: stores ## unit and integration tests (against real PostgreSQL and Redis)
	pnpm test

check: lint typecheck test ## everything the CI checks except the browser tests

mutate: stores ## break each critical rule on purpose and confirm a test notices
	node scripts/mutation-check.mjs

transcripts: stores ## re-record the guided tour on the lab page from the running code
	pnpm transcripts

e2e: env ## browser tests (Playwright + axe) against the Compose stack
	$(COMPOSE) up --build --wait -d
	$(COMPOSE) --profile e2e run --rm $(E2E_USER) e2e

screenshots: env ## re-take the README screenshots (docs/img) from the running stack
	$(COMPOSE) up --build --wait -d
	$(COMPOSE) --profile e2e run --rm $(E2E_USER) -e SHOTS=1 e2e bash -lc "npm ci --no-audit --no-fund && npx playwright test shots"
