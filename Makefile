SHELL := /bin/bash
.DEFAULT_GOAL := help

.PHONY: help build build-web build-server build-agent test test-go test-agent test-web e2e up down logs \
        dev-deps dev-server agent-scenario tls clean fmt \
        prod-help prod-deploy prod-deploy-all prod-status prod-health prod-logs prod-backup prod-rollback-list

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	 awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build-web: ## Build the React console and embed it into the server
	cd web && CI=true pnpm install --frozen-lockfile && bash ./scripts/build.sh
	rm -rf server/internal/api/webdist && cp -r web/dist server/internal/api/webdist

build-server: ## Build the Go server binary (console must be embedded first)
	cd server && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/sentinel-server ./cmd/server

build-agent: ## Build the Rust agent (release)
	cd agent && cargo build --release && cp target/release/sentinel-agent ../bin/sentinel-agent

build: build-web build-server build-agent ## Build everything

test-go: ## Run Go unit tests (detection / DLP / behavior / rule validation)
	cd server && go test ./... && go vet ./...

test-agent: ## Run Rust agent tests/checks
	cd agent && cargo test && cargo check

test-web: ## Typecheck and build the React console
	cd web && bash ./scripts/build.sh

test: test-go test-agent test-web ## Run all tests/checks

up: ## Start the full single-node stack in the background (always-on)
	docker compose up -d --build
	@echo "Console → http://localhost:8080  (admin / $${SENTINEL_ADMIN_PASS:-sentinel-admin})"

down: ## Stop the stack
	docker compose down

logs: ## Tail stack logs
	docker compose logs -f --tail=100

dev-deps: ## Start only TimescaleDB + NATS (for native dev)
	docker compose up -d timescaledb nats

dev-server: ## Run the server natively (role=all) against dev-deps
	cd server && SENTINEL_ENROLL_TOKEN=devtoken \
		SENTINEL_DATABASE_URL="postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable" \
		SENTINEL_NATS_URL="nats://localhost:4222" \
		go run ./cmd/server

agent-scenario: ## Run the agent locally in scenario mode against localhost
	cd agent && cargo run -- --server http://localhost:8080 --enroll-token devtoken \
		--scenario --interval 3 --state /tmp/sentinel/agent.json --labels dev,laptop

e2e: ## Run the end-to-end pipeline test (requires running server)
	./scripts/e2e.sh

tls: ## Generate a dev CA + server cert + agent client cert for mTLS
	./scripts/gen-certs.sh

fmt: ## Format Go + Rust
	cd server && go fmt ./...
	cd agent && cargo fmt

clean: ## Remove build artifacts
	rm -rf bin web/dist agent/target/release/sentinel-agent

# ---- production (app2.makebell.com): delegates to deploy/app2/Makefile ----
# Full target list: `make prod-help` (or `cd deploy/app2 && make help`).
PROD := $(MAKE) --no-print-directory -C deploy/app2

prod-help: ## Production: list all deploy/app2 targets
	@$(PROD) help
prod-deploy: ## Production: back up, build, recreate the server on app2
	@$(PROD) deploy
prod-deploy-all: ## Production: redeploy server + dashboard on app2
	@$(PROD) deploy-all
prod-status: ## Production: container status on app2
	@$(PROD) status
prod-health: ## Production: probe public endpoints
	@$(PROD) health
prod-logs: ## Production: tail server logs
	@$(PROD) logs-server
prod-backup: ## Production: back up env/keys + tag rollback images
	@$(PROD) backup
prod-rollback-list: ## Production: list server rollback image tags
	@$(PROD) rollback-list
