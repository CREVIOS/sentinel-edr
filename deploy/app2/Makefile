# Sentinel EDR — production deploy for app2.makebell.com
# ---------------------------------------------------------------------------
# Run from this directory (deploy/app2) on the server:
#     make help            # list every target
#     make deploy          # the usual: back up, build server, recreate, verify
#     make deploy-all      # server + dashboard (out-of-band, OOM-safe)
#
# Secrets live ONLY in ./.env (git-ignored). This Makefile never embeds them;
# it passes --env-file .env to docker compose and sources .env for one-off
# `docker run` steps. Copy ../../.env.example as a starting point if missing.
#
# Code updates: the server has no GitHub credentials (private repo), so push a
# self-contained git bundle from a dev box and apply it here:
#     (dev)    git bundle create /tmp/sentinel.bundle master
#     (dev)    scp /tmp/sentinel.bundle mb_dev@app2.makebell.com:/tmp/
#     (server) make update BUNDLE=/tmp/sentinel.bundle && make deploy
# ---------------------------------------------------------------------------

SHELL    := /bin/bash
.DEFAULT_GOAL := help

ENV      ?= .env
COMPOSE  := docker compose --env-file $(ENV)
ROOT     := $(abspath ../..)
DASH     := $(ROOT)/dashboard
HOST     ?= https://app2.makebell.com
NET      := sentinel_internal
STAMP    := $(shell date +%Y%m%d-%H%M%S)
BKDIR    := $(HOME)/sentinel-backups

REQUIRED_KEYS := PGPW NATS_TOKEN SENTINEL_JWT_SECRET SENTINEL_ENROLL_TOKEN \
                 SENTINEL_ADMIN_USER SENTINEL_ADMIN_PASS BETTER_AUTH_SECRET \
                 BETTER_AUTH_URL SEED_ADMIN_EMAIL SEED_ADMIN_PASS

.PHONY: help check build deploy redeploy deploy-all up dashboard migrate \
        restart restart-server down stop start ps status health logs logs-server \
        logs-dashboard logs-db backup db-dump db-shell rollback rollback-list \
        update agent-build agent-install agent-update prune doctor urls

## ----------------------------------------------------------------- info ----

help: ## Show this help
	@echo "Sentinel EDR — production targets (run from deploy/app2):"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	 awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

urls: ## Print the public URLs
	@echo "  console   $(HOST)/"
	@echo "  login     $(HOST)/login"
	@echo "  enroll    $(HOST)/api/v1/enroll"
	@echo "  installer $(HOST)/install-agent.sh"

check: ## Verify .env exists and required keys are present
	@test -f $(ENV) || { echo "ERROR: $(ENV) missing — cp $(ROOT)/.env.example $(ENV) and fill it"; exit 1; }
	@miss=0; for k in $(REQUIRED_KEYS); do \
	   grep -qE "^$$k=" $(ENV) || { echo "  missing key: $$k"; miss=1; }; done; \
	 if [ $$miss -ne 0 ]; then exit 1; fi; echo "  $(ENV) OK"

doctor: ## Diagnose host: docker, global-proxy net, .env, disk, mem
	@echo "docker:"; docker version --format '  client {{.Client.Version}} / server {{.Server.Version}}' 2>&1 || true
	@echo "global-proxy network:"; docker network inspect global-proxy >/dev/null 2>&1 && echo "  present" || echo "  MISSING (create it or start nginx-proxy)"
	@echo "env:"; $(MAKE) -s check || true
	@echo "disk:"; df -h / | tail -1 | awk '{print "  "$$4" free ("$$5" used)"}'
	@echo "mem:"; free -h | awk '/Mem:/{print "  "$$7" available"}'

## -------------------------------------------------------------- build/run --

build: check ## Build the Go server image (pulls latest golang base)
	$(COMPOSE) build --pull server

up: check ## Start the whole stack (server + db + nats); dashboard via `make dashboard`
	$(COMPOSE) up -d
	@sleep 4; $(MAKE) -s status

deploy: check backup build ## Standard redeploy: back up, build server, recreate, verify
	$(COMPOSE) up -d --no-deps server
	@sleep 6; $(MAKE) -s status; echo; $(MAKE) -s health

redeploy: deploy ## Alias for `deploy`

dashboard: check ## Rebuild + migrate + recreate the dashboard (out-of-band, OOM-safe)
	./build-dashboard.sh

deploy-all: check backup build dashboard ## Full redeploy: server + dashboard
	$(COMPOSE) up -d --no-deps server
	@sleep 6; $(MAKE) -s status; echo; $(MAKE) -s health

migrate: check ## Apply Better Auth DB migrations only
	@set -a; . ./$(ENV); set +a; \
	 docker run --rm --network $(NET) \
	   -e DATABASE_URL="postgres://sentinel:$$PGPW@timescaledb:5432/sentinel?sslmode=disable" \
	   -e BETTER_AUTH_SECRET="$$BETTER_AUTH_SECRET" \
	   -v "$(DASH)":/app -w /app node:22-bookworm-slim \
	   bash -c 'corepack enable && pnpm dlx @better-auth/cli@latest migrate -y'

## ----------------------------------------------------------- lifecycle -----

restart: ## Restart all services
	$(COMPOSE) restart
restart-server: ## Restart only the server
	$(COMPOSE) restart server
start: ## Start stopped containers (no rebuild)
	$(COMPOSE) start
stop: ## Stop containers (keep them)
	$(COMPOSE) stop
down: ## Stop and remove containers (volumes/data are KEPT)
	$(COMPOSE) down

## ------------------------------------------------------------ observe ------

ps: ## docker compose ps
	$(COMPOSE) ps
status: ## Container status table (name / status / image)
	@docker ps --filter name=sentinel- --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'
health: ## Probe public endpoints (expect / 307, /login 200, enroll 200)
	@for p in / /login /api/v1/enroll; do \
	   printf '  %-22s ' "$$p"; curl -sk -o /dev/null -w '%{http_code}\n' "$(HOST)$$p" || echo "FAIL"; done
logs: ## Tail all logs
	$(COMPOSE) logs -f --tail=120
logs-server: ## Tail server logs
	docker logs -f --tail=120 sentinel-server
logs-dashboard: ## Tail dashboard logs
	docker logs -f --tail=120 sentinel-dashboard
logs-db: ## Tail database logs
	docker logs -f --tail=120 sentinel-timescaledb

## ------------------------------------------------------- backup/rollback ---

backup: ## Back up .env + signing keys and tag current images for rollback
	@bk="$(BKDIR)/$(STAMP)"; mkdir -p "$$bk"; \
	 cp -a $(ENV) "$$bk"/app2.env 2>/dev/null || true; \
	 cp -a signing/. "$$bk"/signing/ 2>/dev/null || true; \
	 git -C "$(ROOT)" rev-parse HEAD > "$$bk"/HEAD.txt 2>/dev/null || true; \
	 docker tag sentinel/server:app2 sentinel/server:app2-rollback-$(STAMP) 2>/dev/null || true; \
	 docker tag sentinel/dashboard:app2 sentinel/dashboard:app2-rollback-$(STAMP) 2>/dev/null || true; \
	 chmod -R go-rwx "$$bk"; echo "  backed up -> $$bk (images tagged app2-rollback-$(STAMP))"

db-dump: ## pg_dump the database to ~/sentinel-backups (custom format)
	@bk="$(BKDIR)/$(STAMP)"; mkdir -p "$$bk"; \
	 docker exec sentinel-timescaledb pg_dump -U sentinel -d sentinel -Fc -f /tmp/sentinel.dump && \
	 docker cp sentinel-timescaledb:/tmp/sentinel.dump "$$bk"/sentinel.dump && \
	 docker exec sentinel-timescaledb rm -f /tmp/sentinel.dump && \
	 echo "  dumped -> $$bk/sentinel.dump"
db-shell: ## Open a psql shell in the database
	docker exec -it sentinel-timescaledb psql -U sentinel -d sentinel

rollback-list: ## List available server rollback image tags
	@docker images sentinel/server --format '  {{.Tag}}\t{{.CreatedSince}}' | grep rollback || echo "  (none — run a deploy to create one)"
rollback: ## Roll server back to a tag: make rollback TAG=app2-rollback-YYYYmmdd-HHMMSS
	@test -n "$(TAG)" || { echo "Usage: make rollback TAG=<tag>"; echo "Available:"; $(MAKE) -s rollback-list; exit 1; }
	docker tag sentinel/server:$(TAG) sentinel/server:app2
	$(COMPOSE) up -d --no-deps --force-recreate server
	@sleep 6; $(MAKE) -s status

## --------------------------------------------------------- code update -----

update: ## Apply code from a git bundle (fast-forward only): make update BUNDLE=/tmp/x.bundle
	@test -n "$(BUNDLE)" || { echo "Usage: make update BUNDLE=/path/to/file.bundle"; exit 1; }
	@test -z "$$(git -C "$(ROOT)" status --porcelain)" || { echo "ERROR: working tree dirty — commit/stash first"; git -C "$(ROOT)" status -s; exit 1; }
	git -C "$(ROOT)" bundle verify "$(BUNDLE)"
	git -C "$(ROOT)" fetch "$(BUNDLE)" master
	git -C "$(ROOT)" merge --ff-only FETCH_HEAD
	@git -C "$(ROOT)" log --oneline -1

## --------------------------------------------------------------- agent -----

agent-build: ## Build the agent image (heavy: Rust + eBPF + usbutils)
	cd "$(ROOT)" && docker build -f agent/Dockerfile -t sentinel/agent:app2 .

agent-install: check ## (Re)install the host agent (needs SIGNING_PUBKEY=/path to rotated pubkey)
	@test -n "$(SIGNING_PUBKEY)" || { echo "Usage: sudo make agent-install SIGNING_PUBKEY=/etc/sentinel/release-signing.pub"; echo "(or SENTINEL_REQUIRE_SIGNATURE=0 for dev only)"; exit 1; }
	@set -a; . ./$(ENV); set +a; \
	 sudo SENTINEL_SERVER="$(HOST)" SENTINEL_ENROLL_TOKEN="$$SENTINEL_ENROLL_TOKEN" \
	      SENTINEL_SIGNING_PUBKEY_FILE="$(SIGNING_PUBKEY)" bash ./install-agent.sh

agent-update: agent-build ## Rebuild agent image then restart the host agent service
	sudo systemctl restart sentinel-agent || echo "  (host agent service not found — install with 'make agent-install')"

## --------------------------------------------------------------- misc ------

prune: ## Remove dangling images (rollback tags are kept)
	docker image prune -f
