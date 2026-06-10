#!/usr/bin/env bash
###############################################################################################
# Sentinel EDR — one-command LOCAL-SERVER deploy.
#
# Brings up the FULL stack on a single box behind a local nginx (HTTP):
#   TimescaleDB · NATS · Go control plane · Next.js dashboard · nginx (single entry point)
#
# What it does (idempotent — safe to re-run):
#   1. preflight  — checks docker + docker compose + openssl
#   2. env        — creates .env from .env.example and auto-generates every secret
#   3. webroot    — stages the agent installer at /install-agent.sh
#   4. server     — builds the Go image, starts db + nats + server, waits for /readyz
#   5. dashboard  — builds the Next.js standalone artifact OUT-OF-BAND (OOM-safe),
#                   runs Better Auth migrations, seeds your console operator, builds the
#                   COPY-only runtime image
#   6. up         — starts the dashboard + nginx
#   7. verify     — probes the public endpoints and prints URLs + credentials
#
# Usage:
#   ./deploy.sh                       # full deploy (default)
#   ./deploy.sh --host 192.168.1.50 --port 8088
#   ./deploy.sh --with-agent          # also start a demo scenario agent (synthetic telemetry)
#   ./deploy.sh --skip-build          # reuse existing dashboard image (fast redeploy)
#
#   ./deploy.sh up | down | restart | status | health | logs [svc]
#   ./deploy.sh dashboard             # rebuild + migrate + reseed + recreate dashboard only
#   ./deploy.sh seed                  # (re)create the console operator from .env
#   ./deploy.sh agent                 # start the demo scenario agent
#   ./deploy.sh install-cmd           # print the endpoint install one-liner
#   ./deploy.sh clean                 # stop the stack (data volumes are KEPT)
#
# Secrets live ONLY in ./.env (git-ignored). This script never prints them except the final
# credentials summary, and never commits them.
###############################################################################################
set -euo pipefail

# ---- locations ------------------------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DASH="$ROOT/dashboard"
ENV_FILE="$HERE/.env"
WWW="$HERE/www"
NET="sentinel_internal"          # docker network created by this compose (project=sentinel)
NODE_IMG="node:22-bookworm-slim"
NODE_HEAP="${NODE_HEAP:-4096}"    # Node heap cap for the dashboard build (MB)

# ---- pretty logging -------------------------------------------------------------------------
log()  { printf '\033[36m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗ ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;35m== %s ==\033[0m\n' "$*"; }

# ---- docker compose detection ---------------------------------------------------------------
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  die "docker compose not found — install Docker Engine + the compose plugin"
fi
compose() { ( cd "$HERE" && "${COMPOSE[@]}" --env-file "$ENV_FILE" "$@" ); }

# ---- .env helpers ---------------------------------------------------------------------------
# get_val KEY — print the (trimmed) value of KEY from .env, stripping a trailing # comment.
get_val() {
  grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- \
    | sed -e 's/[[:space:]]*#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}
# set_kv KEY VALUE — replace KEY's line in .env (or append). Values are hex/host strings only,
# so no escaping headaches.
set_kv() {
  local key="$1" val="$2" tmp
  if grep -qE "^${key}=" "$ENV_FILE"; then
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$val" 'BEGIN{FS="="} $1==k{print k"="v; next} {print}' "$ENV_FILE" >"$tmp"
    mv "$tmp" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$val" >>"$ENV_FILE"
  fi
}
# ensure_secret KEY BYTES — generate a hex secret if KEY is blank.
ensure_secret() {
  local key="$1" bytes="$2"
  if [ -z "$(get_val "$key")" ]; then
    set_kv "$key" "$(openssl rand -hex "$bytes")"
    log "generated $key"
  fi
}

# ---- preflight ------------------------------------------------------------------------------
preflight() {
  command -v docker  >/dev/null 2>&1 || die "docker not found"
  command -v openssl >/dev/null 2>&1 || die "openssl not found (needed to generate secrets)"
  docker info >/dev/null 2>&1 || die "docker daemon not reachable (is Docker running?)"
}

# ---- env: create .env + generate secrets + normalize host ----------------------------------
prepare_env() {
  if [ ! -f "$ENV_FILE" ]; then
    cp "$HERE/.env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "created .env from .env.example"
  fi

  ensure_secret PGPW 16
  ensure_secret NATS_TOKEN 24
  ensure_secret SENTINEL_JWT_SECRET 32         # 64 hex chars (>=32 required)
  ensure_secret SENTINEL_ENROLL_TOKEN 24
  ensure_secret BETTER_AUTH_SECRET 32
  ensure_secret SENTINEL_ADMIN_PASS 16         # Go service-account password
  ensure_secret CONSOLE_ADMIN_PASS 16          # console login (32 hex chars >= 12 required)
  [ -n "$(get_val SENTINEL_ADMIN_USER)"   ] || set_kv SENTINEL_ADMIN_USER admin
  [ -n "$(get_val CONSOLE_ADMIN_EMAIL)"   ] || set_kv CONSOLE_ADMIN_EMAIL admin@sentinel.local
  [ -n "$(get_val CONSOLE_ADMIN_ROLE)"    ] || set_kv CONSOLE_ADMIN_ROLE admin

  # Normalize SENTINEL_HOST so it always agrees with HTTP_PORT (CORS + Better Auth need an
  # exact origin match). --host / --port override the bare host / port.
  local cur bare port
  cur="$(get_val SENTINEL_HOST)"; cur="${cur:-http://localhost}"
  bare="${cur#http://}"; bare="${bare#https://}"; bare="${bare%%:*}"; bare="${bare%%/*}"
  [ -n "${HOST_ARG:-}" ] && bare="$HOST_ARG"
  [ -n "${PORT_ARG:-}" ] && set_kv HTTP_PORT "$PORT_ARG"
  port="$(get_val HTTP_PORT)"; port="${port:-80}"
  if [ "$port" = "80" ]; then set_kv SENTINEL_HOST "http://$bare"; else set_kv SENTINEL_HOST "http://$bare:$port"; fi

  chmod 600 "$ENV_FILE"
  ok ".env ready  (host $(get_val SENTINEL_HOST), port $(get_val HTTP_PORT))"
}

# ---- webroot: stage the agent installer -----------------------------------------------------
stage_webroot() {
  mkdir -p "$WWW/dl"
  if [ -f "$ROOT/deploy/app2/install-agent.sh" ]; then
    cp "$ROOT/deploy/app2/install-agent.sh" "$WWW/install-agent.sh"
    chmod 644 "$WWW/install-agent.sh"
    ok "staged /install-agent.sh"
  else
    warn "install-agent.sh not found under deploy/app2 — endpoints must build the agent from source"
  fi
}

# ---- wait for the server to be ready (poll /readyz from inside the network) ------------------
wait_server() {
  log "waiting for the server to become ready…"
  local _
  for _ in $(seq 1 60); do
    if docker run --rm --network "$NET" curlimages/curl:latest \
         -sf -o /dev/null --max-time 3 http://sentinel-server:8080/readyz >/dev/null 2>&1; then
      ok "server is ready"
      return 0
    fi
    sleep 2
  done
  warn "server did not report ready in 120s — check: ./deploy.sh logs server"
}

# ---- build the Next.js standalone artifact OUT-OF-BAND (OOM-safe), then the runtime image ----
build_dashboard() {
  step "DASHBOARD BUILD (out-of-band, OOM-safe)"
  # The build container runs as root; remove a prior root-owned .next with sudo if needed.
  rm -rf "$DASH/.next" 2>/dev/null || sudo rm -rf "$DASH/.next"
  log "[1/3] building Next.js standalone artifact (heap ${NODE_HEAP}MB)"
  docker run --rm -v "$DASH":/app -w /app \
    -e NEXT_TELEMETRY_DISABLED=1 -e NODE_OPTIONS="--max-old-space-size=${NODE_HEAP}" "$NODE_IMG" \
    bash -c 'corepack enable && pnpm install --frozen-lockfile && pnpm exec next build --webpack'
  [ -f "$DASH/.next/standalone/server.js" ] || die "dashboard build produced no standalone output"
  # chown build output back to the invoking user so the next rm/build needs no sudo.
  docker run --rm -v "$DASH":/app -w /app "$NODE_IMG" \
    chown -R "$(id -u):$(id -g)" /app/.next /app/node_modules 2>/dev/null || true

  log "[2/3] applying Better Auth migrations"
  migrate_db

  log "[3/3] building COPY-only runtime image (sentinel/dashboard:local)"
  docker build -f "$DASH/Dockerfile.prebuilt" -t sentinel/dashboard:local "$DASH"
}

migrate_db() {
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  docker run --rm --network "$NET" \
    -e DATABASE_URL="postgres://sentinel:${PGPW}@timescaledb:5432/sentinel?sslmode=disable" \
    -e BETTER_AUTH_SECRET="$BETTER_AUTH_SECRET" \
    -v "$DASH":/app -w /app "$NODE_IMG" \
    bash -c 'corepack enable && pnpm dlx @better-auth/cli@latest migrate -y'
}

# ---- seed (or re-create) the console operator so you can log in ------------------------------
seed_operator() {
  step "SEED CONSOLE OPERATOR"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  [ -n "${CONSOLE_ADMIN_EMAIL:-}" ] && [ -n "${CONSOLE_ADMIN_PASS:-}" ] || die "CONSOLE_ADMIN_EMAIL / CONSOLE_ADMIN_PASS missing in .env"
  docker run --rm --network "$NET" \
    -e DATABASE_URL="postgres://sentinel:${PGPW}@timescaledb:5432/sentinel?sslmode=disable" \
    -e BETTER_AUTH_SECRET="$BETTER_AUTH_SECRET" \
    -e OP_EMAIL="$CONSOLE_ADMIN_EMAIL" -e OP_PASS="$CONSOLE_ADMIN_PASS" -e OP_ROLE="${CONSOLE_ADMIN_ROLE:-admin}" \
    -v "$DASH":/app -w /app "$NODE_IMG" \
    bash -c 'corepack enable && pnpm install --frozen-lockfile >/dev/null 2>&1; node scripts/seed-operator.mjs'
  ok "operator ready: $CONSOLE_ADMIN_EMAIL (role ${CONSOLE_ADMIN_ROLE:-admin})"
}

# ---- health probe (from the host, through nginx) --------------------------------------------
health() {
  local port; port="$(get_val HTTP_PORT)"; port="${port:-80}"
  local base="http://localhost:${port}"
  step "HEALTH"
  if ! command -v curl >/dev/null 2>&1; then warn "curl not on host — skipping probe ($base)"; return 0; fi
  local p code
  for p in /healthz /login /api/v1/enroll; do
    printf '  %-18s ' "$p"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${base}${p}" 2>/dev/null || echo FAIL)"
    printf '%s\n' "$code"
  done
  echo "  (expect: /healthz 200, /login 200, /api/v1/enroll 400/401/405 — reachable, rejects empty)"
}

# ---- status ---------------------------------------------------------------------------------
status() {
  step "STATUS"
  docker ps --filter name=sentinel- --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
}

# ---- final summary --------------------------------------------------------------------------
summary() {
  local host port email
  host="$(get_val SENTINEL_HOST)"; port="$(get_val HTTP_PORT)"; email="$(get_val CONSOLE_ADMIN_EMAIL)"
  step "DONE"
  ok  "Sentinel is up at ${host}"
  echo
  echo "  Console     ${host}/login"
  echo "  Login       ${email}"
  echo "  Password    (see CONSOLE_ADMIN_PASS in $ENV_FILE)"
  echo
  echo "  Endpoint install (Linux, over local HTTP):"
  echo "    $(install_cmd_string)"
  echo
  echo "  Manage:  ./deploy.sh status | health | logs | down"
}

install_cmd_string() {
  local host token
  host="$(get_val SENTINEL_HOST)"; token="$(get_val SENTINEL_ENROLL_TOKEN)"
  printf 'curl -fsSL %s/install-agent.sh | sudo SENTINEL_SERVER=%s SENTINEL_ENROLL_TOKEN=%s SENTINEL_ALLOW_INSECURE=1 SENTINEL_REQUIRE_SIGNATURE=0 bash' \
    "$host" "$host" "$token"
}

# ---- full deploy ----------------------------------------------------------------------------
deploy() {
  preflight
  step "ENV"; prepare_env
  step "WEBROOT"; stage_webroot

  step "SERVER (db + nats + server)"
  compose build server
  compose up -d timescaledb nats server
  wait_server

  if [ "${SKIP_BUILD:-0}" = "1" ]; then
    warn "--skip-build: reusing existing sentinel/dashboard:local image"
    docker image inspect sentinel/dashboard:local >/dev/null 2>&1 || die "no dashboard image to reuse — drop --skip-build"
  else
    build_dashboard
  fi
  seed_operator

  step "UP (dashboard + nginx)"
  compose up -d dashboard nginx

  [ "${WITH_AGENT:-0}" = "1" ] && { step "DEMO AGENT"; compose --profile agent up -d agent; ok "demo scenario agent started"; }

  status
  health
  summary
}

# ---- arg parsing ----------------------------------------------------------------------------
HOST_ARG=""; PORT_ARG=""; WITH_AGENT=0; SKIP_BUILD=0
CMD="deploy"
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --host)        HOST_ARG="${2:?--host needs a value}"; shift 2;;
    --port)        PORT_ARG="${2:?--port needs a value}"; shift 2;;
    --with-agent)  WITH_AGENT=1; shift;;
    --skip-build)  SKIP_BUILD=1; shift;;
    -h|--help)     CMD="help"; shift;;
    deploy|up|down|restart|status|health|logs|dashboard|seed|agent|install-cmd|clean|help)
                   CMD="$1"; shift;;
    *)             args+=("$1"); shift;;
  esac
done

case "$CMD" in
  deploy)   deploy;;
  up)       preflight; prepare_env; compose up -d timescaledb nats server; wait_server; compose up -d dashboard nginx; [ "$WITH_AGENT" = 1 ] && compose --profile agent up -d agent; status; health;;
  down)     compose --profile agent down; ok "stopped (data volumes kept)";;
  restart)  compose restart; status;;
  status)   status;;
  health)   health;;
  logs)     compose logs -f --tail=150 "${args[@]:-}";;
  dashboard) preflight; prepare_env; build_dashboard; seed_operator; compose up -d --no-deps --force-recreate dashboard; status;;
  seed)     preflight; seed_operator;;
  agent)    preflight; compose --profile agent up -d agent; ok "demo scenario agent started";;
  install-cmd) install_cmd_string; echo;;
  clean)    compose --profile agent down; docker image prune -f >/dev/null 2>&1 || true; ok "stopped + pruned dangling images (volumes kept)";;
  help|*)   sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//';;
esac
