#!/usr/bin/env bash
# Build + migrate + deploy the Sentinel dashboard, bypassing the Docker build cgroup that
# OOM-kills `next build` (exit 137) on this high-RAM host. Steps:
#   1. build the Next.js standalone artifact in a memory-capped `docker run`
#   2. apply Better Auth migrations the same way (reaches timescaledb on sentinel_internal)
#   3. assemble a COPY-only runtime image (Dockerfile.prebuilt) — no in-image build
#   4. recreate the dashboard container with the new image
#
# Run from deploy/app2:  ./build-dashboard.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASH="$(cd "$HERE/../../dashboard" && pwd)"
ENV_FILE="$HERE/.env"
NET="sentinel_internal"
NODE_IMG="node:22-bookworm-slim"
NODE_HEAP="${NODE_HEAP:-8192}"
# No `docker -m` cap here: a cgroup memory cap makes Next 16's per-CPU build workers get
# SIGKILLed under transient pressure (next then exits 1 — NOT a kernel OOM), which is what
# broke this build. The host has ~120g; let the build use what it needs. Set BUILD_MEM to
# re-impose a cap only if a co-tenant needs protecting.
MEM_FLAG=""
[ -n "${BUILD_MEM:-}" ] && MEM_FLAG="-m ${BUILD_MEM}"

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE"; exit 1; }

echo "==> [1/4] building standalone artifact ${MEM_FLAG:-(uncapped)}"
# The build container runs as root, so its .next is root-owned; a plain `rm -rf` by the
# deploying user then fails on the next run. Remove with sudo if needed, and chown the fresh
# output back to the mount owner so subsequent runs (and rsync) stay permission-clean.
rm -rf "$DASH/.next" 2>/dev/null || sudo rm -rf "$DASH/.next"
# Build form matters: `pnpm build` (the npm-script wrapper) intermittently has its `next build`
# worker SIGKILLed on this host, while invoking `pnpm exec next build` directly with the heap
# passed as a real env var (-e NODE_OPTIONS, not an inline prefix) is reliable. Keep this form.
docker run --rm $MEM_FLAG -v "$DASH":/app -w /app \
  -e NEXT_TELEMETRY_DISABLED=1 -e NODE_OPTIONS="--max-old-space-size=$NODE_HEAP" "$NODE_IMG" \
  bash -c 'corepack enable && pnpm install --frozen-lockfile && pnpm exec next build --webpack'
[ -f "$DASH/.next/standalone/server.js" ] || { echo "build produced no standalone output"; exit 1; }
# chown the root-owned build output back to the deploying user in a separate run, so the next
# `rm -rf .next` / rsync don't need sudo.
docker run --rm -v "$DASH":/app -w /app "$NODE_IMG" \
  chown -R "$(id -u):$(id -g)" /app/.next /app/node_modules 2>/dev/null || true

echo "==> [2/4] applying Better Auth migrations"
# Pull the real DATABASE_URL/secret from the running dashboard if present, else from .env.
DBURL="$(docker inspect sentinel-dashboard --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^DATABASE_URL=//p' | head -1)"
SECRET="$(docker inspect sentinel-dashboard --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -n 's/^BETTER_AUTH_SECRET=//p' | head -1)"
if [ -z "${DBURL:-}" ]; then
  # shellcheck disable=SC1090
  set -a; . "$ENV_FILE"; set +a
  DBURL="postgres://sentinel:${PGPW}@timescaledb:5432/sentinel?sslmode=disable"
  SECRET="${BETTER_AUTH_SECRET}"
fi
docker run --rm --network "$NET" -e DATABASE_URL="$DBURL" -e BETTER_AUTH_SECRET="$SECRET" \
  -v "$DASH":/app -w /app "$NODE_IMG" \
  bash -c 'corepack enable && pnpm dlx @better-auth/cli@latest migrate -y'

echo "==> [3/4] building COPY-only runtime image"
# Dockerfile.prebuilt does `COPY public ./public`; ensure the dir exists so the build never
# fails on an app that ships no static assets (an empty public/ is valid for Next standalone).
mkdir -p "$DASH/public"
docker build -f "$DASH/Dockerfile.prebuilt" -t sentinel/dashboard:app2 "$DASH"

echo "==> [4/4] recreating dashboard container"
cd "$HERE"
docker compose --env-file .env up -d --no-deps --force-recreate dashboard
docker compose --env-file .env ps dashboard
echo "==> done."
