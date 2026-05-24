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
MEM="${BUILD_MEM:-14g}"

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE"; exit 1; }

echo "==> [1/4] building standalone artifact (capped ${MEM})"
rm -rf "$DASH/.next"
docker run --rm -m "$MEM" -v "$DASH":/app -w /app -e NEXT_TELEMETRY_DISABLED=1 "$NODE_IMG" \
  bash -c 'corepack enable && pnpm install --frozen-lockfile && NODE_OPTIONS=--max-old-space-size=8192 pnpm build'
[ -f "$DASH/.next/standalone/server.js" ] || { echo "build produced no standalone output"; exit 1; }

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
docker build -f "$DASH/Dockerfile.prebuilt" -t sentinel/dashboard:app2 "$DASH"

echo "==> [4/4] recreating dashboard container"
cd "$HERE"
docker compose --env-file .env up -d --no-deps --force-recreate dashboard
docker compose --env-file .env ps dashboard
echo "==> done."
