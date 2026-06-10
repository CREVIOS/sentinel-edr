# Sentinel EDR — local-server deploy

Run the **entire Sentinel stack on one machine** behind a local nginx — TimescaleDB, NATS, the
Go control plane, the Next.js dashboard, and nginx as the single entry point. Plain HTTP by
default (trusted LAN / localhost); TLS is opt-in.

This mirrors the production `app2` topology but is **self-contained**: nginx runs *inside* the
compose project and publishes one host port — there is no shared host proxy and no public TLS
requirement.

```
                      ┌────────────────────── host port (HTTP_PORT, default 80) ──────────────┐
 browser / agents ───▶│ nginx ─┬─ /            /api/stream   ─▶ dashboard (Next.js :3000)      │
                      │        ├─ /api/v1/enroll /api/v1/events /agent/ws ─▶ server (Go :8080) │
                      │        └─ /install-agent.sh /dl/      ─▶ static ./www                   │
                      └─────────────────────────────────────────────────────────────────────┘
                          server ─▶ TimescaleDB · NATS   |   dashboard ─▶ TimescaleDB (Better Auth)
```

## Quick start

```bash
cd deploy/local
./deploy.sh
```

That's it. The script creates `.env`, **auto-generates every secret**, builds the images,
migrates the database, seeds your console operator, and brings everything up. When it finishes
it prints the console URL, your login, and the endpoint install command.

Log in at `http://localhost/login` as `admin@sentinel.local`; the password is
`CONSOLE_ADMIN_PASS` in `deploy/local/.env`.

### Bind to a LAN address / custom port

```bash
./deploy.sh --host 192.168.1.50 --port 8088
```

`SENTINEL_HOST` (used for CORS + Better Auth) is kept in sync with the host/port automatically.

### Demo telemetry

No real endpoints yet? Start a synthetic scenario agent so the console has data:

```bash
./deploy.sh --with-agent      # or: ./deploy.sh agent
```

## Enrolling real endpoints (Linux)

`deploy.sh` prints the exact command (with the live enroll token). Over local HTTP it is:

```bash
curl -fsSL http://<host>/install-agent.sh | sudo \
  SENTINEL_SERVER=http://<host> \
  SENTINEL_ENROLL_TOKEN=<token> \
  SENTINEL_ALLOW_INSECURE=1 \
  SENTINEL_REQUIRE_SIGNATURE=0 \
  bash
```

`SENTINEL_ALLOW_INSECURE=1` permits HTTP (no TLS); `SENTINEL_REQUIRE_SIGNATURE=0` skips binary
signature verification — both acceptable only on a trusted local network. For anything exposed,
turn on TLS (below) and ship a signed binary.

## Commands

| Command | Does |
|---|---|
| `./deploy.sh` | full deploy (build + migrate + seed + up) |
| `./deploy.sh up` | start the stack (no rebuild of the dashboard image) |
| `./deploy.sh down` | stop + remove containers (**data volumes are kept**) |
| `./deploy.sh restart` | restart all services |
| `./deploy.sh status` | container status table |
| `./deploy.sh health` | probe the public endpoints |
| `./deploy.sh logs [svc]` | tail logs (optionally one service) |
| `./deploy.sh dashboard` | rebuild + migrate + reseed + recreate the dashboard only |
| `./deploy.sh seed` | (re)create the console operator from `.env` |
| `./deploy.sh agent` | start the demo scenario agent |
| `./deploy.sh install-cmd` | print the endpoint install one-liner |
| `./deploy.sh clean` | stop the stack + prune dangling images (volumes kept) |

Flags: `--host`, `--port`, `--with-agent`, `--skip-build` (reuse the existing dashboard image
for a fast redeploy).

## Configuration (`.env`)

Created from [`.env.example`](./.env.example) on first run; `[auto]` keys are generated if left
blank and never overwritten on re-run.

| Key | Purpose |
|---|---|
| `SENTINEL_HOST` | public origin (scheme+host+port) — CORS + Better Auth base URL |
| `HTTP_PORT` | host port nginx publishes |
| `PGPW` `NATS_TOKEN` `SENTINEL_JWT_SECRET` `SENTINEL_ENROLL_TOKEN` `BETTER_AUTH_SECRET` | secrets `[auto]` |
| `SENTINEL_ADMIN_USER` / `SENTINEL_ADMIN_PASS` | Go service account (dashboard BFF ↔ Go API) |
| `CONSOLE_ADMIN_EMAIL` / `CONSOLE_ADMIN_PASS` / `CONSOLE_ADMIN_ROLE` | your console login (seeded operator) |
| `SENTINEL_IOC_FEEDS` | live abuse.ch C2 blocklists (optional; empty = air-gapped) |

Secrets live only in `deploy/local/.env` (git-ignored). The server runs with
`SENTINEL_ENV=production` + `SENTINEL_BEHIND_PROXY=true`, so the production security gates
(strong secrets, origin allow-list) are enforced; nginx terminates the connection so no
server-side TLS cert is required.

## Enable TLS (optional)

1. Put `server.crt` + `server.key` in `deploy/local/certs/`.
2. In `docker-compose.yml`, mount it into nginx (`- ./certs:/etc/nginx/certs:ro`) and publish
   `443`.
3. In `nginx.conf`, swap `listen 80;` for the `listen 443 ssl;` block documented at the top of
   that file.
4. Set `SENTINEL_HOST=https://<host>` and redeploy. Self-signed is fine on a LAN.

## Updating code

Rebuild from the current checkout:

```bash
./deploy.sh            # rebuilds server + dashboard images, recreates containers
# fast path (server changed, dashboard unchanged):
./deploy.sh --skip-build
```

## Requirements

- **Docker Compose v2** (the `docker compose` plugin — note the space). This stack uses
  Compose-spec keys (`name:`, `profiles:`) that legacy `docker-compose` v1 cannot parse.
  On Ubuntu: `sudo apt-get update && sudo apt-get install -y docker-compose-plugin`.

## Troubleshooting

- **`name does not match any of the regexes: '^x-'`** → you're on legacy docker-compose v1.
  Install Compose v2: `sudo apt-get install -y docker-compose-plugin`, then use `docker compose`
  (with a space) / re-run `./deploy.sh`.
- **`server did not report ready`** → `./deploy.sh logs server` (usually a DB/secret issue).
- **Dashboard build fails / OOM** → the build runs out-of-band with a capped Node heap; raise
  it with `NODE_HEAP=8192 ./deploy.sh dashboard`.
- **Can't log in** → re-seed: `./deploy.sh seed` (reads `CONSOLE_ADMIN_*` from `.env`).
- **Port already in use** → `./deploy.sh --port 8088` (or free port 80).
