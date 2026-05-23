# Sentinel Console (Next.js 16)

Production console for the Sentinel platform: **Next.js 16 (App Router, Turbopack) · shadcn/ui ·
Tailwind v4 · Better Auth · Recharts**. Aurora-indigo theme, collapsible sidebar, real-time
(polling) data, dark by default.

## How it fits

```
Browser ──(Better Auth session cookie)──▶ Next.js 16 (this app)
                                              │  BFF: /api/proxy/* (session-gated)
                                              ▼  (server-side, holds Go service token)
                                        Go control plane (:8080)  ── TimescaleDB · NATS
```

- **Auth:** Better Auth (email + password) at `/api/auth/*`, sessions in HTTP-only cookies,
  users + sessions in Postgres. The browser never holds Go credentials.
- **Data:** the Next server is a backend-for-frontend — `/api/proxy/[...]` verifies the Better
  Auth session, then forwards to the Go API with a short-lived Go JWT minted from a service
  account. Client pages poll the proxy for near-real-time updates.

## Run (dev)

```bash
# Postgres reachable (shared with the platform) + Go server up on :8080
pnpm install
pnpm dlx @better-auth/cli@latest migrate -y   # create Better Auth tables (once)
pnpm dev                                        # http://localhost:3000
```

First visit seeds the bootstrap admin (`/api/bootstrap`).
Login: **admin@sentinel.local / sentinel-admin** (dev defaults — change via env).

## Environment (`.env.local`)

| Var | Purpose |
|---|---|
| `DATABASE_URL` | Postgres for Better Auth tables |
| `BETTER_AUTH_SECRET` | Better Auth signing secret |
| `BETTER_AUTH_URL` | this app's base URL |
| `GO_API` | Go control-plane base URL (e.g. http://localhost:8080) |
| `GO_ADMIN_USER` / `GO_ADMIN_PASS` | service account the BFF uses for the Go API |
| `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASS` | bootstrap operator |

## Pages
Overview (charts) · Endpoints (MAC/IP/arch + isolate/block actions) · Event Stream ·
Detections (triage + respond) · Data Loss (DLP) · Internet/Web · Response · Detection Rules ·
SIEM/Settings (CEF/ECS export).

All UI is built from native shadcn/ui components (`components/ui`).
