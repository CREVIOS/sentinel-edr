# Sentinel — Linux Endpoint Monitoring, EDR & DLP Platform

A centralized platform to **Monitor → Detect → Prevent → Respond** across Linux endpoints:
endpoint visibility, EDR detections, data-loss prevention, internet/browser monitoring,
centralized SIEM-ready logging, and automated response.

- **Agent** — Rust. Low-overhead collectors, local DLP, AES-256-GCM encrypted offline spool
  with replay, real response executor (kill / isolate / disable / block) with verification.
- **Server** — Go. Stateless ingest, Sigma detection engine, DLP engine, behavioral
  correlator, response orchestration, SIEM export, RBAC console API + WebSocket. One binary,
  many roles (`all` / `ingest` / `worker` / `correlator` / `gateway`).
- **Console (`dashboard/`)** — Next.js 16 + shadcn/ui + Tailwind v4 + **Better Auth**. Primary
  operator console: aurora-indigo theme, collapsible sidebar, real-time tail, pagination,
  detail sheets, RBAC. Talks to the Go API through a session-gated BFF (`/api/proxy`).
- **Embedded console (`web/`)** — React + Vite, dark "tactical" theme, embedded in the Go
  binary for a zero-dependency single-binary deploy.
- **Data plane** — TimescaleDB (hypertables) + NATS JetStream (durable event bus) + NATS core
  (control mesh).

> Read [`PLAN.md`](PLAN.md) for the requirement-by-requirement status (implemented vs roadmap)
> and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security posture. Nothing here is
> claimed that the code does not do.

---

## Quick start (single node, always-on)

```bash
cp .env.example .env          # set SENTINEL_ENROLL_TOKEN (and admin pass)
make up                       # TimescaleDB + NATS + server + agent (scenario), detached
open http://localhost:8080    # admin / sentinel-admin (dev default)
make logs                     # watch the pipeline
```

`make up` runs everything with `restart: unless-stopped`, so the stack stays up across
crashes and reboots. The bundled agent runs in `--scenario` mode, generating a realistic
multi-stage intrusion so every detection, DLP incident, and automated response is visible
immediately.

### Verify end-to-end

```bash
make e2e        # asserts enrollment → ingest → detection → auto-response → SIEM export
make test       # Go, Rust, and console build checks
```

---

## Native development (no full container build)

```bash
make dev-deps        # just TimescaleDB + NATS
make dev-server      # run the Go server (role=all) on :8080
make agent-scenario  # run the Rust agent against localhost in scenario mode
```

A real (non-scenario) agent on this host:

```bash
cd agent && cargo run -- --server http://localhost:8080 --enroll-token devtoken \
  --watch /etc,/usr/local/bin,$HOME
```

---

## Horizontal scale-out

```bash
docker compose -f docker-compose.scale.yml up -d --scale gateway=3 --scale worker=4
```

- **gateway** (N): REST + WebSocket + agent ingest, bridges the NATS control mesh.
- **worker** (M): consume the event bus — Sigma + DLP + persist + auto-response.
- **correlator** (1): stateful behavioral correlation over the full stream.
- **nginx**: single entry point / load balancer on `:8080`.

Stateless tiers scale freely; the correlator is a single consumer so windowed state
(brute-force, exfiltration volume, beaconing) stays consistent. See `docs/ARCHITECTURE.md`.

---

## Production hardening

Set `SENTINEL_ENV=production`. The server then **refuses to start** unless:

- `SENTINEL_JWT_SECRET` (≥32 chars), `SENTINEL_ENROLL_TOKEN`, and a non-default
  `SENTINEL_ADMIN_PASS` are set;
- TLS is configured (`SENTINEL_TLS_CERT`, `SENTINEL_TLS_KEY`);
- `SENTINEL_ALLOW_ORIGINS` restricts console origins.

Enable mutual TLS for agents with `SENTINEL_TLS_CLIENT_CA`. Agents must be started with
`SENTINEL_AGENT_TLS_CA`, `SENTINEL_AGENT_TLS_CERT`, and `SENTINEL_AGENT_TLS_KEY`. Generate a
dev PKI with `make tls`. Install the agent as a service with `deploy/sentinel-agent.service`.

---

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_ENV` | `development` | `production` enforces hard security gates |
| `SENTINEL_ROLE` | `all` | `all` / `ingest` / `worker` / `correlator` / `gateway` |
| `SENTINEL_HTTP_ADDR` | `:8080` | listen address |
| `SENTINEL_DATABASE_URL` | postgres://… | TimescaleDB DSN |
| `SENTINEL_NATS_URL` | _(empty)_ | NATS URL; empty = in-process bus (`all` only) |
| `SENTINEL_ENROLL_TOKEN` | _(random in dev)_ | shared agent enrollment secret |
| `SENTINEL_JWT_SECRET` | _(random in dev)_ | console JWT signing key |
| `SENTINEL_ADMIN_USER/PASS` | admin / sentinel-admin | bootstrap console account |
| `SENTINEL_TLS_CERT/KEY/CLIENT_CA` | _(none)_ | TLS / mTLS |
| `SENTINEL_ALLOW_ORIGINS` | same-origin | console origin allowlist |
| `SENTINEL_TRUSTED_PROXIES` | _(empty)_ | CIDR/IP list allowed to set `X-Forwarded-For` |
| `SENTINEL_RULES_DIR` | `rules` | Sigma rule directory |

Agent flags: `--server --enroll-token --watch --interval --labels --scenario --enforce`
plus `--tls-ca --tls-cert --tls-key` for mTLS.

---

## Repository layout

```
agent/      Rust endpoint agent (collectors, DLP, spool, responder, scenario)
server/     Go control plane (api, ingest, detect, dlp, behavior, respond, siem, store, bus, mesh)
server/rules/  Sigma-style YAML detection rules (MITRE ATT&CK mapped)
dashboard/  Next.js 16 + shadcn console (Better Auth, BFF to the Go API) — primary UI
web/        React + Vite console (embedded into the server at build time)
deploy/     nginx LB config, systemd unit
scripts/    e2e test, TLS generator, agent installer
docs/       ARCHITECTURE, RESEARCH, API, THREAT_MODEL, SCALING, CAPACITY, AGENT-INSTALL
```

## Run the Next.js console (dashboard/)

```bash
cd dashboard
pnpm install
pnpm dlx @better-auth/cli@latest migrate -y   # create Better Auth tables (once)
pnpm dev                                        # http://localhost:3000
```
Requires the Go API on `:8080` and Postgres reachable. See `dashboard/README.md`.

## License
Apache-2.0.
