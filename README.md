<div align="center">

# Sentinel

**Linux Endpoint Detection & Response (EDR) + Data Loss Prevention (DLP)**

Monitor → Detect → Prevent → Respond — across your Linux fleet, from one console.

[![Go](https://img.shields.io/badge/server-Go%201.25-00ADD8?logo=go&logoColor=white)](server/)
[![Rust](https://img.shields.io/badge/agent-Rust-DEA584?logo=rust&logoColor=white)](agent/)
[![Next.js](https://img.shields.io/badge/console-Next.js%2016-000000?logo=nextdotjs&logoColor=white)](dashboard/)
[![TimescaleDB](https://img.shields.io/badge/store-TimescaleDB-FDB515)](https://www.timescale.com/)
[![NATS](https://img.shields.io/badge/bus-NATS%20JetStream-27AAE1?logo=natsdotio&logoColor=white)](https://nats.io/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

</div>

---

Sentinel is a self-hosted endpoint security platform for Linux: a lightweight Rust agent on
every host, a Go control plane that detects and responds to threats, and a real-time Next.js
security-operations console. It captures process / file / network / USB / auth telemetry,
runs Sigma + behavioral + threat-intel detection, classifies and blocks sensitive-data
exfiltration, and executes containment (kill, isolate, quarantine, freeze) — with the whole
pipeline visible live in the console.

## Highlights

| | |
|---|---|
| 🛰️ **Full endpoint telemetry** | process (uid/user, full lineage, container), file integrity, network (PID + bytes + **domain attribution**), USB & removable-mount, auth/SSH, kernel-module load |
| 🔬 **Layered detection** | Sigma rule engine (27+ rules), stateful behavioral correlation (brute-force, exfil-volume, C2 beaconing, USB mass-copy), threat-intel IOC matching (hash/IP/domain) |
| 🛡️ **Data Loss Prevention** | content classification (PCI/SSN/AWS keys/private keys/JWT/source), full PII/PAN masking at source, channel-aware policy verdicts (alert/block) |
| ⚡ **Automated + manual response** | kill process / kill tree (cgroup), network isolate, account disable, USB & upload block, file quarantine, cgroup freeze, live triage — verified, audited, structured-argv (no shell injection) |
| 🕵️ **Rootkit & posture** | hidden-PID detection, `ld.so.preload` tamper, kernel taint, sysctl / lockdown / IMA hardening grading |
| 📟 **SOC console** | real-time SSE stream, paginated sortable DataTables, process-tree view, detail sheets, ⌘K palette, 2FA (TOTP), RBAC |
| 📤 **Integrations** | SIEM export (CEF + ECS), alerting to Slack / Discord (rich embeds) / Email (SMTP) |
| 📈 **Built to scale** | role-split tiers, NATS JetStream durable bus, TimescaleDB hypertables + hierarchical continuous aggregates + tiered retention |

## Architecture

```
   ┌────────── Linux endpoints ──────────┐
   │  Rust agent                          │     enroll + events (HTTPS, token/mTLS)
   │  collectors · DLP · response         │ ───────────────┐         WebSocket commands
   │  AES-256-GCM offline spool + replay  │ ◀──────────────┤              (containment)
   └──────────────────────────────────────┘                │
                                                            ▼
   ┌──────────────────────── Go control plane ─────────────────────────┐
   │  ingest → NATS JetStream → workers (Sigma · DLP · IOC)             │
   │                          → correlator (behavioral)                 │
   │  response orchestration · SIEM export · alerting · RBAC API + WS   │
   │  roles: all | ingest | worker | correlator | gateway              │
   └───────────────┬───────────────────────────────┬──────────────────┘
                   ▼                                 ▼
           TimescaleDB (hypertables,         Next.js console (BFF)
           continuous aggregates)            session-gated /api/proxy + SSE
```

- **Agent** (`agent/`, Rust) — low-overhead userspace collectors with an in-kernel **eBPF**
  tier (foundation in place) and a graceful fallback chain (eBPF → auditd → netlink → poll).
  Encrypted offline spool with poison-file-safe replay; self-protecting (OOM-immune,
  non-dumpable); structured-argv response executor with verification.
- **Server** (`server/`, Go) — single binary, many roles. Decoupled by the NATS event bus and
  control mesh so each tier scales independently.
- **Console** (`dashboard/`, Next.js 16 + shadcn/ui + Tailwind v4 + Better Auth) — the operator
  console; talks to the Go API only through a session-gated Backend-for-Frontend.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SCALING.md`](docs/SCALING.md),
and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Quick start (single node)

```bash
cp .env.example .env            # set SENTINEL_ENROLL_TOKEN + admin pass
make up                         # TimescaleDB + NATS + server + agent, detached
open http://localhost:8080      # console (dev: admin / sentinel-admin)
make logs
```

The stack runs `restart: unless-stopped` (always-on). The bundled agent's `--scenario` mode
injects a realistic multi-stage intrusion so every detection, DLP incident, and automated
response is visible immediately.

```bash
make e2e        # asserts enrollment → ingest → detection → auto-response → SIEM export
```

### Run the operator console (dashboard)

```bash
cd dashboard && pnpm install && pnpm dev   # http://localhost:3000
```

## Install the agent on an endpoint

```bash
curl -fsSL https://<server>/install-agent.sh | \
  sudo SENTINEL_SERVER=https://<server> \
       SENTINEL_ENROLL_TOKEN=<token> \
       SENTINEL_REQUIRE_CHECKSUM=1 bash
```

The installer SHA-256-verifies the downloaded binary and refuses non-HTTPS servers.
See [`docs/AGENT-INSTALL.md`](docs/AGENT-INSTALL.md).

## Security model (summary)

- Console API never exposed publicly — only agent enroll/events + the session-gated BFF.
- Better Auth sessions (`__Secure-` HttpOnly SameSite cookies), per-endpoint RBAC, TOTP 2FA,
  brute-force rate limiting, constant-time secret comparison, no user enumeration.
- AES-256-GCM encrypted spool, TLS 1.2/1.3 only, full PII/PAN masking, injection-safe SIEM/CEF.
- Production config hard-gate (`Validate()`): strong secrets, TLS-or-behind-proxy, origin
  allowlist. NATS token auth; network-segmented control plane.

A full third-party-style penetration test & GRC report lives in
[`docs/security/`](docs/security/) (`PENETRATION-TEST-REPORT.md` + Word doc).

## Build & test

```bash
make test            # Go unit tests + Rust agent tests + dashboard typecheck/build
make build           # build web + server + agent
cd server && go test ./...
cd agent  && cargo test
```

CI runs the test matrix, `govulncheck` / `cargo-audit` / `pnpm audit`, and publishes signed
artifacts (see [`.github/workflows/`](.github/workflows/)).

## Tech stack

| Layer | Tech |
|---|---|
| Agent | Rust · tokio · rustls · sysinfo · aya (eBPF) |
| Server | Go 1.25 · pgx · nats.go · golang-jwt · gorilla/websocket |
| Console | Next.js 16 · React 19 · TypeScript 6 · shadcn/ui · Tailwind v4 · Better Auth · TanStack Table · Recharts · Motion |
| Data | TimescaleDB (PG 16) · NATS JetStream |

## Native development (no full container build)

```bash
make dev-deps        # just TimescaleDB + NATS
make dev-server      # run the Go server (role=all) on :8080
make agent-scenario  # run the agent locally in scenario mode
cd dashboard && pnpm dev
```

## Documentation

| Doc | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | components, data flow, tiers |
| [`docs/AGENT-INSTALL.md`](docs/AGENT-INSTALL.md) | endpoint deployment |
| [`docs/API.md`](docs/API.md) | control-plane + console API |
| [`docs/SCALING.md`](docs/SCALING.md) · [`docs/CAPACITY.md`](docs/CAPACITY.md) | scale-out & capacity (700+ endpoints) |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | STRIDE threat model |
| [`docs/ROADMAP-IMPL.md`](docs/ROADMAP-IMPL.md) | capability roadmap & status |
| [`docs/security/`](docs/security/) | penetration-test & GRC report |

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
