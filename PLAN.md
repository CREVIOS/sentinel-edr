# Sentinel — Linux Endpoint Monitoring, EDR & DLP Platform

> Centralized platform to **Monitor → Detect → Prevent → Respond** across Linux endpoints.

This document is the master plan and an **honest status tracker**. It maps every requirement
in `task.md` to a component and states plainly what is *implemented and verified* versus what
is *production roadmap*. No capability is claimed that the code does not deliver.

---

## 1. Objective (from task.md)

A centralized enterprise platform to monitor, detect, control, and respond to activity across
Linux endpoints: full endpoint visibility, data-leak prevention, suspicious-behavior detection,
and automated security response.

---

## 2. Architecture

```
Rust agents (TLS/mTLS) ──HTTPS batch──▶ Ingest API (Go, stateless, N replicas)
                                              │ publish
                                              ▼
                                        NATS JetStream (durable event bus)
                                              │ consume
                       ┌──────────────────────┴───────────────────────┐
                       ▼ (queue group, scales out)                     ▼ (single consumer)
            Processors: Sigma detect · DLP · persist · auto-respond   Correlator: behavioral
                       │                         │                      │
                       ▼                         ▼                      ▼
               TimescaleDB (hypertables)   NATS control mesh      (windowed detections)
                                                  │
 Console (React, embedded) ◀──WS/REST── Gateway ◀┘  ── syslog/CEF/ECS ▶ external SIEM
```

- **One binary, `--role/SENTINEL_ROLE all|ingest|worker|correlator|gateway`** — scale each tier.
- **Backends:** Store = TimescaleDB only. Bus = NATS JetStream (or in-process memory for `all`).
  Control plane = in-process hub (`all`) or NATS core mesh (scaled).
- **Agent:** Rust. Collectors, local DLP, AES-256-GCM offline spool with replay, response executor.

See `docs/ARCHITECTURE.md` and `docs/RESEARCH.md`.

---

## 3. Requirement → status

Legend: ☑ implemented & tested · ◐ implemented (polling/baseline; kernel-grade path on roadmap) · ☐ roadmap

### 3.1 Endpoint Monitoring
| Requirement | Component | Status |
|---|---|---|
| Login/logout | agent auth-log + `who` collectors | ☑ |
| SSH & privileged access | agent auth-log collector (sshd, sudo) | ☑ |
| Command execution / process activity | agent process collector (snapshot diff) | ◐ (eBPF/auditd execve = roadmap) |
| File access/modify/delete | agent FIM (walk + sha256 + content DLP) | ◐ (fanotify/inotify real-time = roadmap) |
| System config / package changes | agent package collector (dpkg/rpm/brew/pacman) | ☑ |
| USB / external device | agent USB collector (sysfs/system_profiler) | ☑ |
| MAC / host identity | agent identity (MAC, IP, arch, kernel, OS) | ☑ |

### 3.2 EDR
| Requirement | Component | Status |
|---|---|---|
| Malware / suspicious behavior | Sigma rules + 18 rule packs | ☑ |
| Privilege escalation | rule packs (pkexec, setuid, sudo) | ☑ |
| Abnormal chains / persistence | rules (cron/systemd/rc/authkeys) + parent lineage | ☑ |
| Compromise IOCs | rules + FIM correlation | ☑ |
| Behavioral + rule-based | Sigma engine + behavioral correlator (brute-force, exfil, beaconing, USB mass-copy) | ☑ |

### 3.3 DLP
| Requirement | Component | Status |
|---|---|---|
| Identify sensitive data | classifiers: PCI(Luhn), SSN, AWS, private key, JWT, token(entropy), source | ☑ |
| Monitor transfers/movement | agent file/usb/network events + server DLP | ☑ |
| Detect unauthorized copy/exfil | DLP policy + behavioral volume/USB-copy | ☑ |
| SCP/rsync/FTP/USB/cloud channels | channel classification + policy table | ☑ |
| Content inspection & enforcement | local pre-egress scan + server policy verdict (audit/alert/block) | ◐ (block via nft/USBGuard; full pre-copy interception = roadmap) |

### 3.4 Internet & Browser
| Requirement | Component | Status |
|---|---|---|
| Websites visited / browsing | network collector + domain categorization | ◐ (tested `ss`/`lsof` connection parser; DNS/eBPF + browser extension = roadmap) |
| Downloads / uploads | bytes in/out per connection | ◐ |
| Webmail / cloud usage | category classification (gmail/drive/dropbox…) | ☑ |
| Restrict unauthorized sites | response: block_upload (nft egress) | ◐ (per-domain proxy policy = roadmap) |
| Suspicious internet activity | rules (miner pools, Tor/.onion) + beaconing | ☑ |

### 3.5 Central Visibility & Response
| Requirement | Component | Status |
|---|---|---|
| Centralize logs/events | ingest → bus → TimescaleDB | ☑ |
| SIEM dashboards & correlation | console + CEF/ECS export | ☑ |
| Alerts | detections + WS push + toasts | ☑ |
| Kill process | response executor (`kill -9`, structured) | ☑ |
| Block upload | nftables egress table + verification | ☑ (Linux) |
| Isolate endpoint | dedicated nftables table + verification | ☑ (Linux) |
| Disable account/session | `usermod --lock` + `pkill -u`, validated | ☑ (Linux) |

> Response actions are real OS operations on Linux with NET_ADMIN/root; on non-Linux hosts the
> agent reports an honest "unsupported" result rather than faking success. Every action is
> written to a local audit log and a server-side response record.

---

## 4. Security posture (implemented)
- Production gate: `SENTINEL_ENV=production` refuses to start without TLS, strong JWT secret,
  non-default admin password, enrollment token, and an origin allowlist (`config.Validate`).
- Console auth: bcrypt creds, HS256 JWT (12h), RBAC (admin > analyst > viewer), per-IP rate limit.
- Agent auth: per-agent key in **headers** (never URL); console WS token via `Sec-WebSocket-Protocol`.
- mTLS-ready: server requests client certs at TLS handshake and enforces verified certs on agent routes when `SENTINEL_TLS_CLIENT_CA` is set; agents support `SENTINEL_AGENT_TLS_*`.
- WebSocket origins restricted to same-origin (or explicit allowlist) by default.
- Parameterized SQL; idempotent ingest (`ON CONFLICT DO NOTHING`); offline spool encrypted at rest.
- Response actions use structured argv (no shell interpolation), validated targets, dedicated
  firewall chains (no global flush), and audit records.

See `docs/THREAT_MODEL.md`.

---

## 5. Implemented vs roadmap (no overstatement)

**Implemented & verified**
- Go server: ingest, Sigma detect, DLP, behavioral correlation, response orchestration, SIEM
  export, RBAC/JWT, metrics, WS hub, NATS bus + mesh, TimescaleDB store. Unit tests for
  detect/dlp/behavior + rule validation.
- Rust agent: identity (MAC etc.), collectors (process, auth-log, login, FIM+DLP, USB, package,
	  network), local DLP, AES-256-GCM offline spool with replay, response executor with real Linux
	  enforcement + verification + audit, scenario test harness.
- React console: Overview (charts), Endpoints, Events, Detections, DLP, Internet, Responses,
  Rules, SIEM/Settings — real-time over WebSocket, embedded into the server binary.
- Deployment: Docker Compose (TimescaleDB, NATS, server, agent), Dockerfiles, Makefile, scripts,
  systemd unit, `.env.example`.

**Production roadmap (documented, not claimed as done)**
- Kernel-grade telemetry: eBPF / auditd (execve, sudo), fanotify (real-time blockable file access),
	  DNS/conntrack visibility — current collectors are polling/log-based.
- Browser extension / managed-browser telemetry for full URL + upload/download capture.
- DB migrations tool (currently idempotent auto-DDL), per-tenant retention, dead-letter queue.
- Helm chart, CI pipelines, signed agent releases & auto-update.
- Full pre-copy DLP interception (vs detect-then-block) and per-domain web proxy policy.

---

## 6. Run
- **Dev / single node:** `make up` (TimescaleDB + NATS + server `all`) then `make agent-scenario`.
- **Verify:** `make test` (Go + Rust + web build checks) and `make e2e` (end-to-end scenario assertions).
- **Scale:** `docker compose -f docker-compose.yml -f docker-compose.scale.yml up -d`.

See `README.md`.
