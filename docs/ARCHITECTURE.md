# Sentinel Architecture

Sentinel has four runtime planes:

- Endpoint agents collect telemetry, classify local content, spool events while offline, and execute response commands.
- Gateways serve REST/WebSocket traffic, authenticate console and agent clients, and bridge agent command channels into the control mesh.
- Workers consume NATS JetStream events, persist telemetry, evaluate Sigma-style rules, run DLP policy, and issue automated responses.
- A single correlator consumes the full stream for stateful behavioral detections.

In single-node mode, one server process runs all roles. In scale-out mode, NATS JetStream carries event traffic and NATS core carries console fan-out plus command routing.

Production TLS layout:

- Browser console: normal HTTPS, JWT stored as an HTTP-only same-site cookie.
- Agent data plane: HTTPS plus per-agent key headers.
- Agent mTLS: when `SENTINEL_TLS_CLIENT_CA` is set, the listener requests client certificates and the API enforces a verified certificate only on `/api/v1/enroll`, `/api/v1/events`, and `/agent/ws`.

Current telemetry is intentionally conservative: process, auth, USB, package, FIM, and network collectors are polling/log based. Kernel-grade audit/eBPF/fanotify and managed-browser telemetry are the next production step for higher fidelity and pre-access enforcement.
