# Threat Model

Primary assets:

- Agent enrollment keys, per-agent keys, JWT signing secret, and operator credentials.
- Endpoint telemetry, DLP findings, response records, and audit logs.
- Response command channel capable of host isolation, account lock, process kill, and USB/upload blocking.

Implemented controls:

- Production config gate requires TLS, strong secrets, non-default admin password, enrollment token, and origin allowlist.
- Console JWTs are issued in HTTP-only same-site cookies; the UI does not persist the token in local storage.
- Agent enrollment and ingest use headers rather than URL query parameters.
- Agent mTLS can be enabled on agent-only routes without breaking the browser console.
- Response commands use structured argv, validated targets, dedicated nftables tables, and local audit logs.
- Agent state, spool, and audit files are written with private permissions on Unix.
- Durable NATS consumers explicitly ack only after successful processing and retry on handler errors.

Residual risks:

- Polling collectors can miss short-lived activity; use auditd/eBPF/fanotify for production fidelity.
- DLP blocking is containment after detection, not full pre-copy/pre-upload prevention.
- Compose files are development references; production should use pinned images, external secrets, NATS auth/TLS, backups, and least-privilege service accounts.
