# API

Console API:

- `POST /api/v1/login` returns JSON for API clients and sets an HTTP-only session cookie for the web console.
- `POST /api/v1/logout` clears the session cookie.
- `GET /api/v1/agents`, `/events`, `/detections`, `/responses`, `/rules`, `/stats/overview`.
- `POST /api/v1/detections/{id}/status`.
- `POST /api/v1/respond`.
- `GET /api/v1/siem/export?kind=events|detections&format=cef|ecs`.
- `GET /ws` streams live console updates. It accepts a bearer WebSocket subprotocol token or the session cookie.

Agent API:

- `POST /api/v1/enroll` with `X-Enroll-Token`.
- `POST /api/v1/events` with `X-Agent-Id` and `X-Agent-Key`.
- `GET /agent/ws` with `X-Agent-Id` and `Authorization: Bearer <agent-key>`.

When `SENTINEL_TLS_CLIENT_CA` is configured, all agent API routes also require a verified client certificate.
