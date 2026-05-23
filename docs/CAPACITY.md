# Capacity & sizing — running ~700 endpoints

Target: **700 endpoints (agents) monitored together**, plus a handful of SOC operators on the
console. This is comfortably within a small deployment. Numbers below are conservative.

## Load model (700 agents)
| Flow | Rate | Notes |
|---|---|---|
| Ingest requests | ~140 req/s | 700 agents × 1 batch / 5s (`--interval 5`) |
| Events written | ~hundreds–few k/s | real collectors emit modest volume; batched inserts |
| Agent command WebSockets | 700 persistent | one long-lived WS per agent to a gateway |
| Console operators | a few | poll/live-tail via the BFF |
| NATS event messages | = ingest rate | JetStream handles 100k+ msg/s |

A single Go server (`SENTINEL_ROLE=all`) handles this on ~2 vCPU / 4 GB. Go routinely serves
10k+ req/s/core; 140 req/s + 700 idle WebSockets is light. TimescaleDB ingests 100k+ rows/s.

## Recommended topology
**Simple (≤700, fine):** one `all` server + TimescaleDB + NATS (the default `docker-compose.yml`).
Give Postgres 4 vCPU / 8 GB and an SSD volume.

**HA / headroom:** `docker-compose.scale.yml` —
```
docker compose -f docker-compose.scale.yml up -d --scale gateway=2 --scale worker=2
```
- **gateway ×2** — REST/WS + agent ingest behind nginx (spreads the 700 WebSockets)
- **worker ×2** — stateless detection/DLP/persist
- **correlator ×1** — single consumer for consistent behavioral windows

## Tuning knobs
| Setting | Default | For 700 |
|---|---|---|
| `SENTINEL_DB_MAX_CONNS` (per server replica) | 40 | keep `replicas × value` **under** Postgres `max_connections` |
| Postgres `max_connections` | 100 | raise to 200, or front with **PgBouncer** (transaction pooling) |
| Agent `--interval` | 5s | 5–10s; higher interval = fewer requests, slightly less real-time |
| ingest rate limit (per source IP) | 500/s burst 1000 | already ample; behind a proxy set `SENTINEL_TRUSTED_PROXIES` |
| Event retention | 90 days | lower if disk-bound; compression kicks in after 7 days |

> Connection math: in the scaled topology (2 gateway + 2 worker + 1 correlator = 5 replicas),
> set `SENTINEL_DB_MAX_CONNS=18` → 90 total, under a default `max_connections=100`. Or raise
> Postgres / add PgBouncer and keep 40.

## Disk
At ~a few hundred events/s, 90-day retention with compression (≈10×) lands in the low
hundreds of GB. Monitor `events` hypertable size; adjust `add_retention_policy`.

## Verifying capacity
- `GET /metrics` (Prometheus) exposes agent/event/detection/response gauges — scrape and graph.
- Load-test ingest: replay the agent `--scenario` from N hosts, or a small load script POSTing
  batches with valid agent keys, and watch p95 latency + DB CPU.

See `SCALING.md` for query/pagination/streaming performance and `AGENT-INSTALL.md` for fleet
rollout.
