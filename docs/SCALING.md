# Scaling, query performance & real-time (how Sentinel handles logs at volume)

How the platform stays fast, accurate and searchable as event volume grows — and how that
maps to the patterns Grafana/Loki, ClickHouse and large observability stacks use.

## 1. Storage — time-partitioned, compressed, pre-aggregated
- **TimescaleDB hypertables** partition `events` by time (`ts`). Queries with a time range
  touch only the relevant chunks (chunk exclusion) — the same idea as Loki's per-stream chunks
  and ClickHouse's `MergeTree` partitions.
- **Compression** after 7 days (`compress_segmentby=agent_id`) and **retention** at 90 days keep
  the hot set small and fast. Old data is columnar-compressed (≈10×), like ClickHouse columns.
- **Continuous aggregates (roadmap, recommended):** the Overview's hourly counts /
  severity / category / tactic rollups should be materialized views refreshed incrementally,
  so dashboards read pre-aggregated rows instead of scanning raw events — Grafana dashboards do
  the same with recording rules / downsampled series.

## 2. Indexes — match every access path
Already created by the store migration:
- `events(ts DESC)` — time tail / range scans
- `events(agent_id, ts DESC)`, `events(category, ts DESC)`, `events(severity, ts DESC)` —
  filtered tails without a full scan
**Search recommendation:** add a `pg_trgm` GIN index for fast `ILIKE`:
```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX idx_events_msg_trgm ON events USING gin (message gin_trgm_ops);
-- or full-text:
ALTER TABLE events ADD COLUMN tsv tsvector
  GENERATED ALWAYS AS (to_tsvector('simple', coalesce(message,''))) STORED;
CREATE INDEX idx_events_tsv ON events USING gin (tsv);
```
At extreme free-text scale, mirror events to **OpenSearch/Elastic** (the SIEM export already
emits ECS) and run text search there — the classic "DB for structured, search engine for text"
split.

## 3. Pagination — keyset, not OFFSET
- The console paginates with a **`since` cursor** for the live tail (only rows newer than the
  newest seen — tiny payloads) and pages history with bounded `limit`.
- **Keyset pagination** on `(ts, id)` is the scalable history pattern (constant cost regardless
  of depth), vs `OFFSET` which degrades linearly. Server cursor:
  ```sql
  SELECT ... FROM events
  WHERE ts < $cursor_ts OR (ts = $cursor_ts AND id < $cursor_id)
  ORDER BY ts DESC, id DESC LIMIT $n;
  ```
  This is exactly how Grafana Explore / Loki page backwards through time.

## 4. Real-time — incremental tail now, streaming at scale
- **Now:** the console live-tails with a `since`-cursor poll every ~2s — small, accurate,
  robust, dedup-by-id. Near-real-time with minimal load.
- **At scale:** server-side **filtered streaming** (WebSocket/SSE) — the agent→ingest→NATS
  pipeline already streams; expose a filtered live-tail subscription (like Loki `/tail`) so the
  browser receives only matching rows instead of polling. Fan-out across console replicas via
  the NATS control mesh.

## 5. Ingest — backpressure & idempotency
- **NATS JetStream** decouples ingest from processing and provides durable buffering +
  backpressure (`MaxAckPending`) under bursts — like Kafka in large pipelines.
- **Batched, idempotent inserts** (`ON CONFLICT (id, ts) DO NOTHING`) make agent spool replays
  safe and keep write amplification low.
- Stateless **ingest/worker** tiers scale horizontally behind the queue group; the **correlator**
  is a single consumer for consistent windows (shard by `hash(agent)` to scale that tier).

## 6. Console — keep the client cheap
- Incremental live-tail (delta payloads), debounced search (no query spam), "Load older"
  keyset pagination, hard client-side caps, and `tabular-nums` to avoid layout thrash.
- **Roadmap:** list virtualization (render only visible rows) for 10k+ row views — the same
  technique Grafana's logs panel uses.

## Summary mapping
| Concern | Sentinel | Equivalent in Grafana/Loki/ClickHouse |
|---|---|---|
| Time partitioning | Timescale hypertable chunks | Loki chunks / CH partitions |
| Compression + retention | Timescale policies | CH codecs / Loki object store TTL |
| Dashboard rollups | continuous aggregates (roadmap) | recording rules / downsampling |
| History paging | keyset on (ts,id) | Explore backward paging |
| Live tail | `since` cursor → streaming | Loki `/tail` |
| Free-text search | pg_trgm/tsvector → OpenSearch | Loki label+grep / ES |
| Ingest buffering | NATS JetStream | Kafka |
