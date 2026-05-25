package store

import (
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/sentinel/server/internal/model"
)

// pgStore is the TimescaleDB (Postgres) backend.
type pgStore struct {
	db    *sql.DB
	caggs bool // true when the events_hourly continuous aggregate exists (TimescaleDB present)
}

func openPostgres(dsn string) (*pgStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// Pool sized for fleet scale; tune per replica with SENTINEL_DB_MAX_CONNS.
	// Total DB connections = (max conns) × (server replicas) — keep under Postgres max_connections.
	maxConns := 40
	if v, err := strconv.Atoi(os.Getenv("SENTINEL_DB_MAX_CONNS")); err == nil && v > 0 {
		maxConns = v
	}
	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns / 2)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &pgStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *pgStore) Close() error { return s.db.Close() }

func (s *pgStore) migrate() error {
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS timescaledb`,
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY, hostname TEXT, os TEXT, kernel TEXT, arch TEXT, ip TEXT, mac TEXT,
			version TEXT, status TEXT, labels JSONB DEFAULT '[]', key TEXT,
			enrolled_at TIMESTAMPTZ, last_seen TIMESTAMPTZ, event_count BIGINT DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS events (
			id TEXT NOT NULL, agent_id TEXT, hostname TEXT, ts TIMESTAMPTZ NOT NULL,
			category TEXT, action TEXT, severity TEXT, "user" TEXT, message TEXT, doc JSONB,
			UNIQUE (id, ts))`,
		`SELECT create_hypertable('events','ts', if_not_exists => TRUE, migrate_data => TRUE)`,
		`CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity, ts DESC)`,
		`CREATE TABLE IF NOT EXISTS detections (
			id TEXT PRIMARY KEY, ts TIMESTAMPTZ, rule_id TEXT, rule_name TEXT, severity TEXT,
			category TEXT, agent_id TEXT, hostname TEXT, "user" TEXT, summary TEXT,
			mitre JSONB, tactic TEXT, status TEXT, engine TEXT, assigned_to TEXT, doc JSONB)`,
		`CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_det_status ON detections(status)`,
		`CREATE TABLE IF NOT EXISTS responses (
			id TEXT PRIMARY KEY, ts TIMESTAMPTZ, type TEXT, agent_id TEXT, hostname TEXT,
			reason TEXT, issued_by TEXT, detection_id TEXT, status TEXT, result TEXT,
			automated BOOLEAN, doc JSONB)`,
		`CREATE INDEX IF NOT EXISTS idx_resp_ts ON responses(ts DESC)`,
		`CREATE TABLE IF NOT EXISTS cases (
			id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT, assigned_to TEXT,
			agent_id TEXT, hostname TEXT, created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ, doc JSONB)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_agent ON cases(agent_id, status)`,
		`CREATE TABLE IF NOT EXISTS suppressions (
			id TEXT PRIMARY KEY, rule_id TEXT, field TEXT, op TEXT, value TEXT,
			created_at TIMESTAMPTZ, expires TIMESTAMPTZ, doc JSONB)`,
		`CREATE TABLE IF NOT EXISTS rule_overrides (
			rule_id TEXT PRIMARY KEY, enabled BOOLEAN, updated_by TEXT, updated_at TIMESTAMPTZ)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			// timescaledb extension / hypertable may be unavailable on a plain Postgres;
			// tolerate those two so the platform still runs, but fail on real schema errors.
			if strings.Contains(q, "timescaledb") || strings.Contains(q, "create_hypertable") {
				continue
			}
			return err
		}
	}
	// Best-effort retention + compression (ignored on plain Postgres).
	_, _ = s.db.Exec(`SELECT add_retention_policy('events', INTERVAL '90 days', if_not_exists => TRUE)`)
	_, _ = s.db.Exec(`ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id', timescaledb.compress_orderby = 'ts DESC')`)
	_, _ = s.db.Exec(`SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE)`)

	// Trigram index so event search hits the message column via an index instead of a full
	// scan + JSONB cast (pg_trgm; best-effort — degrades to a seq scan if unavailable).
	_, _ = s.db.Exec(`CREATE EXTENSION IF NOT EXISTS pg_trgm`)
	_, _ = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_msg_trgm ON events USING gin (message gin_trgm_ops)`)

	// Hourly continuous aggregate: dashboard overview (timeline, per-category, 24h counts)
	// reads pre-materialized rollups instead of scanning 24h of raw events on every poll. With
	// real-time aggregation the current partial hour is still included. Best-effort: on plain
	// Postgres these no-op and the code falls back to raw-table queries (s.caggs stays false).
	_, _ = s.db.Exec(`CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly
		WITH (timescaledb.continuous) AS
		SELECT time_bucket('1 hour', ts) AS bucket, category, count(*) AS n
		FROM events GROUP BY bucket, category WITH NO DATA`)
	// start_offset covers the dashboard's 24h window (+margin) so the whole timeline is
	// materialized; refreshes are incremental, so only changed regions are recomputed.
	_, _ = s.db.Exec(`SELECT add_continuous_aggregate_policy('events_hourly',
		start_offset => INTERVAL '2 days', end_offset => INTERVAL '1 hour',
		schedule_interval => INTERVAL '30 minutes', if_not_exists => TRUE)`)
	_ = s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM timescaledb_information.continuous_aggregates WHERE view_name='events_hourly')`).Scan(&s.caggs)

	// Hierarchical daily rollup (a cagg ON the hourly cagg, TimescaleDB 2.9+). Powers long-range
	// trend/reporting cheaply. Hierarchical caggs can't run concurrent refreshes, so this uses
	// its own hourly schedule that doesn't overlap the 30-min hourly refresh window.
	_, _ = s.db.Exec(`CREATE MATERIALIZED VIEW IF NOT EXISTS events_daily
		WITH (timescaledb.continuous) AS
		SELECT time_bucket('1 day', bucket) AS day, category, sum(n) AS n
		FROM events_hourly GROUP BY day, category WITH NO DATA`)
	_, _ = s.db.Exec(`SELECT add_continuous_aggregate_policy('events_daily',
		start_offset => INTERVAL '30 days', end_offset => INTERVAL '1 day',
		schedule_interval => INTERVAL '1 hour', if_not_exists => TRUE)`)

	// Retention tiers: raw events 90d (set above) → hourly rollup 180d → daily rollup 730d.
	// Old raw data ages out while increasingly-coarse summaries survive for historical analysis.
	_, _ = s.db.Exec(`SELECT add_retention_policy('events_hourly', INTERVAL '180 days', if_not_exists => TRUE)`)
	_, _ = s.db.Exec(`SELECT add_retention_policy('events_daily', INTERVAL '730 days', if_not_exists => TRUE)`)
	return nil
}

func (s *pgStore) UpsertAgent(a *model.Agent) error {
	labels, _ := json.Marshal(a.Labels)
	_, err := s.db.Exec(`INSERT INTO agents (id,hostname,os,kernel,arch,ip,mac,version,status,labels,key,enrolled_at,last_seen,event_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO UPDATE SET hostname=EXCLUDED.hostname, os=EXCLUDED.os, kernel=EXCLUDED.kernel,
		arch=EXCLUDED.arch, ip=EXCLUDED.ip, mac=EXCLUDED.mac, version=EXCLUDED.version, status=EXCLUDED.status,
		labels=EXCLUDED.labels, last_seen=EXCLUDED.last_seen`,
		a.ID, a.Hostname, a.OS, a.Kernel, a.Arch, a.IP, a.MAC, a.Version, a.Status, string(labels), a.Key, a.EnrolledAt, a.LastSeen, a.EventCount)
	return err
}

func (s *pgStore) SetAgentStatus(id string, status model.AgentStatus) error {
	_, err := s.db.Exec(`UPDATE agents SET status=$1 WHERE id=$2`, status, id)
	return err
}

func (s *pgStore) Heartbeat(id string, n int) error {
	_, err := s.db.Exec(`UPDATE agents SET last_seen=$1, event_count=event_count+$2 WHERE id=$3`, time.Now().UTC(), n, id)
	return err
}

func (s *pgStore) GetAgent(id string) (*model.Agent, error) {
	row := s.db.QueryRow(`SELECT id,hostname,os,kernel,arch,ip,mac,version,status,labels,key,enrolled_at,last_seen,event_count FROM agents WHERE id=$1`, id)
	return scanAgentPG(row)
}

func (s *pgStore) ListAgents() ([]*model.Agent, error) {
	rows, err := s.db.Query(`SELECT id,hostname,os,kernel,arch,ip,mac,version,status,labels,key,enrolled_at,last_seen,event_count FROM agents ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Agent
	for rows.Next() {
		a, err := scanAgentPG(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func scanAgentPG(r scanner) (*model.Agent, error) {
	var a model.Agent
	var labels []byte
	if err := r.Scan(&a.ID, &a.Hostname, &a.OS, &a.Kernel, &a.Arch, &a.IP, &a.MAC, &a.Version, &a.Status, &labels, &a.Key, &a.EnrolledAt, &a.LastSeen, &a.EventCount); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(labels, &a.Labels)
	return &a, nil
}

func (s *pgStore) MarkStaleOffline(window time.Duration) error {
	cutoff := time.Now().UTC().Add(-window)
	_, err := s.db.Exec(`UPDATE agents SET status='offline' WHERE status='online' AND last_seen < $1`, cutoff)
	return err
}

func (s *pgStore) InsertEvents(evs []model.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO events (id,agent_id,hostname,ts,category,action,severity,"user",message,doc)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id, ts) DO NOTHING`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range evs {
		doc, _ := json.Marshal(e)
		if _, err := stmt.Exec(e.ID, e.AgentID, e.Hostname, e.TS, e.Category, e.Action, e.Severity, e.User, e.Message, string(doc)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *pgStore) QueryEvents(f EventFilter) ([]model.Event, error) {
	var where []string
	var args []any
	i := 0
	add := func(col string, val any) {
		i++
		where = append(where, col+"=$"+itoa(i))
		args = append(args, val)
	}
	if f.AgentID != "" {
		add("agent_id", f.AgentID)
	}
	if f.Category != "" {
		add("category", f.Category)
	}
	if f.Severity != "" {
		add("severity", f.Severity)
	}
	if f.User != "" {
		add(`"user"`, f.User)
	}
	if f.Search != "" {
		// Search real, indexable columns (message has a trigram GIN index) instead of casting
		// the whole JSONB doc to text per row — the latter is unindexable and scans everything.
		i++
		p := "$" + itoa(i)
		where = append(where, `(message ILIKE `+p+` OR "user" ILIKE `+p+` OR hostname ILIKE `+p+` OR action ILIKE `+p+`)`)
		args = append(args, "%"+f.Search+"%")
	}
	if f.Since != nil {
		i++
		where = append(where, "ts >= $"+itoa(i))
		args = append(args, *f.Since)
	}
	q := "SELECT doc FROM events"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY ts DESC" + limitOffset(f.Limit, f.Offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEventsPG(rows)
}

func scanEventsPG(rows *sql.Rows) ([]model.Event, error) {
	var out []model.Event
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var e model.Event
		if json.Unmarshal(doc, &e) == nil {
			out = append(out, e)
		}
	}
	return out, rows.Err()
}

func (s *pgStore) InsertDetection(d *model.Detection) error {
	doc, _ := json.Marshal(d)
	mitre, _ := json.Marshal(d.MITRE)
	_, err := s.db.Exec(`INSERT INTO detections
		(id,ts,rule_id,rule_name,severity,category,agent_id,hostname,"user",summary,mitre,tactic,status,engine,assigned_to,doc)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, assigned_to=EXCLUDED.assigned_to, doc=EXCLUDED.doc`,
		d.ID, d.TS, d.RuleID, d.RuleName, d.Severity, d.Category, d.AgentID, d.Hostname, d.User, d.Summary,
		string(mitre), d.Tactic, d.Status, d.Engine, d.AssignedTo, string(doc))
	return err
}

func (s *pgStore) ListDetections(limit int, status string) ([]model.Detection, error) {
	q := "SELECT doc FROM detections"
	var args []any
	if status != "" {
		q += " WHERE status=$1"
		args = append(args, status)
	}
	q += " ORDER BY ts DESC" + limitOffset(limit, 0)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDetectionsPG(rows)
}

func scanDetectionsPG(rows *sql.Rows) ([]model.Detection, error) {
	var out []model.Detection
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var d model.Detection
		if json.Unmarshal(doc, &d) == nil {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

func (s *pgStore) GetDetection(id string) (*model.Detection, error) {
	var doc []byte
	if err := s.db.QueryRow(`SELECT doc FROM detections WHERE id=$1`, id).Scan(&doc); err != nil {
		return nil, err
	}
	var d model.Detection
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *pgStore) UpdateDetectionStatus(id string, status model.DetectionStatus, assignee string) error {
	d, err := s.GetDetection(id)
	if err != nil {
		return err
	}
	d.Status = status
	if assignee != "" {
		d.AssignedTo = assignee
	}
	return s.InsertDetection(d)
}

func (s *pgStore) InsertResponse(r *model.ResponseAction) error {
	doc, _ := json.Marshal(r)
	_, err := s.db.Exec(`INSERT INTO responses
		(id,ts,type,agent_id,hostname,reason,issued_by,detection_id,status,result,automated,doc)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, result=EXCLUDED.result, doc=EXCLUDED.doc`,
		r.ID, r.TS, r.Type, r.AgentID, r.Hostname, r.Reason, r.IssuedBy, r.DetectionID, r.Status, r.Result, r.Automated, string(doc))
	return err
}

func (s *pgStore) GetResponse(id string) (*model.ResponseAction, error) {
	var doc []byte
	if err := s.db.QueryRow(`SELECT doc FROM responses WHERE id=$1`, id).Scan(&doc); err != nil {
		return nil, err
	}
	var r model.ResponseAction
	if err := json.Unmarshal(doc, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *pgStore) ListResponses(limit int) ([]model.ResponseAction, error) {
	rows, err := s.db.Query(`SELECT doc FROM responses ORDER BY ts DESC` + limitOffset(limit, 0))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ResponseAction
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var r model.ResponseAction
		if json.Unmarshal(doc, &r) == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// ---------- cases ----------

func (s *pgStore) InsertCase(c *model.Case) error {
	doc, _ := json.Marshal(c)
	_, err := s.db.Exec(`INSERT INTO cases
		(id,title,severity,status,assigned_to,agent_id,hostname,created_at,updated_at,doc)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, severity=EXCLUDED.severity,
		status=EXCLUDED.status, assigned_to=EXCLUDED.assigned_to, updated_at=EXCLUDED.updated_at,
		doc=EXCLUDED.doc`,
		c.ID, c.Title, c.Severity, c.Status, c.AssignedTo, c.AgentID, c.Hostname,
		c.CreatedAt, c.UpdatedAt, string(doc))
	return err
}

func (s *pgStore) GetCase(id string) (*model.Case, error) {
	var doc []byte
	if err := s.db.QueryRow(`SELECT doc FROM cases WHERE id=$1`, id).Scan(&doc); err != nil {
		return nil, err
	}
	var c model.Case
	if err := json.Unmarshal(doc, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *pgStore) ListCases(limit int, status string) ([]model.Case, error) {
	q := "SELECT doc FROM cases"
	var args []any
	if status != "" {
		q += " WHERE status=$1"
		args = append(args, status)
	}
	q += " ORDER BY updated_at DESC" + limitOffset(limit, 0)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Case
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var c model.Case
		if json.Unmarshal(doc, &c) == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// ---------- detection tuning ----------

func (s *pgStore) ListSuppressions() ([]model.Suppression, error) {
	rows, err := s.db.Query(`SELECT doc FROM suppressions ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Suppression
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var sp model.Suppression
		if json.Unmarshal(doc, &sp) == nil {
			out = append(out, sp)
		}
	}
	return out, rows.Err()
}

func (s *pgStore) InsertSuppression(sp *model.Suppression) error {
	doc, _ := json.Marshal(sp)
	_, err := s.db.Exec(`INSERT INTO suppressions (id,rule_id,field,op,value,created_at,expires,doc)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET rule_id=EXCLUDED.rule_id, field=EXCLUDED.field,
		op=EXCLUDED.op, value=EXCLUDED.value, expires=EXCLUDED.expires, doc=EXCLUDED.doc`,
		sp.ID, sp.RuleID, sp.Field, sp.Op, sp.Value, sp.CreatedAt, sp.Expires, string(doc))
	return err
}

func (s *pgStore) DeleteSuppression(id string) error {
	_, err := s.db.Exec(`DELETE FROM suppressions WHERE id=$1`, id)
	return err
}

func (s *pgStore) ListRuleOverrides() ([]model.RuleOverride, error) {
	rows, err := s.db.Query(`SELECT rule_id,enabled,updated_by,updated_at FROM rule_overrides`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RuleOverride
	for rows.Next() {
		var o model.RuleOverride
		if err := rows.Scan(&o.RuleID, &o.Enabled, &o.UpdatedBy, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *pgStore) SetRuleOverride(o *model.RuleOverride) error {
	_, err := s.db.Exec(`INSERT INTO rule_overrides (rule_id,enabled,updated_by,updated_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (rule_id) DO UPDATE SET enabled=EXCLUDED.enabled,
		updated_by=EXCLUDED.updated_by, updated_at=EXCLUDED.updated_at`,
		o.RuleID, o.Enabled, o.UpdatedBy, o.UpdatedAt)
	return err
}

func (s *pgStore) Counts() (map[string]int, error) {
	out := map[string]int{}
	// Agents: all three counts in one round-trip via FILTER (was 3 queries).
	var aTotal, aOnline, aIso int
	if err := s.db.QueryRow(`SELECT count(*),
		count(*) FILTER (WHERE status='online'),
		count(*) FILTER (WHERE status='isolated') FROM agents`).Scan(&aTotal, &aOnline, &aIso); err != nil {
		return nil, err
	}
	out["agents_total"], out["agents_online"], out["agents_isolated"] = aTotal, aOnline, aIso

	// Detections: both counts in one round-trip (was 2 queries).
	var dOpen, dCrit int
	if err := s.db.QueryRow(`SELECT count(*) FILTER (WHERE status='open'),
		count(*) FILTER (WHERE severity='critical' AND status='open') FROM detections`).Scan(&dOpen, &dCrit); err != nil {
		return nil, err
	}
	out["detections_open"], out["detections_critical"] = dOpen, dCrit

	var rTotal int
	if err := s.db.QueryRow(`SELECT count(*) FROM responses`).Scan(&rTotal); err != nil {
		return nil, err
	}
	out["responses_total"] = rTotal

	// Events 24h + DLP 24h in one round-trip. From the hourly continuous aggregate when present
	// (cheap pre-materialized rollup) instead of scanning 24h of raw events on every poll.
	var ev24, dlp24 int
	q := `SELECT count(*), count(*) FILTER (WHERE category='dlp') FROM events WHERE ts >= NOW() - INTERVAL '24 hours'`
	if s.caggs {
		q = `SELECT COALESCE(sum(n),0)::bigint, COALESCE(sum(n) FILTER (WHERE category='dlp'),0)::bigint
			FROM events_hourly WHERE bucket >= NOW() - INTERVAL '24 hours'`
	}
	if err := s.db.QueryRow(q).Scan(&ev24, &dlp24); err != nil {
		return nil, err
	}
	out["events_24h"], out["dlp_24h"] = ev24, dlp24
	return out, nil
}

func (s *pgStore) SeverityBreakdown() (map[string]int, error) {
	return s.groupCount(`SELECT severity, COUNT(*) FROM detections WHERE status!='closed' GROUP BY severity`)
}

func (s *pgStore) EventsPerCategory() (map[string]int, error) {
	if s.caggs {
		return s.groupCount(`SELECT category, sum(n)::bigint FROM events_hourly WHERE bucket>=NOW() - INTERVAL '24 hours' GROUP BY category`)
	}
	return s.groupCount(`SELECT category, COUNT(*) FROM events WHERE ts>=NOW() - INTERVAL '24 hours' GROUP BY category`)
}

func (s *pgStore) groupCount(q string, args ...any) (map[string]int, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

func (s *pgStore) EventTimeline() ([]map[string]any, error) {
	q := `SELECT to_char(date_trunc('hour', ts) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:00:00"Z"') AS hour, COUNT(*)
		FROM events WHERE ts>=NOW() - INTERVAL '24 hours' GROUP BY 1 ORDER BY 1`
	if s.caggs {
		q = `SELECT to_char(bucket AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:00:00"Z"') AS hour, sum(n)::bigint
			FROM events_hourly WHERE bucket>=NOW() - INTERVAL '24 hours' GROUP BY bucket ORDER BY bucket`
	}
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var hour string
		var n int
		if err := rows.Scan(&hour, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"hour": hour, "count": n})
	}
	return out, rows.Err()
}

func (s *pgStore) TopMitre(limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT tactic, COUNT(*) n FROM detections WHERE tactic!='' GROUP BY tactic ORDER BY n DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var tactic string
		var n int
		if err := rows.Scan(&tactic, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"tactic": tactic, "count": n})
	}
	return out, rows.Err()
}

// itoa avoids importing strconv just for placeholder numbers.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
