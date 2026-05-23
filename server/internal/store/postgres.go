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
	db *sql.DB
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
	_, _ = s.db.Exec(`ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id')`)
	_, _ = s.db.Exec(`SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE)`)
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
		i++
		where = append(where, "(message ILIKE $"+itoa(i)+" OR doc::text ILIKE $"+itoa(i)+")")
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

func (s *pgStore) Counts() (map[string]int, error) {
	out := map[string]int{}
	scalar := func(key, q string, args ...any) error {
		var n int
		if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
			return err
		}
		out[key] = n
		return nil
	}
	day := "NOW() - INTERVAL '24 hours'"
	specs := []struct{ k, q string }{
		{"agents_total", `SELECT COUNT(*) FROM agents`},
		{"agents_online", `SELECT COUNT(*) FROM agents WHERE status='online'`},
		{"agents_isolated", `SELECT COUNT(*) FROM agents WHERE status='isolated'`},
		{"events_24h", `SELECT COUNT(*) FROM events WHERE ts>=` + day},
		{"detections_open", `SELECT COUNT(*) FROM detections WHERE status='open'`},
		{"detections_critical", `SELECT COUNT(*) FROM detections WHERE severity='critical' AND status='open'`},
		{"dlp_24h", `SELECT COUNT(*) FROM events WHERE category='dlp' AND ts>=` + day},
		{"responses_total", `SELECT COUNT(*) FROM responses`},
	}
	for _, sp := range specs {
		if err := scalar(sp.k, sp.q); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *pgStore) SeverityBreakdown() (map[string]int, error) {
	return s.groupCount(`SELECT severity, COUNT(*) FROM detections WHERE status!='closed' GROUP BY severity`)
}

func (s *pgStore) EventsPerCategory() (map[string]int, error) {
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
	rows, err := s.db.Query(`SELECT to_char(date_trunc('hour', ts) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:00:00"Z"') AS hour, COUNT(*)
		FROM events WHERE ts>=NOW() - INTERVAL '24 hours' GROUP BY 1 ORDER BY 1`)
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
