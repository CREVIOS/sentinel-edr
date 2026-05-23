// Package store persists agents, events, detections and response actions in TimescaleDB
// (Postgres + hypertables) — time-partitioned, compressible, horizontally readable, with
// retention policies for fleet-scale event volumes. Access is through the Store interface
// so the backend stays swappable, but the only supported production backend is Postgres.
package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/sentinel/server/internal/model"
)

// EventFilter narrows event queries from the API.
type EventFilter struct {
	AgentID  string
	Category string
	Severity string
	User     string
	Search   string
	Since    *time.Time
	Limit    int
	Offset   int
}

// Store is the persistence contract implemented by every backend.
type Store interface {
	Close() error

	// agents
	UpsertAgent(a *model.Agent) error
	SetAgentStatus(id string, status model.AgentStatus) error
	Heartbeat(id string, n int) error
	GetAgent(id string) (*model.Agent, error)
	ListAgents() ([]*model.Agent, error)
	MarkStaleOffline(window time.Duration) error

	// events
	InsertEvents(evs []model.Event) error
	QueryEvents(f EventFilter) ([]model.Event, error)

	// detections
	InsertDetection(d *model.Detection) error
	ListDetections(limit int, status string) ([]model.Detection, error)
	GetDetection(id string) (*model.Detection, error)
	UpdateDetectionStatus(id string, status model.DetectionStatus, assignee string) error

	// responses
	InsertResponse(r *model.ResponseAction) error
	GetResponse(id string) (*model.ResponseAction, error)
	ListResponses(limit int) ([]model.ResponseAction, error)

	// aggregates for dashboards
	Counts() (map[string]int, error)
	SeverityBreakdown() (map[string]int, error)
	EventsPerCategory() (map[string]int, error)
	EventTimeline() ([]map[string]any, error)
	TopMitre(limit int) ([]map[string]any, error)
}

// Open returns a Store for the given DSN. Only TimescaleDB/Postgres is supported:
//
//	postgres://user:pass@host:5432/db?sslmode=require
func Open(dsn string) (Store, error) {
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return nil, fmt.Errorf("store: unsupported DSN %q (expected postgres://…)", dsn)
	}
	return openPostgres(dsn)
}

// scanner is satisfied by *sql.Row and *sql.Rows.
type scanner interface{ Scan(...any) error }

// limitOffset is a small helper shared by backends.
func limitOffset(limit, offset int) string {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	return fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
}
