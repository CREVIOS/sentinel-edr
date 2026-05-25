// Package cases groups related detections into investigations. Detections from the same
// endpoint within a sliding window are attached to one open case (so an analyst sees a
// single incident instead of a flood of findings); otherwise a new case is opened. Analysts
// can then assign, annotate, and progress cases through their lifecycle via the API.
package cases

import (
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
)

// window is how long an open case keeps absorbing new detections from the same endpoint.
const window = 30 * time.Minute

// Store is the subset of the persistence layer the correlator needs.
type Store interface {
	InsertCase(*model.Case) error
	GetCase(string) (*model.Case, error)
	ListCases(int, string) ([]model.Case, error)
}

// Correlator maintains the current open case per endpoint and folds detections into it.
type Correlator struct {
	store Store
	log   *slog.Logger

	mu     sync.Mutex
	active map[string]ref // agent_id -> most-recent open case
}

type ref struct {
	id   string
	last time.Time
}

// New creates a correlator over the given store.
func New(s Store, log *slog.Logger) *Correlator {
	return &Correlator{store: s, log: log, active: map[string]ref{}}
}

// Seed primes the in-memory index from open cases so correlation survives a restart.
func (c *Correlator) Seed() {
	open, err := c.store.ListCases(500, string(model.CaseOpen))
	if err != nil {
		if c.log != nil {
			c.log.Warn("case seed failed", "err", err)
		}
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range open {
		cs := &open[i]
		if cs.AgentID == "" {
			continue
		}
		if cur, ok := c.active[cs.AgentID]; !ok || cs.UpdatedAt.After(cur.last) {
			c.active[cs.AgentID] = ref{id: cs.ID, last: cs.UpdatedAt}
		}
	}
}

// Add folds a detection into the active case for its endpoint (creating one if none is
// active within the window) and returns the updated/created case for broadcasting.
func (c *Correlator) Add(d *model.Detection) (*model.Case, error) {
	now := time.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()

	if r, ok := c.active[d.AgentID]; ok && now.Sub(r.last) < window {
		if cs, err := c.store.GetCase(r.id); err == nil && cs.Status != model.CaseClosed {
			fold(cs, d, now)
			if err := c.store.InsertCase(cs); err != nil {
				return nil, err
			}
			c.active[d.AgentID] = ref{id: cs.ID, last: now}
			return cs, nil
		}
		// stale/closed reference — fall through to open a fresh case
	}

	cs := &model.Case{
		ID:           uuid.NewString(),
		Title:        caseTitle(d),
		Severity:     d.Severity,
		Status:       model.CaseOpen,
		AgentID:      d.AgentID,
		Hostname:     d.Hostname,
		DetectionIDs: []string{d.ID},
		MITRE:        append([]string(nil), d.MITRE...),
		CreatedAt:    now,
		UpdatedAt:    now,
		CreatedBy:    "auto-correlation",
	}
	if err := c.store.InsertCase(cs); err != nil {
		return nil, err
	}
	c.active[d.AgentID] = ref{id: cs.ID, last: now}
	return cs, nil
}

// fold attaches a detection to an existing case: dedup the id, raise severity to the max,
// union MITRE techniques, and touch the timestamp.
func fold(cs *model.Case, d *model.Detection, now time.Time) {
	for _, id := range cs.DetectionIDs {
		if id == d.ID {
			return // already attached (re-emit) — nothing to do
		}
	}
	cs.DetectionIDs = append(cs.DetectionIDs, d.ID)
	if d.Severity.Rank() > cs.Severity.Rank() {
		cs.Severity = d.Severity
	}
	cs.MITRE = unionMitre(cs.MITRE, d.MITRE)
	cs.UpdatedAt = now
}

func unionMitre(a, b []string) []string {
	seen := map[string]bool{}
	out := a[:0:0]
	for _, x := range append(append([]string{}, a...), b...) {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

func caseTitle(d *model.Detection) string {
	host := d.Hostname
	if host == "" {
		host = d.AgentID
	}
	name := d.RuleName
	if name == "" {
		name = d.RuleID
	}
	return name + " on " + host
}
