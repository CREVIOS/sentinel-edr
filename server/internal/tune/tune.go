// Package tune is the detection-tuning layer: per-rule enable/disable and suppression
// predicates that silence known-benign activity without disabling a rule globally. It is
// consulted in the detection pipeline before a finding is persisted/alerted, and is mutated
// from the console. State is cached in memory (loaded from the store at boot) so the hot
// path is a couple of map/slice lookups under a read lock.
package tune

import (
	"strings"
	"sync"
	"time"

	"github.com/sentinel/server/internal/model"
)

// Engine holds the live tuning state.
type Engine struct {
	mu       sync.RWMutex
	disabled map[string]bool // rule_id -> true when disabled
	supps    []model.Suppression
	hits     map[string]int64 // suppression id -> detections silenced (in-memory)
}

// New returns an empty engine. Call Load to seed it from the store.
func New() *Engine {
	return &Engine{disabled: map[string]bool{}, hits: map[string]int64{}}
}

// Load replaces the cached state from persisted overrides + suppressions.
func (e *Engine) Load(overrides []model.RuleOverride, supps []model.Suppression) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disabled = map[string]bool{}
	for _, o := range overrides {
		if !o.Enabled {
			e.disabled[o.RuleID] = true
		}
	}
	e.supps = supps
}

// SetRuleEnabled flips a rule on/off.
func (e *Engine) SetRuleEnabled(ruleID string, enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if enabled {
		delete(e.disabled, ruleID)
	} else {
		e.disabled[ruleID] = true
	}
}

// AddSuppression inserts or replaces a suppression by id.
func (e *Engine) AddSuppression(s model.Suppression) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.supps {
		if e.supps[i].ID == s.ID {
			e.supps[i] = s
			return
		}
	}
	e.supps = append(e.supps, s)
}

// RemoveSuppression drops a suppression and its hit counter.
func (e *Engine) RemoveSuppression(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.supps[:0]
	for _, s := range e.supps {
		if s.ID != id {
			out = append(out, s)
		}
	}
	e.supps = out
	delete(e.hits, id)
}

// Allowed reports whether a detection should be emitted. It returns (false, reason) when the
// rule is disabled or a non-expired suppression matches; matching suppressions have their
// in-memory hit counter bumped so the console can show what each one is silencing.
func (e *Engine) Allowed(d *model.Detection) (bool, string) {
	e.mu.RLock()
	if e.disabled[d.RuleID] {
		e.mu.RUnlock()
		return false, "rule disabled"
	}
	now := time.Now()
	matched := ""
	for i := range e.supps {
		s := &e.supps[i]
		if s.Expires != nil && now.After(*s.Expires) {
			continue
		}
		if s.RuleID != "*" && s.RuleID != d.RuleID {
			continue
		}
		if matchField(s, d) {
			matched = s.ID
			break
		}
	}
	e.mu.RUnlock()
	if matched != "" {
		e.mu.Lock()
		e.hits[matched]++
		e.mu.Unlock()
		return false, "suppressed by " + matched
	}
	return true, ""
}

func matchField(s *model.Suppression, d *model.Detection) bool {
	var hay string
	switch s.Field {
	case "host":
		hay = d.Hostname
	case "user":
		hay = d.User
	case "agent":
		hay = d.AgentID
	case "summary":
		hay = d.Summary
	case "rule":
		hay = d.RuleID
	default:
		return false
	}
	if s.Op == "contains" {
		return s.Value != "" && strings.Contains(hay, s.Value)
	}
	return hay == s.Value // default: equals
}

// Hits returns the in-memory suppressed count for a suppression id.
func (e *Engine) Hits(id string) int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hits[id]
}

// DisabledRules returns a copy of the disabled rule-id set.
func (e *Engine) DisabledRules() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]bool, len(e.disabled))
	for k := range e.disabled {
		out[k] = true
	}
	return out
}
