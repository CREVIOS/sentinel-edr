// Package baseline learns each endpoint's normal behavior and flags first-seen deviations —
// the statistical half of a hybrid (rules + baseline) detector that catches novel activity
// rules don't encode, while keeping false positives low by only alerting AFTER a per-host
// learning period and only on genuinely new values.
//
// Dimensions tracked per agent: executed-binary identity (sha256, else name), parent→child
// ancestry, and outbound network peer (domain, else IP). All sets are bounded so memory stays
// proportional to active hosts, not to uptime.
package baseline

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
)

const (
	maxPerDim = 8192          // cap distinct values per (agent,dimension)
	refire    = 6 * time.Hour // don't re-alert the same novel value within this window
	gcEvery   = 30 * time.Minute
)

// Engine holds per-agent baselines.
type Engine struct {
	mu    sync.Mutex
	learn time.Duration // per-host learning period before deviations alert

	firstSeen map[string]time.Time           // agent -> first time we saw it
	execs     map[string]map[string]struct{} // agent -> seen exec identities
	parents   map[string]map[string]struct{} // agent -> seen "parent>child"
	peers     map[string]map[string]struct{} // agent -> seen outbound peers
	fired     map[string]time.Time           // dedupe key -> last alert
	lastGC    time.Time
}

// New creates the engine with the given per-host learning period (e.g. 24h; longer = fewer FPs).
func New(learn time.Duration) *Engine {
	return &Engine{
		learn:     learn,
		firstSeen: map[string]time.Time{},
		execs:     map[string]map[string]struct{}{},
		parents:   map[string]map[string]struct{}{},
		peers:     map[string]map[string]struct{}{},
		fired:     map[string]time.Time{},
	}
}

// Observe feeds one event in and returns any first-seen-deviation detections.
func (e *Engine) Observe(ev *model.Event) []*model.Detection {
	if ev.AgentID == "" {
		return nil
	}
	now := ev.TS
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gc(now)

	if _, ok := e.firstSeen[ev.AgentID]; !ok {
		e.firstSeen[ev.AgentID] = now
	}
	mature := now.Sub(e.firstSeen[ev.AgentID]) >= e.learn

	var out []*model.Detection
	switch ev.Category {
	case model.CatProcess:
		if ev.Process != nil {
			id := ev.Process.Hash
			if id == "" {
				id = ev.Process.Name
			}
			if id != "" && e.note(e.execs, ev.AgentID, id) && mature {
				if d := e.maybe(ev, now, "exec:"+id,
					"baseline-new-binary", "First-seen binary on this host",
					"Execution", []string{"T1204"},
					"first execution of "+display(ev.Process.Name, ev.Process.Exe)+" on "+host(ev)); d != nil {
					out = append(out, d)
				}
			}
			if ev.Process.Parent != "" && ev.Process.Name != "" {
				pc := ev.Process.Parent + ">" + ev.Process.Name
				if e.note(e.parents, ev.AgentID, pc) && mature {
					if d := e.maybe(ev, now, "anc:"+pc,
						"baseline-new-ancestry", "First-seen process ancestry on this host",
						"Execution", []string{"T1059"},
						"first time "+ev.Process.Parent+" spawned "+ev.Process.Name+" on "+host(ev)); d != nil {
						out = append(out, d)
					}
				}
			}
		}
	case model.CatNetwork:
		if ev.Network != nil && ev.Network.Direction != "inbound" && ev.Network.Category != "internal" {
			peer := ev.Network.Domain
			if peer == "" {
				peer = ipOnly(ev.Network.Remote)
			}
			if peer != "" && e.note(e.peers, ev.AgentID, peer) && mature {
				if d := e.maybe(ev, now, "peer:"+peer,
					"baseline-new-destination", "First-seen outbound destination from this host",
					"Command and Control", []string{"T1071"},
					"first outbound connection to "+peer+" from "+host(ev)); d != nil {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// note records value v in set[agent]; returns true if it was NOT seen before (novel).
func (e *Engine) note(set map[string]map[string]struct{}, agent, v string) bool {
	m := set[agent]
	if m == nil {
		m = map[string]struct{}{}
		set[agent] = m
	}
	if _, ok := m[v]; ok {
		return false
	}
	if len(m) >= maxPerDim {
		// bounded: once saturated, stop learning new values (and don't alert) to cap memory;
		// a host with >8k distinct binaries/peers is already past useful baselining.
		return false
	}
	m[v] = struct{}{}
	return true
}

func (e *Engine) maybe(ev *model.Event, now time.Time, key, ruleID, name, tactic string, mitre []string, summary string) *model.Detection {
	fk := ev.AgentID + "|" + key
	if last, ok := e.fired[fk]; ok && now.Sub(last) < refire {
		return nil
	}
	e.fired[fk] = now
	return &model.Detection{
		ID: uuid.NewString(), TS: time.Now().UTC(),
		RuleID: ruleID, RuleName: name, Severity: model.SevMedium,
		Category: ev.Category, AgentID: ev.AgentID, Hostname: ev.Hostname, User: ev.User,
		Summary: summary, MITRE: mitre, Tactic: tactic,
		Status: model.DetOpen, EventIDs: []string{ev.ID}, Engine: "baseline",
	}
}

func (e *Engine) gc(now time.Time) {
	if !e.lastGC.IsZero() && now.Sub(e.lastGC) < gcEvery {
		return
	}
	e.lastGC = now
	for k, t := range e.fired {
		if now.Sub(t) > refire {
			delete(e.fired, k)
		}
	}
}

func display(name, exe string) string {
	if exe != "" {
		return exe
	}
	return name
}

func host(ev *model.Event) string {
	if ev.Hostname != "" {
		return ev.Hostname
	}
	return ev.AgentID
}

func ipOnly(remote string) string {
	if remote == "" {
		return ""
	}
	if i := lastColon(remote); i > 0 {
		return remote[:i]
	}
	return remote
}

func lastColon(s string) int {
	// handle ipv6 [::1]:443 → return index of the closing-bracket boundary
	if len(s) > 0 && s[0] == '[' {
		for i := 0; i < len(s); i++ {
			if s[i] == ']' {
				return i + 1
			}
		}
	}
	idx := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			idx = i
		}
	}
	return idx
}
