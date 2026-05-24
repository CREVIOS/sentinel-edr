package behavior

import (
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

// Maps must not grow forever: once an entity's window lapses and it stops producing events,
// gc must drop the key (otherwise a busy host leaks memory over weeks of uptime).
func TestBehaviorGCEvictsStaleKeys(t *testing.T) {
	e := New()
	t0 := time.Now().UTC()

	// create a failedAuth key and a beaconing conns key
	e.Observe(&model.Event{Category: model.CatAuth, AgentID: "a", TS: t0,
		Auth: &model.AuthInfo{Result: "failure", SourceIP: "1.2.3.4"}})
	e.Observe(&model.Event{Category: model.CatNetwork, AgentID: "a", TS: t0,
		Network: &model.NetInfo{Domain: "evil.test"}})

	if len(e.failedAuth) == 0 || len(e.conns) == 0 {
		t.Fatal("expected keys to be created")
	}

	// well past every window + the gc throttle → an unrelated event triggers a sweep
	later := t0.Add(30 * time.Minute)
	e.Observe(&model.Event{Category: model.CatSystem, AgentID: "a", TS: later})

	if len(e.failedAuth) != 0 {
		t.Fatalf("stale failedAuth keys not evicted: %d", len(e.failedAuth))
	}
	if len(e.conns) != 0 {
		t.Fatalf("stale conns keys not evicted: %d", len(e.conns))
	}
}

func TestBehaviorGCThrottled(t *testing.T) {
	e := New()
	t0 := time.Now().UTC()
	e.Observe(&model.Event{Category: model.CatAuth, AgentID: "a", TS: t0,
		Auth: &model.AuthInfo{Result: "failure", SourceIP: "1.2.3.4"}})
	// only 10s later (< 1m throttle) → gc must NOT run, key stays
	e.Observe(&model.Event{Category: model.CatSystem, AgentID: "a", TS: t0.Add(10 * time.Second)})
	if len(e.failedAuth) == 0 {
		t.Fatal("gc should be throttled within 1 minute; key was evicted too early")
	}
}
