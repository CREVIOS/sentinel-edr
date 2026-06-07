package baseline

import (
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

func execEv(agent, host, hash, name string, ts time.Time) *model.Event {
	return &model.Event{
		ID: "e", AgentID: agent, Hostname: host, TS: ts, Category: model.CatProcess,
		Process: &model.Process{Name: name, Exe: "/usr/bin/" + name, Hash: hash},
	}
}

func TestLearningThenDeviation(t *testing.T) {
	e := New(time.Hour) // 1h learn period
	base := time.Now().UTC().Add(-2 * time.Hour)

	// during learning (first event sets firstSeen; not mature) → no detection even for new binary
	if d := e.Observe(execEv("a1", "h1", "hash-a", "curl", base)); len(d) != 0 {
		t.Fatalf("expected no detection during learning, got %d", len(d))
	}
	// same binary again, now mature → already seen → no detection
	if d := e.Observe(execEv("a1", "h1", "hash-a", "curl", base.Add(90*time.Minute))); len(d) != 0 {
		t.Fatalf("known binary must not alert, got %d", len(d))
	}
	// a NEW binary after maturity → anomaly
	d := e.Observe(execEv("a1", "h1", "hash-evil", "xmrig", base.Add(91*time.Minute)))
	if len(d) != 1 || d[0].RuleID != "baseline-new-binary" {
		t.Fatalf("expected first-seen-binary anomaly, got %+v", d)
	}
	// repeat the novel binary → deduped within refire window
	if d := e.Observe(execEv("a1", "h1", "hash-evil", "xmrig", base.Add(92*time.Minute))); len(d) != 0 {
		t.Fatalf("repeat novel value should dedupe, got %d", len(d))
	}
}

func TestPerHostIsolation(t *testing.T) {
	e := New(0) // mature immediately
	now := time.Now().UTC()
	// a2 has never seen 'bash'; with learn=0 the very first sight is a deviation
	d := e.Observe(execEv("a2", "h2", "hash-bash", "bash", now))
	if len(d) != 1 {
		t.Fatalf("learn=0 → first sight is novel; got %d", len(d))
	}
	// a different host seeing the same binary is also novel for IT
	d = e.Observe(execEv("a3", "h3", "hash-bash", "bash", now))
	if len(d) != 1 {
		t.Fatalf("baseline must be per-host; got %d", len(d))
	}
}

func TestNewOutboundDestination(t *testing.T) {
	e := New(0)
	now := time.Now().UTC()
	ev := &model.Event{
		ID: "n", AgentID: "a4", Hostname: "h4", TS: now, Category: model.CatNetwork,
		Network: &model.NetInfo{Direction: "outbound", Domain: "evil.example.com", Remote: "1.2.3.4:443"},
	}
	d := e.Observe(ev)
	if len(d) != 1 || d[0].RuleID != "baseline-new-destination" {
		t.Fatalf("expected first-seen-destination anomaly, got %+v", d)
	}
}

func TestSaturationStillLearnsNovelValues(t *testing.T) {
	e := New(0)
	now := time.Now().UTC()
	agent := "sat-agent"
	for i := 0; i < maxPerDim; i++ {
		d := e.Observe(execEv(agent, "h", "hash-fill-"+time.Duration(i).String(), "bin", now))
		if len(d) != 1 {
			t.Fatalf("expected detection while filling baseline at %d, got %d", i, len(d))
		}
	}
	// One more novel value beyond the cap should still be treated as novel.
	d := e.Observe(execEv(agent, "h", "hash-over-cap", "bin", now))
	if len(d) != 1 {
		t.Fatalf("expected novel detection after saturation, got %d", len(d))
	}
}

func TestBaselineStoresBoundedKeySize(t *testing.T) {
	e := New(0)
	now := time.Now().UTC()
	big := make([]byte, 64*1024)
	for i := range big {
		big[i] = 'a'
	}
	e.Observe(execEv("a-bound", "h", string(big), "bin", now))
	m := e.execs["a-bound"]
	if len(m) != 1 {
		t.Fatalf("expected one stored key, got %d", len(m))
	}
	for k := range m {
		if len(k) != 64 {
			t.Fatalf("expected sha256 hex key length 64, got %d", len(k))
		}
	}
}
