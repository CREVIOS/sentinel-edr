package notify

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

func TestDisabledWhenNoURL(t *testing.T) {
	if New("", KindGeneric, "high", slog.Default()) != nil {
		t.Fatal("empty URL must return nil notifier")
	}
	// nil.Notify must be a safe no-op
	var n *Notifier
	n.Notify(&model.Detection{Severity: model.SevCritical})
}

func recvServer(t *testing.T, hits *int32, last *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*last = string(b)
		atomic.AddInt32(hits, 1)
		w.WriteHeader(200)
	}))
}

func TestSeverityGate(t *testing.T) {
	var hits int32
	var body string
	srv := recvServer(t, &hits, &body)
	defer srv.Close()
	n := New(srv.URL, KindSlack, "high", slog.Default())
	n.Notify(&model.Detection{RuleID: "r1", Severity: model.SevLow}) // below gate → dropped
	n.Notify(&model.Detection{RuleID: "r2", Severity: model.SevCritical, RuleName: "X", Hostname: "h"})
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 delivery (only critical), got %d", got)
	}
}

func TestThrottle(t *testing.T) {
	var hits int32
	var body string
	srv := recvServer(t, &hits, &body)
	defer srv.Close()
	n := New(srv.URL, KindGeneric, "high", slog.Default())
	for i := 0; i < 4; i++ {
		n.Notify(&model.Detection{RuleID: "same", AgentID: "a", Severity: model.SevHigh})
	}
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("throttle: same rule+host should deliver once, got %d", got)
	}
}

func TestPayloadShapes(t *testing.T) {
	d := &model.Detection{RuleID: "r", RuleName: "Test", Severity: model.SevCritical, Hostname: "h", Summary: "s"}
	if b := (&Notifier{kind: KindSlack}).payload(d); !contains(b, "text") {
		t.Fatal("slack payload missing text")
	}
	if b := (&Notifier{kind: KindDiscord}).payload(d); !contains(b, "content") {
		t.Fatal("discord payload missing content")
	}
	if b := (&Notifier{kind: KindGeneric}).payload(d); !contains(b, "rule_id") {
		t.Fatal("generic payload missing rule_id")
	}
}

func contains(b []byte, s string) bool {
	return len(b) > 0 && (string(b) != "" && (indexOf(string(b), s) >= 0))
}
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
