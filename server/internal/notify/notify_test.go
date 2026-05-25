package notify

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

func TestDisabledWhenNoSink(t *testing.T) {
	if New(Config{MinSeverity: "high"}, slog.Default()) != nil {
		t.Fatal("no webhook + no smtp must return nil notifier")
	}
	var n *Notifier
	n.Notify(&model.Detection{Severity: model.SevCritical}) // nil-safe no-op
}

func recvServer(hits *int32, last *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*last = string(b)
		atomic.AddInt32(hits, 1)
		w.WriteHeader(200)
	}))
}

func TestSeverityGateAndThrottle(t *testing.T) {
	var hits int32
	var body string
	srv := recvServer(&hits, &body)
	defer srv.Close()
	n := New(Config{MinSeverity: "high", WebhookURL: srv.URL, WebhookKind: KindSlack}, slog.Default())
	n.Notify(&model.Detection{RuleID: "r", Severity: model.SevLow}) // below gate
	for i := 0; i < 4; i++ {
		n.Notify(&model.Detection{RuleID: "same", AgentID: "a", Severity: model.SevCritical, RuleName: "X", Hostname: "h"})
	}
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected 1 delivery (gate+throttle), got %d", got)
	}
}

func TestDiscordEmbedShape(t *testing.T) {
	d := &model.Detection{RuleID: "r", RuleName: "Reverse shell", Severity: model.SevCritical,
		Hostname: "h1", User: "root", Tactic: "Execution", MITRE: []string{"T1059"}, Engine: "sigma", Summary: "s"}
	b := (&webhookSink{kind: KindDiscord}).payload(d)
	s := string(b)
	for _, want := range []string{`"embeds"`, `"color":14100029`, `"title"`, `CRITICAL — Reverse shell`, `"fields"`, "T1059"} {
		if !strings.Contains(s, want) {
			t.Fatalf("discord embed missing %q in %s", want, s)
		}
	}
}

func TestSlackAndGenericShapes(t *testing.T) {
	d := &model.Detection{RuleID: "r", RuleName: "T", Severity: model.SevHigh, Hostname: "h", Summary: "s"}
	if !strings.Contains(string((&webhookSink{kind: KindSlack}).payload(d)), `"text"`) {
		t.Fatal("slack payload missing text")
	}
	if !strings.Contains(string((&webhookSink{kind: KindGeneric}).payload(d)), `"rule_id"`) {
		t.Fatal("generic payload missing rule_id")
	}
}

func TestEmailMessageWellFormedAndInjectionSafe(t *testing.T) {
	e := &emailSink{from: "soc@x.tld", to: []string{"a@x.tld", "b@x.tld"}}
	d := &model.Detection{
		RuleName: "evil\r\nBcc: attacker@evil.tld", // header-injection attempt via rule name
		Severity: model.SevCritical, Hostname: "h\r\nX-Inject: 1", User: "root", Summary: "body",
		TS: time.Now(),
	}
	msg := string(e.message(d))
	// headers present
	for _, h := range []string{"From: soc@x.tld", "To: a@x.tld, b@x.tld", "Subject: [Sentinel CRITICAL]", "Content-Type: text/plain"} {
		if !strings.Contains(msg, h) {
			t.Fatalf("email missing header %q", h)
		}
	}
	// the CRLF-injected Bcc/X-Inject must NOT appear as a real header line
	if strings.Contains(msg, "\r\nBcc:") || strings.Contains(msg, "\r\nX-Inject:") {
		t.Fatalf("SMTP header injection not neutralized:\n%s", msg)
	}
}

func TestEmailSinkEnabledNeedsAllFields(t *testing.T) {
	// host without from/to → no email sink (so New returns nil if also no webhook)
	if New(Config{MinSeverity: "high", SMTPHost: "smtp.x.tld"}, slog.Default()) != nil {
		t.Fatal("incomplete SMTP config should not enable email sink")
	}
	n := New(Config{MinSeverity: "high", SMTPHost: "smtp.x.tld", MailFrom: "a@x.tld", MailTo: "b@x.tld"}, slog.Default())
	if n == nil || len(n.Sinks()) != 1 || n.Sinks()[0] != "email" {
		t.Fatalf("email sink not enabled: %v", n.Sinks())
	}
}
