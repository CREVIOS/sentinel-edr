package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

// N4: attacker-controlled fields must not be able to inject a forged CEF/syslog line.
func TestCEFEscapeStripsControlChars(t *testing.T) {
	in := "ok\rCEF:0|Evil|forged|line\nmsg\x00\x07tail"
	got := cefEscapeVal(in)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("newline/CR leaked through cefEscapeVal: %q", got)
	}
	if strings.ContainsRune(got, 0x00) || strings.ContainsRune(got, 0x07) {
		t.Fatalf("control char leaked through cefEscapeVal: %q", got)
	}
	// \r and \n become spaces; the visible text survives.
	if !strings.Contains(got, "ok") || !strings.Contains(got, "tail") {
		t.Fatalf("visible text lost: %q", got)
	}
}

func TestCEFHeaderEscapeStripsControl(t *testing.T) {
	if strings.ContainsAny(cefEscape("a\rb\nc"), "\r\n") {
		t.Fatal("cefEscape (header) leaked CR/LF")
	}
}

func TestEventECSValidJSON(t *testing.T) {
	ev := model.Event{
		TS: time.Now().UTC(), Category: model.CatProcess, Action: "exec",
		Severity: model.SevHigh, Hostname: "h1", AgentID: "a1", User: "root",
		Message: "line1\nline2\rline3", // control chars must be JSON-escaped, not break the doc
		Process: &model.Process{PID: 42, Name: "bash", Cmdline: "bash -i", Parent: "sshd"},
		Network: &model.NetInfo{Direction: "outbound", Proto: "tcp", Remote: "1.2.3.4:443", Domain: "evil.test", BytesOut: 10, BytesIn: 5},
	}
	out := EventECS(ev)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("ECS output is not valid JSON: %v\n%s", err, out)
	}
	if doc["@timestamp"] == nil || doc["event"] == nil || doc["process"] == nil {
		t.Fatalf("ECS missing expected top-level fields: %s", out)
	}
	net, _ := doc["network"].(map[string]any)
	if net == nil || net["bytes"].(float64) != 15 {
		t.Fatalf("ECS network.bytes wrong: %v", doc["network"])
	}
}

func TestCEFEndToEndNoInjection(t *testing.T) {
	ev := model.Event{
		TS: time.Now().UTC(), Category: model.CatProcess, Action: "exec",
		Severity: model.SevCritical, Hostname: "h", AgentID: "a",
		Message: "evil\r\nCEF:0|forged|line",
		Process: &model.Process{Name: "x", Cmdline: "a=b\rc=d"},
	}
	line := EventCEF(ev)
	// the rendered CEF record must be a single line
	if strings.Contains(line, "\n") || strings.Contains(line, "\r") {
		t.Fatalf("CEF record contains a newline (injection): %q", line)
	}
}
