package tune

import (
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

func det(rule, host, user, summary string) *model.Detection {
	return &model.Detection{RuleID: rule, Hostname: host, User: user, Summary: summary, Severity: model.SevHigh}
}

func TestDisabledRuleBlocks(t *testing.T) {
	e := New()
	e.Load([]model.RuleOverride{{RuleID: "proc-revshell", Enabled: false}}, nil)
	if ok, _ := e.Allowed(det("proc-revshell", "h1", "u", "s")); ok {
		t.Fatal("disabled rule should not be allowed")
	}
	if ok, _ := e.Allowed(det("proc-other", "h1", "u", "s")); !ok {
		t.Fatal("enabled rule should be allowed")
	}
}

func TestSuppressionEqualsAndContains(t *testing.T) {
	e := New()
	e.AddSuppression(model.Suppression{ID: "s1", RuleID: "*", Field: "host", Op: "equals", Value: "ci-runner"})
	e.AddSuppression(model.Suppression{ID: "s2", RuleID: "proc-gtfobins", Field: "summary", Op: "contains", Value: "/usr/bin/find backup"})

	if ok, _ := e.Allowed(det("anything", "ci-runner", "u", "s")); ok {
		t.Fatal("host-equals suppression should block")
	}
	if ok, _ := e.Allowed(det("anything", "prod-1", "u", "s")); !ok {
		t.Fatal("non-matching host should pass")
	}
	if ok, _ := e.Allowed(det("proc-gtfobins", "prod-1", "u", "ran /usr/bin/find backup job")); ok {
		t.Fatal("rule+summary-contains suppression should block")
	}
	if ok, _ := e.Allowed(det("proc-other", "prod-1", "u", "ran /usr/bin/find backup job")); !ok {
		t.Fatal("contains suppression scoped to a rule should not block other rules")
	}
	if e.Hits("s1") != 1 || e.Hits("s2") != 1 {
		t.Fatalf("expected 1 hit each, got s1=%d s2=%d", e.Hits("s1"), e.Hits("s2"))
	}
}

func TestExpiredSuppressionIgnored(t *testing.T) {
	e := New()
	past := time.Now().Add(-time.Hour)
	e.AddSuppression(model.Suppression{ID: "s1", RuleID: "*", Field: "host", Op: "equals", Value: "h1", Expires: &past})
	if ok, _ := e.Allowed(det("r", "h1", "u", "s")); !ok {
		t.Fatal("expired suppression must not block")
	}
}

func TestRemoveAndToggle(t *testing.T) {
	e := New()
	e.AddSuppression(model.Suppression{ID: "s1", RuleID: "*", Field: "user", Op: "equals", Value: "svc"})
	if ok, _ := e.Allowed(det("r", "h", "svc", "s")); ok {
		t.Fatal("should block before remove")
	}
	e.RemoveSuppression("s1")
	if ok, _ := e.Allowed(det("r", "h", "svc", "s")); !ok {
		t.Fatal("should pass after remove")
	}
	e.SetRuleEnabled("r", false)
	if ok, _ := e.Allowed(det("r", "h", "x", "s")); ok {
		t.Fatal("disabled after toggle")
	}
	e.SetRuleEnabled("r", true)
	if ok, _ := e.Allowed(det("r", "h", "x", "s")); !ok {
		t.Fatal("enabled after toggle")
	}
}
