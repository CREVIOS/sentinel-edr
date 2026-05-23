package detect

import (
	"regexp"
	"testing"

	"github.com/sentinel/server/internal/model"
)

var mitreRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// Every shipped rule must be well-formed: id, title, valid severity/category, a
// compilable condition, and at least one MITRE technique mapped correctly.
func TestAllRulesValid(t *testing.T) {
	e := New()
	if _, err := e.LoadDir("../../rules"); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	validSev := map[model.Severity]bool{
		model.SevInfo: true, model.SevLow: true, model.SevMedium: true,
		model.SevHigh: true, model.SevCritical: true,
	}
	validCat := map[model.Category]bool{
		model.CatAuth: true, model.CatSSH: true, model.CatProcess: true, model.CatFile: true,
		model.CatPackage: true, model.CatUSB: true, model.CatNetwork: true, model.CatDLP: true, model.CatSystem: true,
	}
	validResp := map[string]bool{
		"": true, "kill_process": true, "isolate": true, "block_upload": true,
		"block_usb": true, "disable_account": true,
	}
	seen := map[string]bool{}
	for _, r := range e.Rules() {
		if r.ID == "" || r.Title == "" {
			t.Errorf("rule missing id/title: %+v", r)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule id: %s", r.ID)
		}
		seen[r.ID] = true
		if !validSev[r.Severity] {
			t.Errorf("%s: invalid severity %q", r.ID, r.Severity)
		}
		if !validCat[r.Category] {
			t.Errorf("%s: invalid category %q", r.ID, r.Category)
		}
		if !validResp[r.AutoRespond] {
			t.Errorf("%s: invalid auto_respond %q", r.ID, r.AutoRespond)
		}
		if len(r.MITRE) == 0 {
			t.Errorf("%s: no MITRE technique mapped", r.ID)
		}
		for _, m := range r.MITRE {
			if !mitreRe.MatchString(m) {
				t.Errorf("%s: malformed MITRE id %q", r.ID, m)
			}
		}
		if len(r.compiled) == 0 {
			t.Errorf("%s: no detection selections", r.ID)
		}
	}
	t.Logf("validated %d rules", len(e.Rules()))
}
