package behavior

import (
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

func TestSSHBruteForce(t *testing.T) {
	e := New()
	base := time.Now().UTC()
	var fired bool
	for i := 0; i < bruteForceCount; i++ {
		ev := &model.Event{
			AgentID: "a1", Category: model.CatSSH, TS: base.Add(time.Duration(i) * time.Second),
			Auth: &model.AuthInfo{Result: "failure", SourceIP: "203.0.113.7"},
		}
		for _, d := range e.Observe(ev) {
			if d.RuleID == "behavior-ssh-bruteforce" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected brute-force detection after %d failures", bruteForceCount)
	}
}

func TestExfilVolume(t *testing.T) {
	e := New()
	base := time.Now().UTC()
	ev := &model.Event{
		AgentID: "a1", Category: model.CatNetwork, TS: base,
		Network: &model.NetInfo{Direction: "outbound", BytesOut: exfilBytes + 1, Domain: "drop.example"},
	}
	var fired bool
	for _, d := range e.Observe(ev) {
		if d.RuleID == "behavior-data-exfil-volume" {
			fired = true
		}
	}
	if !fired {
		t.Fatalf("expected exfil-volume detection")
	}
}

func TestUSBMassCopy(t *testing.T) {
	e := New()
	base := time.Now().UTC()
	var fired bool
	for i := 0; i < usbCopyCount; i++ {
		ev := &model.Event{
			AgentID: "a1", Category: model.CatFile, TS: base.Add(time.Duration(i) * time.Second),
			File: &model.FileInfo{Path: "/media/usb0/secret" + itoa(i) + ".dat", Op: "write"},
			USB:  &model.USBInfo{Serial: "SN123"},
		}
		for _, d := range e.Observe(ev) {
			if d.RuleID == "behavior-usb-mass-copy" {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected usb mass-copy detection")
	}
}

func TestBeaconRegularity(t *testing.T) {
	// evenly spaced timestamps => regular
	base := time.Now()
	var even []time.Time
	for i := 0; i < 10; i++ {
		even = append(even, base.Add(time.Duration(i)*time.Second))
	}
	if !regular(even) {
		t.Fatalf("evenly spaced series should be regular")
	}
	// jittered series => not regular
	jitter := []time.Time{base, base.Add(time.Second), base.Add(10 * time.Second), base.Add(11 * time.Second), base.Add(40 * time.Second)}
	if regular(jitter) {
		t.Fatalf("jittered series should not be regular")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
