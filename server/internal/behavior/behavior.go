// Package behavior implements stateful, windowed correlation that single-event Sigma
// rules cannot express: SSH brute force, data-exfiltration volume, C2 beaconing, and
// USB mass-copy. It keeps small in-memory sliding windows keyed per agent/entity.
package behavior

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
)

// Engine holds sliding-window state.
type Engine struct {
	mu sync.Mutex

	failedAuth map[string][]time.Time // key: agent|sourceIP
	egress     map[string]*window     // key: agent  (bytes_out sum)
	usbWrites  map[string][]time.Time // key: agent|serial
	conns      map[string][]time.Time // key: agent|domain (beaconing)

	// de-dupe so we don't fire the same correlation every event
	fired map[string]time.Time

	lastGC time.Time // throttles map eviction
}

type window struct {
	start time.Time
	bytes int64
}

// New creates the engine.
func New() *Engine {
	return &Engine{
		failedAuth: map[string][]time.Time{},
		egress:     map[string]*window{},
		usbWrites:  map[string][]time.Time{},
		conns:      map[string][]time.Time{},
		fired:      map[string]time.Time{},
	}
}

const (
	bruteForceWindow = 90 * time.Second
	bruteForceCount  = 5
	exfilWindow      = 5 * time.Minute
	exfilBytes       = 50 * 1024 * 1024 // 50 MB outbound in window
	usbCopyWindow    = 60 * time.Second
	usbCopyCount     = 10
	beaconWindow     = 10 * time.Minute
	beaconCount      = 12
	refire           = 5 * time.Minute // don't refire same key within this
)

// Observe feeds one event into the correlators and returns any new detections.
func (e *Engine) Observe(ev *model.Event) []*model.Detection {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := ev.TS
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.gc(now)
	var out []*model.Detection

	switch ev.Category {
	case model.CatAuth, model.CatSSH:
		if ev.Auth != nil && ev.Auth.Result == "failure" {
			key := ev.AgentID + "|" + ev.Auth.SourceIP
			e.failedAuth[key] = append(prune(e.failedAuth[key], now, bruteForceWindow), now)
			if len(e.failedAuth[key]) >= bruteForceCount && e.canFire("bf:"+key, now) {
				out = append(out, e.det(ev, "behavior-ssh-bruteforce", "SSH brute-force / password spraying",
					model.SevHigh, "Credential Access", []string{"T1110"},
					fmt.Sprintf("%d failed logins from %s within %s", len(e.failedAuth[key]), ev.Auth.SourceIP, bruteForceWindow)))
			}
		}

	case model.CatNetwork:
		if ev.Network != nil {
			// exfil volume
			if ev.Network.Direction == "outbound" && ev.Network.BytesOut > 0 {
				w := e.egress[ev.AgentID]
				if w == nil || now.Sub(w.start) > exfilWindow {
					w = &window{start: now}
					e.egress[ev.AgentID] = w
				}
				w.bytes += ev.Network.BytesOut
				if w.bytes >= exfilBytes && e.canFire("exfil:"+ev.AgentID, now) {
					out = append(out, e.det(ev, "behavior-data-exfil-volume", "Large outbound data transfer (possible exfiltration)",
						model.SevHigh, "Exfiltration", []string{"T1041", "T1567"},
						fmt.Sprintf("%d MB sent outbound within %s", w.bytes/(1024*1024), exfilWindow)))
				}
			}
			// beaconing: many connections to one domain at steady cadence
			if ev.Network.Domain != "" {
				key := ev.AgentID + "|" + ev.Network.Domain
				e.conns[key] = append(prune(e.conns[key], now, beaconWindow), now)
				if len(e.conns[key]) >= beaconCount && regular(e.conns[key]) && e.canFire("beacon:"+key, now) {
					out = append(out, e.det(ev, "behavior-c2-beacon", "Periodic C2 beaconing pattern",
						model.SevHigh, "Command and Control", []string{"T1071"},
						fmt.Sprintf("%d regular connections to %s in %s", len(e.conns[key]), ev.Network.Domain, beaconWindow)))
				}
			}
		}

	case model.CatUSB, model.CatFile:
		// USB mass copy: many file writes whose path is under a removable mount
		if ev.File != nil && ev.File.Op != "read" && isRemovablePath(ev.File.Path) {
			serial := "usb"
			if ev.USB != nil && ev.USB.Serial != "" {
				serial = ev.USB.Serial
			}
			key := ev.AgentID + "|" + serial
			e.usbWrites[key] = append(prune(e.usbWrites[key], now, usbCopyWindow), now)
			if len(e.usbWrites[key]) >= usbCopyCount && e.canFire("usbcopy:"+key, now) {
				out = append(out, e.det(ev, "behavior-usb-mass-copy", "Mass file copy to removable device",
					model.SevHigh, "Exfiltration", []string{"T1052"},
					fmt.Sprintf("%d files written to removable media within %s", len(e.usbWrites[key]), usbCopyWindow)))
			}
		}
	}
	return out
}

// gc evicts windows/keys that can no longer contribute to a detection, so the maps stay
// bounded by *active* entities rather than growing for the life of the process (a busy jump
// host sees thousands of distinct source IPs / domains over weeks of uptime). Throttled.
func (e *Engine) gc(now time.Time) {
	if !e.lastGC.IsZero() && now.Sub(e.lastGC) < time.Minute {
		return
	}
	e.lastGC = now
	sweep := func(m map[string][]time.Time, w time.Duration) {
		for k, ts := range m {
			if len(prune(ts, now, w)) == 0 {
				delete(m, k)
			}
		}
	}
	sweep(e.failedAuth, bruteForceWindow)
	sweep(e.usbWrites, usbCopyWindow)
	sweep(e.conns, beaconWindow)
	for k, w := range e.egress {
		if now.Sub(w.start) > exfilWindow {
			delete(e.egress, k)
		}
	}
	for k, t := range e.fired {
		if now.Sub(t) > refire {
			delete(e.fired, k)
		}
	}
}

func (e *Engine) canFire(key string, now time.Time) bool {
	if last, ok := e.fired[key]; ok && now.Sub(last) < refire {
		return false
	}
	e.fired[key] = now
	return true
}

func (e *Engine) det(ev *model.Event, ruleID, name string, sev model.Severity, tactic string, mitre []string, summary string) *model.Detection {
	return &model.Detection{
		ID:       uuid.NewString(),
		TS:       time.Now().UTC(),
		RuleID:   ruleID,
		RuleName: name,
		Severity: sev,
		Category: ev.Category,
		AgentID:  ev.AgentID,
		Hostname: ev.Hostname,
		User:     ev.User,
		Summary:  summary,
		MITRE:    mitre,
		Tactic:   tactic,
		Status:   model.DetOpen,
		EventIDs: []string{ev.ID},
		Engine:   "behavior",
	}
}

func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	var out []time.Time
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// regular returns true when inter-arrival gaps have low relative variance (beacon-like).
func regular(ts []time.Time) bool {
	if len(ts) < 4 {
		return false
	}
	var gaps []float64
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]).Seconds())
	}
	var mean float64
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean <= 0 {
		return false
	}
	var varc float64
	for _, g := range gaps {
		d := g - mean
		varc += d * d
	}
	varc /= float64(len(gaps))
	cv := (varc / (mean * mean)) // coefficient of variation squared
	return cv < 0.25             // gaps cluster tightly around the mean
}

func isRemovablePath(path string) bool {
	for _, p := range []string{"/media/", "/mnt/", "/run/media/", "/Volumes/"} {
		if len(path) >= len(p) && path[:len(p)] == p {
			return true
		}
	}
	return false
}
