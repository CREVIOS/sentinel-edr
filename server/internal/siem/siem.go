// Package siem renders events and detections into formats external SIEMs ingest:
// ArcSight CEF (syslog) and Elastic Common Schema (ECS) JSON. This is how Sentinel
// integrates with Splunk / Elastic / QRadar for cross-source correlation.
package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sentinel/server/internal/model"
)

// sevToCEF maps our severity to CEF's 0-10 scale.
func sevToCEF(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 10
	case model.SevHigh:
		return 8
	case model.SevMedium:
		return 5
	case model.SevLow:
		return 3
	default:
		return 1
	}
}

// EventCEF renders one event as a CEF line.
func EventCEF(e model.Event) string {
	ext := map[string]string{
		"rt":       fmt.Sprintf("%d", e.TS.UnixMilli()),
		"dvchost":  e.Hostname,
		"suser":    e.User,
		"cs1":      string(e.Category),
		"cs1Label": "category",
		"msg":      e.Message,
	}
	if e.Process != nil {
		ext["dproc"] = e.Process.Name
		ext["cs2"] = e.Process.Cmdline
		ext["cs2Label"] = "cmdline"
	}
	if e.Network != nil {
		ext["dhost"] = e.Network.Domain
		ext["out"] = fmt.Sprintf("%d", e.Network.BytesOut)
	}
	if e.File != nil {
		ext["fname"] = e.File.Path
	}
	name := e.Action
	if name == "" {
		name = string(e.Category)
	}
	return cefHeader("event", name, sevToCEF(e.Severity)) + cefExt(ext)
}

// DetectionCEF renders one detection as a CEF line.
func DetectionCEF(d model.Detection) string {
	ext := map[string]string{
		"rt":       fmt.Sprintf("%d", d.TS.UnixMilli()),
		"dvchost":  d.Hostname,
		"suser":    d.User,
		"msg":      d.Summary,
		"cs1":      strings.Join(d.MITRE, ","),
		"cs1Label": "mitre",
		"cs2":      d.Tactic,
		"cs2Label": "tactic",
		"cs3":      d.RuleID,
		"cs3Label": "rule",
	}
	return cefHeader("detection", d.RuleName, sevToCEF(d.Severity)) + cefExt(ext)
}

func cefHeader(class, name string, sev int) string {
	// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|
	return fmt.Sprintf("CEF:0|Sentinel|EDR-DLP|1.0|%s|%s|%d|", cefEscape(class), cefEscape(name), sev)
}

func cefExt(kv map[string]string) string {
	var b strings.Builder
	for k, v := range kv {
		if v == "" {
			continue
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(cefEscapeVal(v))
		b.WriteString(" ")
	}
	return strings.TrimSpace(b.String())
}

func cefEscape(s string) string {
	s = stripCtrl(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}
func cefEscapeVal(s string) string {
	s = stripCtrl(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "=", `\=`)
}

// stripCtrl neutralizes control characters in attacker-controllable fields before they enter
// a CEF/syslog line. Newlines AND carriage returns become spaces (a lone \r could otherwise
// inject a forged log line downstream); other control chars are dropped entirely.
func stripCtrl(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
}

// EventECS renders one event as an ECS JSON document.
func EventECS(e model.Event) string {
	doc := map[string]any{
		"@timestamp": e.TS.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": "9.3.0"},
		"event":      map[string]any{"category": string(e.Category), "action": e.Action, "severity": sevToCEF(e.Severity)},
		"host":       map[string]any{"name": e.Hostname, "id": e.AgentID},
		"user":       map[string]any{"name": e.User},
		"message":    e.Message,
		"observer":   map[string]any{"vendor": "Sentinel", "product": "EDR-DLP"},
	}
	if e.Process != nil {
		doc["process"] = map[string]any{"pid": e.Process.PID, "name": e.Process.Name, "command_line": e.Process.Cmdline, "parent": map[string]any{"name": e.Process.Parent}}
	}
	if e.Network != nil {
		doc["network"] = map[string]any{"direction": e.Network.Direction, "protocol": e.Network.Proto, "bytes": e.Network.BytesOut + e.Network.BytesIn}
		doc["destination"] = map[string]any{"domain": e.Network.Domain, "address": e.Network.Remote}
	}
	if e.File != nil {
		doc["file"] = map[string]any{"path": e.File.Path, "hash": map[string]any{"sha256": e.File.Hash}}
	}
	b, _ := json.Marshal(doc)
	return string(b)
}
