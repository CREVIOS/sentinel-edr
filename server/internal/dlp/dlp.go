// Package dlp implements content classification and policy enforcement for Data Loss
// Prevention. It scans text for sensitive-data patterns (PII, PCI, secrets, source code),
// validates candidates (e.g. Luhn for cards, entropy for secrets), and renders a policy
// verdict (audit / alert / block) per channel.
package dlp

import (
	"math"
	"regexp"
	"strings"

	"github.com/sentinel/server/internal/model"
)

// Classifier identifies one class of sensitive data.
type Classifier struct {
	Name     string
	Label    string
	Severity model.Severity
	re       *regexp.Regexp
	validate func(string) bool
}

// Finding is a single classifier hit.
type Finding struct {
	Classifier string
	Label      string
	Severity   model.Severity
	Matches    int
	Sample     string
}

// Policy maps (classifier, channel) to a verdict.
type Policy struct {
	Classifier string // "*" = any
	Channel    string // usb|scp|rsync|ftp|http_upload|email|cloud|"*"
	Verdict    string // audit|alert|block
}

// Engine holds classifiers and policies.
type Engine struct {
	classifiers []Classifier
	policies    []Policy
}

// New builds the default classifier + policy set.
func New() *Engine {
	e := &Engine{}
	e.classifiers = []Classifier{
		{Name: "pci_card", Label: "Payment card number", Severity: model.SevHigh,
			re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), validate: luhnValid},
		{Name: "pii_ssn", Label: "US Social Security Number", Severity: model.SevHigh,
			re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
		{Name: "pii_email", Label: "Email address (bulk)", Severity: model.SevLow,
			re: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
		{Name: "secret_aws", Label: "AWS access key", Severity: model.SevCritical,
			re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{Name: "secret_privkey", Label: "Private key material", Severity: model.SevCritical,
			re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
		{Name: "secret_token", Label: "High-entropy API token", Severity: model.SevHigh,
			re: regexp.MustCompile(`\b[A-Za-z0-9_\-]{32,64}\b`), validate: highEntropy},
		{Name: "secret_jwt", Label: "JSON Web Token", Severity: model.SevMedium,
			re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
		{Name: "source_code", Label: "Proprietary source code", Severity: model.SevMedium,
			re: regexp.MustCompile(`(?m)^\s*(package |import |func |class |def |#include|public class)`)},
	}
	// Default policy: block secrets/PCI/SSN on removable + network egress; alert/audit elsewhere.
	e.policies = []Policy{
		{Classifier: "secret_aws", Channel: "*", Verdict: "block"},
		{Classifier: "secret_privkey", Channel: "*", Verdict: "block"},
		{Classifier: "pci_card", Channel: "usb", Verdict: "block"},
		{Classifier: "pci_card", Channel: "http_upload", Verdict: "block"},
		{Classifier: "pci_card", Channel: "scp", Verdict: "block"},
		{Classifier: "pci_card", Channel: "rsync", Verdict: "block"},
		{Classifier: "pii_ssn", Channel: "usb", Verdict: "block"},
		{Classifier: "pii_ssn", Channel: "*", Verdict: "alert"},
		{Classifier: "source_code", Channel: "usb", Verdict: "alert"},
		{Classifier: "source_code", Channel: "cloud", Verdict: "alert"},
		{Classifier: "*", Channel: "*", Verdict: "audit"},
	}
	return e
}

// Classifiers exposes the loaded classifiers for the API/UI.
func (e *Engine) Classifiers() []map[string]string {
	var out []map[string]string
	for _, c := range e.classifiers {
		out = append(out, map[string]string{"name": c.Name, "label": c.Label, "severity": string(c.Severity)})
	}
	return out
}

// Policies exposes the policy table for the API/UI.
func (e *Engine) Policies() []Policy { return e.policies }

// Scan classifies a text blob, returning all findings.
func (e *Engine) Scan(text string) []Finding {
	var out []Finding
	if text == "" {
		return out
	}
	for _, c := range e.classifiers {
		hits := c.re.FindAllString(text, -1)
		if len(hits) == 0 {
			continue
		}
		valid := 0
		var sample string
		for _, h := range hits {
			cand := strings.TrimSpace(h)
			if c.validate != nil && !c.validate(cand) {
				continue
			}
			valid++
			if sample == "" {
				sample = redact(cand, c.Name)
			}
		}
		if valid == 0 {
			continue
		}
		out = append(out, Finding{
			Classifier: c.Name, Label: c.Label, Severity: c.Severity,
			Matches: valid, Sample: sample,
		})
	}
	return out
}

// Verdict resolves the strongest policy verdict for a finding on a channel.
func (e *Engine) Verdict(classifier, channel string) string {
	best := ""
	rank := map[string]int{"audit": 1, "alert": 2, "block": 3}
	for _, p := range e.policies {
		if (p.Classifier == classifier || p.Classifier == "*") &&
			(p.Channel == channel || p.Channel == "*") {
			if rank[p.Verdict] > rank[best] {
				best = p.Verdict
			}
		}
	}
	if best == "" {
		best = "audit"
	}
	return best
}

func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
}

// highEntropy gates the generic-token classifier so ordinary identifiers don't trip it.
func highEntropy(s string) bool {
	return shannon(s) >= 3.5 && hasMixedClasses(s)
}

func hasMixedClasses(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// redact masks a sample. PII/PAN classifiers are FULLY masked so no partial SSN/card digit is
// ever persisted to DB/console/SIEM (mirrors the agent-side policy); others keep a short hint.
// Operates on runes so multibyte input can't panic on a byte slice.
func redact(s, classifier string) string {
	r := []rune(s)
	if classifier == "pci_card" || classifier == "pii_ssn" || len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-4) + string(r[len(r)-2:])
}
