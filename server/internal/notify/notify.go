// Package notify pushes detection alerts to external channels: webhooks (Slack / Mattermost,
// Discord rich embeds, generic JSON for SOAR) and email (SMTP). Delivery is fire-and-forget,
// severity-gated, and throttled per rule+host so an alert storm can't flood a channel or block
// the pipeline. A Notifier fans each qualifying detection to every configured sink.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/sentinel/server/internal/model"
)

// Kind selects the webhook payload shape.
type Kind string

const (
	KindSlack   Kind = "slack"   // Slack / Mattermost incoming webhook
	KindDiscord Kind = "discord" // Discord webhook (rich embed)
	KindGeneric Kind = "generic" // raw JSON detection (SOAR/n8n/custom)
)

const throttle = 5 * time.Minute

func rank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 5
	case model.SevHigh:
		return 4
	case model.SevMedium:
		return 3
	case model.SevLow:
		return 2
	case model.SevInfo:
		return 1
	}
	return 0
}

// severityColor returns a Discord/embed-friendly RGB int per severity.
func severityColor(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 0xD7263D // red
	case model.SevHigh:
		return 0xF46036 // orange
	case model.SevMedium:
		return 0xE2C044 // amber
	case model.SevLow:
		return 0x4C8BF5 // blue
	default:
		return 0x8A8D91 // grey
	}
}

// sink is one delivery channel.
type sink interface {
	send(d *model.Detection) error
	name() string
}

// Notifier gates + throttles detections and fans them to all sinks.
type Notifier struct {
	minRank int
	sinks   []sink
	log     *slog.Logger

	mu     sync.Mutex
	lastGC time.Time
	sent   map[string]time.Time
}

// Config builds a Notifier from settings. Returns nil when no sink is configured.
type Config struct {
	MinSeverity string
	// webhook
	WebhookURL  string
	WebhookKind Kind
	// email (SMTP)
	SMTPHost string
	SMTPPort string
	SMTPUser string
	SMTPPass string
	MailFrom string
	MailTo   string // comma-separated
	SMTPTLS  string // "starttls" (default, 587) | "implicit" (465) | "none"
}

// New builds a Notifier with all configured sinks. nil if none.
func New(c Config, log *slog.Logger) *Notifier {
	mr := rank(model.Severity(c.MinSeverity))
	if mr == 0 {
		mr = rank(model.SevHigh)
	}
	var sinks []sink
	if c.WebhookURL != "" {
		k := c.WebhookKind
		if k == "" {
			k = KindGeneric
		}
		sinks = append(sinks, &webhookSink{url: c.WebhookURL, kind: k, client: &http.Client{Timeout: 8 * time.Second}})
	}
	if c.SMTPHost != "" && c.MailFrom != "" && c.MailTo != "" {
		port := c.SMTPPort
		if port == "" {
			port = "587"
		}
		mode := strings.ToLower(c.SMTPTLS)
		if mode == "" {
			mode = "starttls"
		}
		var to []string
		for _, a := range strings.Split(c.MailTo, ",") {
			if a = strings.TrimSpace(a); a != "" {
				to = append(to, a)
			}
		}
		sinks = append(sinks, &emailSink{
			host: c.SMTPHost, port: port, user: c.SMTPUser, pass: c.SMTPPass,
			from: c.MailFrom, to: to, mode: mode,
		})
	}
	if len(sinks) == 0 {
		return nil
	}
	return &Notifier{minRank: mr, sinks: sinks, log: log, sent: map[string]time.Time{}, lastGC: time.Now()}
}

// Sinks returns the configured sink names (for startup logging).
func (n *Notifier) Sinks() []string {
	if n == nil {
		return nil
	}
	out := make([]string, len(n.sinks))
	for i, s := range n.sinks {
		out[i] = s.name()
	}
	return out
}

// Notify fans a qualifying detection to every sink. Non-blocking.
func (n *Notifier) Notify(d *model.Detection) {
	if n == nil || d == nil || rank(d.Severity) < n.minRank {
		return
	}
	key := d.RuleID + "|" + d.AgentID
	now := time.Now()
	n.mu.Lock()
	n.gc(now)
	if last, ok := n.sent[key]; ok && now.Sub(last) < throttle {
		n.mu.Unlock()
		return
	}
	n.sent[key] = now
	n.mu.Unlock()

	for _, s := range n.sinks {
		s := s
		go func() {
			if err := s.send(d); err != nil {
				n.log.Warn("alert delivery failed", "sink", s.name(), "rule", d.RuleID, "err", err)
			}
		}()
	}
}

func (n *Notifier) gc(now time.Time) {
	if now.Sub(n.lastGC) < throttle {
		return
	}
	n.lastGC = now
	for k, t := range n.sent {
		if now.Sub(t) > throttle {
			delete(n.sent, k)
		}
	}
}

// ---------------- webhook sink ----------------

type webhookSink struct {
	url    string
	kind   Kind
	client *http.Client
}

func (w *webhookSink) name() string { return "webhook:" + string(w.kind) }

func (w *webhookSink) send(d *model.Detection) error {
	body := w.payload(d)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func (w *webhookSink) payload(d *model.Detection) []byte {
	text := fmt.Sprintf("🛡️ Sentinel %s — %s\nhost: %s  user: %s\n%s",
		strings.ToUpper(string(d.Severity)), d.RuleName, d.Hostname, nz(d.User), d.Summary)
	var v any
	switch w.kind {
	case KindSlack:
		v = map[string]string{"text": text}
	case KindDiscord:
		// rich embed: severity-colored, structured fields
		v = map[string]any{
			"username": "Sentinel",
			"embeds": []map[string]any{{
				"title":       fmt.Sprintf("%s — %s", strings.ToUpper(string(d.Severity)), d.RuleName),
				"description": d.Summary,
				"color":       severityColor(d.Severity),
				"fields": []map[string]any{
					{"name": "Host", "value": nz(d.Hostname), "inline": true},
					{"name": "User", "value": nz(d.User), "inline": true},
					{"name": "Tactic", "value": nz(d.Tactic), "inline": true},
					{"name": "MITRE", "value": nz(strings.Join(d.MITRE, ", ")), "inline": true},
					{"name": "Engine", "value": nz(d.Engine), "inline": true},
				},
				"footer":    map[string]any{"text": "Sentinel EDR/DLP"},
				"timestamp": d.TS.UTC().Format(time.RFC3339),
			}},
		}
	default:
		v = map[string]any{
			"source": "sentinel", "severity": string(d.Severity), "rule_id": d.RuleID,
			"rule_name": d.RuleName, "hostname": d.Hostname, "agent_id": d.AgentID,
			"user": d.User, "summary": d.Summary, "tactic": d.Tactic, "mitre": d.MITRE,
			"engine": d.Engine, "ts": d.TS,
		}
	}
	b, _ := json.Marshal(v)
	return b
}

// ---------------- email (SMTP) sink ----------------

type emailSink struct {
	host, port, user, pass, from string
	to                           []string
	mode                         string // starttls | implicit | none
}

func (e *emailSink) name() string { return "email" }

func (e *emailSink) send(d *model.Detection) error {
	msg := e.message(d)
	addr := e.host + ":" + e.port
	var auth smtp.Auth
	if e.user != "" {
		auth = smtp.PlainAuth("", e.user, e.pass, e.host)
	}
	switch e.mode {
	case "implicit": // TLS from the start (port 465)
		return e.sendImplicitTLS(addr, auth, msg)
	case "none": // plaintext (lab only)
		return smtp.SendMail(addr, auth, e.from, e.to, msg)
	default: // starttls (port 587) — smtp.SendMail upgrades via STARTTLS when offered
		return smtp.SendMail(addr, auth, e.from, e.to, msg)
	}
}

func (e *emailSink) sendImplicitTLS(addr string, auth smtp.Auth, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: e.host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, e.host)
	if err != nil {
		return err
	}
	defer c.Quit()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(e.from); err != nil {
		return err
	}
	for _, rcpt := range e.to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	return wc.Close()
}

func (e *emailSink) message(d *model.Detection) []byte {
	// RFC5322. Subject + plaintext body. Header-inject-safe: detection fields are sanitized
	// (CR/LF stripped) before going into the Subject.
	// Sanitize every interpolated field: strip CR/LF so attacker-controlled values (hostname,
	// rule name, summary, user) can't inject SMTP headers (in Subject) or forge body lines.
	subj := sanitizeHeader(fmt.Sprintf("[Sentinel %s] %s on %s",
		strings.ToUpper(string(d.Severity)), sanitizeHeader(d.RuleName), sanitizeHeader(d.Hostname)))
	body := fmt.Sprintf(
		"Severity: %s\r\nRule:     %s (%s)\r\nHost:     %s\r\nUser:     %s\r\nTactic:   %s\r\nMITRE:    %s\r\nEngine:   %s\r\nTime:     %s\r\n\r\n%s\r\n",
		d.Severity, sanitizeHeader(d.RuleName), sanitizeHeader(d.RuleID), sanitizeHeader(d.Hostname),
		sanitizeHeader(nz(d.User)), sanitizeHeader(nz(d.Tactic)), sanitizeHeader(strings.Join(d.MITRE, ", ")),
		sanitizeHeader(d.Engine), d.TS.UTC().Format(time.RFC3339), sanitizeHeader(d.Summary))
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subj)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

// sanitizeHeader strips CR/LF to prevent SMTP header injection via attacker-controlled fields
// (hostname, rule name) that flow into the Subject.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func nz(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
