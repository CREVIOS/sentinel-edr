// Package notify pushes detection alerts to external channels (Slack/Teams/Discord/generic
// webhook). Fire-and-forget, severity-gated, and throttled per rule+host so an alert storm
// can't flood the channel or block the pipeline. Disabled when no webhook URL is configured.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/sentinel/server/internal/model"
)

// Kind selects the outbound payload shape.
type Kind string

const (
	KindSlack   Kind = "slack"   // Slack / Mattermost incoming webhook ({"text":...})
	KindDiscord Kind = "discord" // Discord webhook ({"content":...})
	KindGeneric Kind = "generic" // raw JSON detection (for SOAR/n8n/custom)
)

// Notifier delivers alerts to a single webhook.
type Notifier struct {
	url     string
	kind    Kind
	minRank int
	client  *http.Client
	log     *slog.Logger

	mu     sync.Mutex
	lastGC time.Time
	sent   map[string]time.Time // throttle key -> last sent
}

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

// New builds a Notifier. url=="" → returns nil (alerting disabled). minSeverity gates which
// detections alert (default "high").
func New(url string, kind Kind, minSeverity string, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	if kind == "" {
		kind = KindGeneric
	}
	mr := rank(model.Severity(minSeverity))
	if mr == 0 {
		mr = rank(model.SevHigh)
	}
	return &Notifier{
		url: url, kind: kind, minRank: mr,
		client: &http.Client{Timeout: 8 * time.Second},
		log:    log, sent: map[string]time.Time{}, lastGC: time.Now(),
	}
}

// Notify sends an alert for a detection if it clears the severity gate and isn't throttled.
// Non-blocking: delivery runs in a goroutine.
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

	body := n.payload(d)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client.Do(req)
		if err != nil {
			n.log.Warn("alert delivery failed", "err", err, "rule", d.RuleID)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			n.log.Warn("alert webhook non-2xx", "status", resp.StatusCode, "rule", d.RuleID)
		}
	}()
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

func (n *Notifier) payload(d *model.Detection) []byte {
	text := "🛡️ *Sentinel* " + string(d.Severity) + " — *" + d.RuleName + "*\n" +
		"host: `" + d.Hostname + "`  user: `" + d.User + "`\n" +
		d.Summary
	var v any
	switch n.kind {
	case KindSlack:
		v = map[string]string{"text": text}
	case KindDiscord:
		v = map[string]string{"content": text}
	default: // generic: full detection JSON for SOAR pipelines
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
