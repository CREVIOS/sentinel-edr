// Package ai provides LLM-assisted detection triage: it hands a structured evidence
// package (detection + related telemetry + endpoint context) to Claude and returns a
// decision-ready summary, assessment, and recommended next actions for the analyst.
package ai

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const systemPrompt = `You are a senior SOC (Security Operations Center) analyst triaging an EDR/DLP ` +
	`detection on a Linux endpoint. You are given a JSON evidence package containing the detection, ` +
	`the related telemetry events, and endpoint context.

Produce a decision-ready triage. Respond with ONLY a JSON object — no prose, no markdown code fences — ` +
	`of exactly this shape:
{
  "summary": "2-4 sentence plain-English explanation of what happened and why this fired",
  "assessment": "your judgment: likely true positive or false positive, how severe, and the reasoning",
  "recommended_actions": ["concrete next step", "..."],
  "confidence": "high" | "medium" | "low"
}

Base every claim strictly on the evidence provided; do not invent processes, users, or hosts that are ` +
	`not present. Order recommended_actions most-urgent-first and make them concrete and operational ` +
	`(for example: "Isolate the endpoint", "Kill PID 4471", "Disable account bob", "Confirm activity with the user"). ` +
	`Keep the summary tight and skip preamble.`

// Result is the triage verdict returned to the console.
type Result struct {
	Summary            string    `json:"summary"`
	Assessment         string    `json:"assessment"`
	RecommendedActions []string  `json:"recommended_actions"`
	Confidence         string    `json:"confidence"`
	Model              string    `json:"model"`
	GeneratedAt        time.Time `json:"generated_at"`
	Cached             bool      `json:"cached"`
}

// Triager calls Claude to triage detections. Construct with New; a nil *Triager means AI
// triage is not configured (no API key), and callers should surface that as "unavailable".
type Triager struct {
	client anthropic.Client
	model  anthropic.Model
	mu     sync.Mutex
	cache  map[string]Result // keyed by detection ID, so repeated views don't re-bill
}

// New builds a Triager, or returns nil when no API key is set (AI triage disabled).
func New(apiKey, modelID string) *Triager {
	if apiKey == "" {
		return nil
	}
	m := anthropic.ModelClaudeOpus4_8
	if modelID != "" {
		m = anthropic.Model(modelID)
	}
	return &Triager{
		client: anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:  m,
		cache:  map[string]Result{},
	}
}

// Triage returns the cached verdict for detID if present, otherwise calls Claude with the
// supplied evidence JSON and caches the result.
func (t *Triager) Triage(ctx context.Context, detID, evidence string) (*Result, error) {
	t.mu.Lock()
	if r, ok := t.cache[detID]; ok {
		t.mu.Unlock()
		r.Cached = true
		return &r, nil
	}
	t.mu.Unlock()

	resp, err := t.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     t.model,
		MaxTokens: 1500,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(evidence)),
		},
	})
	if err != nil {
		return nil, err
	}

	var text strings.Builder
	for _, block := range resp.Content {
		if b, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(b.Text)
		}
	}

	out := parseResult(text.String())
	out.Model = string(resp.Model)
	out.GeneratedAt = time.Now().UTC()

	t.mu.Lock()
	t.cache[detID] = out
	t.mu.Unlock()
	return &out, nil
}

// parseResult tolerates the model wrapping JSON in ```json fences or trailing prose; on a hard
// parse failure it degrades to surfacing the raw text as the summary rather than erroring out.
func parseResult(raw string) Result {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		s = strings.TrimPrefix(s, "json")
		if j := strings.Index(s, "```"); j >= 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	// Trim to the outermost JSON object if extra prose surrounds it.
	if start := strings.Index(s, "{"); start >= 0 {
		if end := strings.LastIndex(s, "}"); end > start {
			s = s[start : end+1]
		}
	}
	var r Result
	if err := json.Unmarshal([]byte(s), &r); err != nil || r.Summary == "" {
		return Result{
			Summary:    strings.TrimSpace(raw),
			Confidence: "low",
		}
	}
	return r
}
