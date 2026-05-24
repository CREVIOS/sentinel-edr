// Package detect implements a Sigma-style rule engine. Rules are YAML, log-source
// agnostic, and carry MITRE ATT&CK technique ids. Each incoming event is flattened to
// dotted-key fields and evaluated against every loaded rule; matches become Detections.
package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
	"gopkg.in/yaml.v3"
)

// Rule is a simplified Sigma rule.
type Rule struct {
	ID            string                       `yaml:"id"`
	Title         string                       `yaml:"title"`
	Status        string                       `yaml:"status"`
	Description   string                       `yaml:"description"`
	Severity      model.Severity               `yaml:"severity"`
	Category      model.Category               `yaml:"category"`
	MITRE         []string                     `yaml:"mitre"`
	Tactic        string                       `yaml:"tactic"`
	FalsePositive []string                     `yaml:"falsepositives"`
	AutoRespond   string                       `yaml:"auto_respond"` // kill_process|isolate|block_upload|disable_account
	Detection     map[string]map[string]any    `yaml:"-"`            // selections, filled from raw
	Condition     string                       `yaml:"-"`
	raw           map[string]any               // raw detection block

	// compiled selection -> field -> matcher
	compiled map[string][]matcher
}

type matcher struct {
	field    string
	modifier string
	values   []string
	regexps  []*regexp.Regexp
	num      *float64
}

// Engine holds the loaded rule set.
type Engine struct {
	rules []*Rule
}

// New creates an empty engine.
func New() *Engine { return &Engine{} }

// Rules returns the loaded rules (for the API).
func (e *Engine) Rules() []*Rule { return e.rules }

// LoadDir loads every *.yml / *.yaml rule under dir.
func (e *Engine) LoadDir(dir string) (int, error) {
	var loaded int
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		r, err := loadRuleFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := r.compile(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		e.rules = append(e.rules, r)
		loaded++
		return nil
	})
	sort.Slice(e.rules, func(i, j int) bool { return e.rules[i].ID < e.rules[j].ID })
	return loaded, err
}

// rawRule mirrors the YAML so we can pull the freeform detection block.
type rawRule struct {
	ID            string         `yaml:"id"`
	Title         string         `yaml:"title"`
	Status        string         `yaml:"status"`
	Description   string         `yaml:"description"`
	Severity      model.Severity `yaml:"severity"`
	Category      model.Category `yaml:"category"`
	MITRE         []string       `yaml:"mitre"`
	Tactic        string         `yaml:"tactic"`
	FalsePositive []string       `yaml:"falsepositives"`
	AutoRespond   string         `yaml:"auto_respond"`
	Detection     map[string]any `yaml:"detection"`
}

func loadRuleFile(path string) (*Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rr rawRule
	if err := yaml.Unmarshal(b, &rr); err != nil {
		return nil, err
	}
	r := &Rule{
		ID: rr.ID, Title: rr.Title, Status: rr.Status, Description: rr.Description,
		Severity: rr.Severity, Category: rr.Category, MITRE: rr.MITRE, Tactic: rr.Tactic,
		FalsePositive: rr.FalsePositive, AutoRespond: rr.AutoRespond,
		Detection: map[string]map[string]any{},
	}
	for k, v := range rr.Detection {
		if k == "condition" {
			r.Condition, _ = v.(string)
			continue
		}
		if m, ok := v.(map[string]any); ok {
			r.Detection[k] = m
		}
	}
	if r.ID == "" || r.Title == "" {
		return nil, fmt.Errorf("rule missing id or title")
	}
	if r.Condition == "" {
		// default: AND of all selections
		var names []string
		for k := range r.Detection {
			names = append(names, k)
		}
		r.Condition = strings.Join(names, " and ")
	}
	return r, nil
}

func (r *Rule) compile() error {
	r.compiled = map[string][]matcher{}
	for sel, fields := range r.Detection {
		var ms []matcher
		for rawField, val := range fields {
			parts := strings.SplitN(rawField, "|", 2)
			m := matcher{field: parts[0]}
			if len(parts) == 2 {
				m.modifier = parts[1]
			}
			for _, s := range toStringList(val) {
				m.values = append(m.values, s)
			}
			if m.modifier == "re" {
				for _, s := range m.values {
					re, err := regexp.Compile("(?i)" + s)
					if err != nil {
						return fmt.Errorf("rule %s bad regex %q: %w", r.ID, s, err)
					}
					m.regexps = append(m.regexps, re)
				}
			}
			if strings.HasPrefix(m.modifier, "gt") || strings.HasPrefix(m.modifier, "lt") {
				if len(m.values) > 0 {
					if f, err := strconv.ParseFloat(m.values[0], 64); err == nil {
						m.num = &f
					}
				}
			}
			ms = append(ms, m)
		}
		r.compiled[sel] = ms
	}
	return nil
}

// Eval runs every rule against one event; returns fired detections.
func (e *Engine) Eval(ev *model.Event) []*model.Detection {
	flat := flatten(ev)
	var out []*model.Detection
	for _, r := range e.rules {
		// quick category gate (if rule scoped to a category)
		if r.Category != "" && r.Category != ev.Category {
			// allow cross-category rules only when category unset
			continue
		}
		if e.match(r, flat) {
			out = append(out, r.toDetection(ev))
		}
	}
	return out
}

// AutoRespondFor returns the configured auto-response for a rule id (if any).
func (e *Engine) AutoRespondFor(ruleID string) string {
	for _, r := range e.rules {
		if r.ID == ruleID {
			return r.AutoRespond
		}
	}
	return ""
}

func (r *Rule) toDetection(ev *model.Event) *model.Detection {
	sev := r.Severity
	if sev == "" {
		sev = model.SevMedium
	}
	return &model.Detection{
		ID:       uuid.NewString(),
		TS:       time.Now().UTC(),
		RuleID:   r.ID,
		RuleName: r.Title,
		Severity: sev,
		Category: ev.Category,
		AgentID:  ev.AgentID,
		Hostname: ev.Hostname,
		User:     ev.User,
		Summary:  r.Title + " — " + ev.Message,
		MITRE:    r.MITRE,
		Tactic:   r.Tactic,
		Status:   model.DetOpen,
		EventIDs: []string{ev.ID},
		Engine:   "sigma",
	}
}

func (e *Engine) match(r *Rule, flat map[string][]string) bool {
	selResult := map[string]bool{}
	for sel, ms := range r.compiled {
		selResult[sel] = matchSelection(ms, flat)
	}
	return evalCondition(r.Condition, selResult)
}

// matchSelection ANDs all field matchers; each field matcher ORs its values.
func matchSelection(ms []matcher, flat map[string][]string) bool {
	for _, m := range ms {
		if !m.eval(flat) {
			return false
		}
	}
	return len(ms) > 0
}

func (m matcher) eval(flat map[string][]string) bool {
	have := flat[m.field]
	switch {
	case strings.HasPrefix(m.modifier, "gt") || strings.HasPrefix(m.modifier, "lt"):
		if m.num == nil || len(have) == 0 {
			return false
		}
		v, err := strconv.ParseFloat(have[0], 64)
		if err != nil {
			return false
		}
		switch m.modifier {
		case "gt":
			return v > *m.num
		case "gte":
			return v >= *m.num
		case "lt":
			return v < *m.num
		case "lte":
			return v <= *m.num
		}
		return false
	case m.modifier == "re":
		for _, h := range have {
			for _, re := range m.regexps {
				if re.MatchString(h) {
					return true
				}
			}
		}
		return false
	default:
		for _, h := range have {
			hl := strings.ToLower(h)
			for _, want := range m.values {
				wl := strings.ToLower(want)
				switch m.modifier {
				case "contains":
					if strings.Contains(hl, wl) {
						return true
					}
				case "startswith":
					if strings.HasPrefix(hl, wl) {
						return true
					}
				case "endswith":
					if strings.HasSuffix(hl, wl) {
						return true
					}
				default:
					if hl == wl {
						return true
					}
				}
			}
		}
		return false
	}
}

// ---------- condition evaluation ----------

// evalCondition supports: selection names, and/or/not, parentheses,
// "all of them", "1 of them"/"any of them", "all of pre*", "1 of pre*".
func evalCondition(cond string, sel map[string]bool) bool {
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return false
	}
	// expand "X of ..." aggregates into parenthesized boolean groups
	cond = expandAggregates(cond, sel)
	toks := tokenize(cond)
	p := &parser{toks: toks, sel: sel}
	v := p.parseExpr()
	return v
}

func expandAggregates(cond string, sel map[string]bool) string {
	names := make([]string, 0, len(sel))
	for k := range sel {
		names = append(names, k)
	}
	repl := func(quantAll bool, glob string) string {
		var group []string
		for _, n := range names {
			if glob == "them" || globMatch(glob, n) {
				group = append(group, n)
			}
		}
		if len(group) == 0 {
			return "false"
		}
		op := " or "
		if quantAll {
			op = " and "
		}
		return "( " + strings.Join(group, op) + " )"
	}
	re := regexp.MustCompile(`(?i)(all|1|any)\s+of\s+([a-zA-Z0-9_*]+)`)
	return re.ReplaceAllStringFunc(cond, func(s string) string {
		m := re.FindStringSubmatch(s)
		return repl(strings.EqualFold(m[1], "all"), m[2])
	})
}

func globMatch(glob, name string) bool {
	if strings.HasSuffix(glob, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(glob, "*"))
	}
	return glob == name
}

func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type parser struct {
	toks []string
	pos  int
	sel  map[string]bool
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}
func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

// expr := term (or term)*
func (p *parser) parseExpr() bool {
	v := p.parseTerm()
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		r := p.parseTerm()
		v = v || r
	}
	return v
}

// term := factor (and factor)*
func (p *parser) parseTerm() bool {
	v := p.parseFactor()
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		r := p.parseFactor()
		v = v && r
	}
	return v
}

// factor := not factor | ( expr ) | name
func (p *parser) parseFactor() bool {
	t := p.peek()
	if strings.EqualFold(t, "not") {
		p.next()
		return !p.parseFactor()
	}
	if t == "(" {
		p.next()
		v := p.parseExpr()
		if p.peek() == ")" {
			p.next()
		}
		return v
	}
	name := p.next()
	switch strings.ToLower(name) {
	case "true":
		return true
	case "false":
		return false
	}
	return p.sel[name]
}

// ---------- event flattening ----------

func flatten(ev *model.Event) map[string][]string {
	f := map[string][]string{}
	put := func(k, v string) {
		if v != "" {
			f[k] = append(f[k], v)
		}
	}
	put("category", string(ev.Category))
	put("action", ev.Action)
	put("severity", string(ev.Severity))
	put("user", ev.User)
	put("message", ev.Message)
	put("hostname", ev.Hostname)
	for _, l := range ev.Labels {
		put("labels", l)
	}
	if p := ev.Process; p != nil {
		put("process.name", p.Name)
		put("process.exe", p.Exe)
		put("process.cmdline", p.Cmdline)
		put("process.parent", p.Parent)
		put("process.user", p.User)
		put("process.pid", strconv.Itoa(p.PID))
		put("process.ppid", strconv.Itoa(p.PPID))
		put("process.uid", strconv.Itoa(p.UID))
		put("process.lineage", p.Lineage)
		put("process.container", p.Container)
	}
	if fi := ev.File; fi != nil {
		put("file.path", fi.Path)
		put("file.op", fi.Op)
		put("file.hash", fi.Hash)
		put("file.mode", fi.Mode)
		put("file.size", strconv.FormatInt(fi.Size, 10))
	}
	if n := ev.Network; n != nil {
		put("network.direction", n.Direction)
		put("network.proto", n.Proto)
		put("network.remote", n.Remote)
		put("network.domain", n.Domain)
		put("network.url", n.URL)
		put("network.category", n.Category)
		put("network.bytes_out", strconv.FormatInt(n.BytesOut, 10))
		put("network.bytes_in", strconv.FormatInt(n.BytesIn, 10))
	}
	if u := ev.USB; u != nil {
		put("usb.action", u.Action)
		put("usb.vendor", u.Vendor)
		put("usb.product", u.Product)
		put("usb.serial", u.Serial)
		put("usb.mount", u.Mount)
	}
	if a := ev.Auth; a != nil {
		put("auth.method", a.Method)
		put("auth.source_ip", a.SourceIP)
		put("auth.result", a.Result)
		put("auth.tty", a.TTY)
	}
	if d := ev.DLP; d != nil {
		put("dlp.classifier", d.Classifier)
		put("dlp.channel", d.Channel)
		put("dlp.verdict", d.Verdict)
	}
	for k, v := range ev.Extra {
		for _, s := range toStringList(v) {
			put("extra."+k, s)
		}
	}
	return f
}

func toStringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case int:
		return []string{strconv.Itoa(t)}
	case float64:
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	case bool:
		return []string{strconv.FormatBool(t)}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, toStringList(e)...)
		}
		return out
	}
	return nil
}
