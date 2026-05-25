// Package intel is a threat-intelligence (IOC) matcher: it loads indicators of compromise
// (SHA-256 file hashes, IPv4/IPv6 addresses, domains) from local feed files (and, optionally,
// remote URL feeds in OTX/abuse.ch/newline-list format) and matches them against the live
// event stream, raising detections. Lookups are O(1) hash-map; the store is rebuilt atomically
// on refresh so matching never blocks on a feed update.
package intel

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/server/internal/model"
)

// Kind classifies an indicator.
type Kind string

const (
	KindHash   Kind = "hash"   // sha256
	KindIP     Kind = "ip"     // ipv4/ipv6
	KindDomain Kind = "domain" // fqdn
)

type indicator struct {
	source   string
	severity model.Severity
}

// Engine holds the loaded indicator set.
type Engine struct {
	mu       sync.RWMutex
	hashes   map[string]indicator
	ips      map[string]indicator
	domains  map[string]indicator
	loadedAt time.Time
	count    int

	dir  string       // local feed directory (optional)
	urls []string     // remote feed URLs (optional)
	http *http.Client // for URL feeds
}

// New returns an empty engine.
func New() *Engine {
	return &Engine{
		hashes:  map[string]indicator{},
		ips:     map[string]indicator{},
		domains: map[string]indicator{},
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Sources configures the feed inputs used by Refresh. A local directory of feed files and/or a
// list of remote feed URLs (abuse.ch/OTX/newline lists). Call Refresh to (re)load from them.
func (e *Engine) Sources(dir string, urls []string) {
	e.mu.Lock()
	e.dir, e.urls = dir, urls
	e.mu.Unlock()
}

// Count returns how many indicators are loaded.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.count
}

// LoadDir sets dir as the local feed source and loads it (plus any configured URL feeds).
// Line formats accepted:
//
//	<value>                                  (type auto-detected, severity=high)
//	<value>,<type>,<severity>,<source>       (explicit; type/severity optional)
//
// Lines beginning with '#' or blank are ignored. The filename (sans ext) is the default source.
func (e *Engine) LoadDir(dir string) (int, error) {
	e.mu.Lock()
	e.dir = dir
	e.mu.Unlock()
	return e.Refresh()
}

// Refresh rebuilds the indicator set from the configured local directory and remote URL feeds,
// then swaps it in atomically so matching never blocks on a feed update. URL-fetch failures are
// returned but do not discard indicators gathered from the other sources — partial intel beats
// none. Returns the resulting indicator count.
func (e *Engine) Refresh() (int, error) {
	e.mu.RLock()
	dir, urls := e.dir, append([]string(nil), e.urls...)
	e.mu.RUnlock()

	h := map[string]indicator{}
	ip := map[string]indicator{}
	dom := map[string]indicator{}
	var errs []string

	if dir != "" {
		if err := scanDir(dir, h, ip, dom); err != nil {
			errs = append(errs, fmt.Sprintf("dir %s: %v", dir, err))
		}
	}
	for _, u := range urls {
		if err := e.fetchURL(u, h, ip, dom); err != nil {
			errs = append(errs, fmt.Sprintf("feed %s: %v", u, err))
		}
	}

	e.mu.Lock()
	e.hashes, e.ips, e.domains = h, ip, dom
	e.count = len(h) + len(ip) + len(dom)
	e.loadedAt = time.Now()
	cnt := e.count
	e.mu.Unlock()
	if len(errs) > 0 {
		return cnt, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return cnt, nil
}

// scanDir reads every *.txt / *.csv / *.ioc file in dir into the indicator maps.
func scanDir(dir string, h, ip, dom map[string]indicator) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(ent.Name()))
		if ext != ".txt" && ext != ".csv" && ext != ".ioc" {
			continue
		}
		src := strings.TrimSuffix(ent.Name(), filepath.Ext(ent.Name()))
		f, err := os.Open(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			addLine(sc.Text(), src, h, ip, dom)
		}
		f.Close()
	}
	return nil
}

// fetchURL downloads one remote feed and parses it line-by-line. Works with plain newline lists
// (abuse.ch Feodo/SSLBL, URLhaus) where each line is a bare indicator with '#' comments; the
// per-line CSV form (value,type,severity,source) is honoured too. The feed host is the default
// source label. Capped at 32 MiB to bound a hostile/huge response.
func (e *Engine) fetchURL(feed string, h, ip, dom map[string]indicator) error {
	req, err := http.NewRequest(http.MethodGet, feed, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "sentinel-edr/intel")
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	src := feed
	if u, err := url.Parse(feed); err == nil && u.Host != "" {
		src = u.Host
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 32<<20))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		addLine(sc.Text(), src, h, ip, dom)
	}
	return sc.Err()
}

func addLine(line, defSrc string, h, ip, dom map[string]indicator) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	parts := strings.Split(line, ",")
	val := strings.TrimSpace(parts[0])
	if val == "" {
		return
	}
	kind := classify(val)
	sev := model.SevHigh
	src := defSrc
	if len(parts) >= 2 && parts[1] != "" {
		if k := Kind(strings.ToLower(strings.TrimSpace(parts[1]))); k == KindHash || k == KindIP || k == KindDomain {
			kind = k
		}
	}
	if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
		sev = model.Severity(strings.ToLower(strings.TrimSpace(parts[2])))
	}
	if len(parts) >= 4 && strings.TrimSpace(parts[3]) != "" {
		src = strings.TrimSpace(parts[3])
	}
	ind := indicator{source: src, severity: sev}
	switch kind {
	case KindHash:
		h[strings.ToLower(val)] = ind
	case KindIP:
		ip[val] = ind
	case KindDomain:
		dom[strings.ToLower(strings.TrimPrefix(val, "*."))] = ind
	}
}

// classify guesses the indicator type from its shape.
func classify(v string) Kind {
	if len(v) == 64 && isHex(v) {
		return KindHash
	}
	if net.ParseIP(v) != nil {
		return KindIP
	}
	return KindDomain
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Match returns IOC detections for an event (file hash, remote IP, domain).
func (e *Engine) Match(ev *model.Event) []*model.Detection {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.count == 0 {
		return nil
	}
	var out []*model.Detection
	add := func(kind, value, source string, sev model.Severity) {
		out = append(out, &model.Detection{
			ID: uuid.NewString(), TS: time.Now().UTC(),
			RuleID: "ioc-" + kind, RuleName: "Threat-intel IOC match (" + kind + ")",
			Severity: sevOr(sev, model.SevHigh), Category: ev.Category,
			AgentID: ev.AgentID, Hostname: ev.Hostname, User: ev.User,
			Summary: "Known-bad " + kind + " observed: " + value + " (source: " + source + ")",
			MITRE:   []string{"T1071"}, Tactic: "Command and Control",
			Status: model.DetOpen, EventIDs: []string{ev.ID}, Engine: "ioc",
		})
	}
	if ev.File != nil && ev.File.Hash != "" {
		if ind, ok := e.hashes[strings.ToLower(ev.File.Hash)]; ok {
			add("hash", ev.File.Hash, ind.source, ind.severity)
		}
	}
	// executed-binary hash (sha256) — exact identity match against known-bad hashes
	if ev.Process != nil && ev.Process.Hash != "" {
		if ind, ok := e.hashes[strings.ToLower(ev.Process.Hash)]; ok {
			add("hash", ev.Process.Hash, ind.source, ind.severity)
		}
	}
	if ev.Network != nil {
		if host := ipOnly(ev.Network.Remote); host != "" {
			if ind, ok := e.ips[host]; ok {
				add("ip", host, ind.source, ind.severity)
			}
		}
		if d := strings.ToLower(ev.Network.Domain); d != "" {
			// match the domain itself or any listed parent suffix (down to 2 labels):
			// deep.c2.evil.test → checks deep.c2.evil.test, c2.evil.test, evil.test
			labels := strings.Split(d, ".")
			for i := 0; i+1 < len(labels); i++ {
				if ind, ok := e.domains[strings.Join(labels[i:], ".")]; ok {
					add("domain", d, ind.source, ind.severity)
					break
				}
			}
		}
	}
	return out
}

func sevOr(s, def model.Severity) model.Severity {
	switch s {
	case model.SevInfo, model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical:
		return s
	}
	return def
}

// ipOnly strips the :port (handles IPv6 [::1]:443 and 1.2.3.4:80).
func ipOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
	return ""
}
