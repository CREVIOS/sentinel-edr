// Package api exposes the REST + WebSocket surface: console endpoints (JWT/RBAC), the
// agent data plane (enrollment, batched event ingest, command WebSocket), health probes,
// SIEM export, and the embedded single-page console. Security headers, rate limiting and
// input validation are applied centrally.
package api

import (
	"crypto/hmac"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/sentinel/server/internal/auth"
	"github.com/sentinel/server/internal/bus"
	"github.com/sentinel/server/internal/config"
	"github.com/sentinel/server/internal/detect"
	"github.com/sentinel/server/internal/dlp"
	"github.com/sentinel/server/internal/hub"
	"github.com/sentinel/server/internal/model"
	"github.com/sentinel/server/internal/respond"
	"github.com/sentinel/server/internal/siem"
	"github.com/sentinel/server/internal/store"
	"github.com/sentinel/server/internal/transport"
)

// Server holds the API dependencies.
type Server struct {
	cfg         *config.Config
	store       store.Store
	auth        *auth.Manager
	hub         *hub.Hub
	bcast       transport.Broadcaster
	bus         bus.Bus
	detect      *detect.Engine
	dlp         *dlp.Engine
	respond     *respond.Orchestrator
	limiter     *auth.Limiter
	ingestLimit *auth.Limiter
	log         *slog.Logger
	upgrader    websocket.Upgrader
}

// Deps bundles what the API needs.
type Deps struct {
	Cfg     *config.Config
	Store   store.Store
	Auth    *auth.Manager
	Hub     *hub.Hub
	Bcast   transport.Broadcaster
	Bus     bus.Bus
	Detect  *detect.Engine
	DLP     *dlp.Engine
	Respond *respond.Orchestrator
	Log     *slog.Logger
}

// New builds the API server.
func New(d Deps) *Server {
	allow := map[string]bool{}
	for _, o := range d.Cfg.AllowOrigins {
		allow[strings.TrimSpace(o)] = true
	}
	bcast := d.Bcast
	if bcast == nil {
		bcast = d.Hub
	}
	return &Server{
		cfg: d.Cfg, store: d.Store, auth: d.Auth, hub: d.Hub, bcast: bcast, bus: d.Bus,
		detect: d.Detect, dlp: d.DLP, respond: d.Respond,
		limiter:     auth.NewLimiter(5, 15),     // auth surface: 5 req/s, burst 15
		ingestLimit: auth.NewLimiter(500, 1000), // ingest surface, per source IP
		log:         d.Log,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // non-browser client (agent)
				}
				if len(allow) > 0 {
					return allow[origin]
				}
				// default: same-origin only
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				return strings.EqualFold(u.Host, r.Host)
			},
		},
	}
}

// Handler returns the fully wired HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// health / readiness / metrics
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /metrics", s.metrics)

	// agent data plane
	mux.HandleFunc("POST /api/v1/enroll", s.requireAgentMTLS(s.limiter.Middleware(s.enroll)))
	mux.HandleFunc("POST /api/v1/events", s.requireAgentMTLS(s.ingestEvents))
	mux.HandleFunc("GET /agent/ws", s.requireAgentMTLS(s.agentWS))

	// console auth
	mux.HandleFunc("POST /api/v1/login", s.limiter.Middleware(s.login))
	mux.HandleFunc("POST /api/v1/logout", s.logout)

	// console read APIs (viewer+)
	mux.HandleFunc("GET /api/v1/agents", s.auth.Require(auth.RoleViewer, s.listAgents))
	mux.HandleFunc("GET /api/v1/agents/{id}", s.auth.Require(auth.RoleViewer, s.getAgent))
	mux.HandleFunc("GET /api/v1/events", s.auth.Require(auth.RoleViewer, s.listEvents))
	mux.HandleFunc("GET /api/v1/detections", s.auth.Require(auth.RoleViewer, s.listDetections))
	mux.HandleFunc("GET /api/v1/responses", s.auth.Require(auth.RoleViewer, s.listResponses))
	mux.HandleFunc("GET /api/v1/rules", s.auth.Require(auth.RoleViewer, s.listRules))
	mux.HandleFunc("GET /api/v1/dlp/policies", s.auth.Require(auth.RoleViewer, s.dlpPolicies))
	mux.HandleFunc("GET /api/v1/dlp/classifiers", s.auth.Require(auth.RoleViewer, s.dlpClassifiers))
	mux.HandleFunc("GET /api/v1/stats/overview", s.auth.Require(auth.RoleViewer, s.overview))
	mux.HandleFunc("GET /api/v1/siem/export", s.auth.Require(auth.RoleAnalyst, s.siemExport))

	// console write APIs (analyst+)
	mux.HandleFunc("POST /api/v1/detections/{id}/status", s.auth.Require(auth.RoleAnalyst, s.setDetectionStatus))
	mux.HandleFunc("POST /api/v1/respond", s.auth.Require(auth.RoleAnalyst, s.issueResponse))

	// console live feed (JWT via Sec-WebSocket-Protocol)
	mux.HandleFunc("GET /ws", s.consoleWS)

	// embedded SPA
	mux.HandleFunc("GET /", s.serveSPA)

	return securityHeaders(mux)
}

// ---------- agent data plane ----------

type enrollReq struct {
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Kernel   string   `json:"kernel"`
	Arch     string   `json:"arch"`
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Version  string   `json:"version"`
	Labels   []string `json:"labels"`
}

type enrollResp struct {
	AgentID string `json:"agent_id"`
	Key     string `json:"key"`
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !constTimeEqual(r.Header.Get("X-Enroll-Token"), s.cfg.EnrollToken) {
		http.Error(w, "invalid enrollment token", http.StatusUnauthorized)
		return
	}
	var req enrollReq
	if err := readJSON(r, &req, 1<<16); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	a := &model.Agent{
		ID: uuid.NewString(), Hostname: req.Hostname, OS: req.OS, Kernel: req.Kernel, Arch: req.Arch,
		IP: s.clientIP(r, req.IP), MAC: req.MAC, Version: req.Version, Status: model.StatusOnline,
		Labels: req.Labels, EnrolledAt: now, LastSeen: now, Key: uuid.NewString(),
	}
	if err := s.store.UpsertAgent(a); err != nil {
		s.log.Error("enroll", "err", err)
		http.Error(w, "enroll failed", http.StatusInternalServerError)
		return
	}
	s.bcast.Broadcast("agent", a)
	writeJSON(w, http.StatusOK, enrollResp{AgentID: a.ID, Key: a.Key})
}

func (s *Server) ingestEvents(w http.ResponseWriter, r *http.Request) {
	if !s.ingestLimit.Allow(s.clientIP(r, "")) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	agentID := r.Header.Get("X-Agent-Id")
	key := r.Header.Get("X-Agent-Key")
	ag, err := s.store.GetAgent(agentID)
	if err != nil || ag == nil || !constTimeEqual(key, ag.Key) {
		http.Error(w, "unauthorized agent", http.StatusUnauthorized)
		return
	}
	var batch model.EventBatch
	if err := readJSON(r, &batch, 8<<20); err != nil { // 8 MB cap
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	accepted := 0
	failed := 0
	for i := range batch.Events {
		ev := &batch.Events[i]
		// server-authoritative fields: never trust the agent for identity
		ev.AgentID = agentID
		ev.Hostname = ag.Hostname
		if ev.ID == "" {
			ev.ID = uuid.NewString()
		}
		if ev.TS.IsZero() {
			ev.TS = time.Now().UTC()
		}
		if ev.Severity == "" {
			ev.Severity = model.SevInfo
		}
		b, _ := json.Marshal(ev)
		if err := s.bus.Publish(bus.SubjectEvents, b); err != nil {
			s.log.Error("bus publish", "err", err)
			failed++
			continue
		}
		accepted++
	}
	if err := s.store.Heartbeat(agentID, accepted); err != nil {
		s.log.Error("heartbeat", "agent", agentID, "err", err)
	}
	// If any event failed to publish, do NOT report success — return 503 so the agent keeps
	// the batch in its encrypted spool and retries. Acking on failure would lose telemetry.
	if failed > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]int{"accepted": accepted, "failed": failed})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"accepted": accepted})
}

func (s *Server) agentWS(w http.ResponseWriter, r *http.Request) {
	// Credentials travel in headers, never the URL (avoids proxy/access-log leakage).
	agentID := r.Header.Get("X-Agent-Id")
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ag, err := s.store.GetAgent(agentID)
	if err != nil || ag == nil || !constTimeEqual(key, ag.Key) {
		http.Error(w, "unauthorized agent", http.StatusUnauthorized)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.hub.AddAgent(agentID, conn)
	_ = s.store.SetAgentStatus(agentID, model.StatusOnline)
	s.log.Info("agent connected", "agent", agentID, "host", ag.Hostname)
	defer func() {
		s.hub.RemoveAgent(agentID)
		s.log.Info("agent disconnected", "agent", agentID)
	}()
	conn.SetReadLimit(1 << 16)
	// Half-open detection: ping the agent periodically and require a pong within pongWait.
	// Without this a network partition leaves this goroutine blocked in ReadMessage forever,
	// leaking a goroutine + DB connection per dead agent across the fleet.
	const pongWait = 120 * time.Second
	const pingEvery = 45 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(pingEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if !s.hub.PingAgent(agentID) {
					return
				}
			}
		}
	}()
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		var res model.CommandResult
		if json.Unmarshal(data, &res) == nil && res.ID != "" {
			s.hub.DeliverResult(agentID, res) // scoped to this authenticated agent
		}
	}
}

// ---------- console auth ----------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := readJSON(r, &req, 1<<16); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, role, err := s.auth.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_session",
		Value:    tok,
		Path:     "/",
		MaxAge:   int((12 * time.Hour).Seconds()),
		HttpOnly: true,
		// Secure when TLS is local OR terminated upstream (behind-proxy prod), so the auth
		// cookie is never sent in cleartext.
		Secure:   s.cfg.TLSEnabled() || s.cfg.BehindProxy,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "role": string(role), "user": req.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.TLSEnabled(),
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ---------- console reads ----------

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListAgents()
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAgent(r.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{
		AgentID:  q.Get("agent_id"),
		Category: q.Get("category"),
		Severity: q.Get("severity"),
		User:     q.Get("user"),
		Search:   q.Get("q"),
		Limit:    atoiDefault(q.Get("limit"), 200),
		Offset:   atoiDefault(q.Get("offset"), 0),
	}
	// `since` cursor enables cheap live-tail polling (only newer rows).
	if sv := q.Get("since"); sv != "" {
		if t, err := time.Parse(time.RFC3339Nano, sv); err == nil {
			f.Since = &t
		}
	}
	evs, err := s.store.QueryEvents(f)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) listDetections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dets, err := s.store.ListDetections(atoiDefault(q.Get("limit"), 200), q.Get("status"))
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dets)
}

func (s *Server) listResponses(w http.ResponseWriter, r *http.Request) {
	resps, err := s.store.ListResponses(atoiDefault(r.URL.Query().Get("limit"), 200))
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resps)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	type ruleDTO struct {
		ID, Title, Severity, Category, Tactic, Description, AutoRespond string
		MITRE                                                           []string
	}
	var out []ruleDTO
	for _, rl := range s.detect.Rules() {
		out = append(out, ruleDTO{
			ID: rl.ID, Title: rl.Title, Severity: string(rl.Severity), Category: string(rl.Category),
			Tactic: rl.Tactic, Description: rl.Description, AutoRespond: rl.AutoRespond, MITRE: rl.MITRE,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) dlpPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.dlp.Policies())
}
func (s *Server) dlpClassifiers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.dlp.Classifiers())
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	counts, _ := s.store.Counts()
	sev, _ := s.store.SeverityBreakdown()
	cats, _ := s.store.EventsPerCategory()
	timeline, _ := s.store.EventTimeline()
	mitre, _ := s.store.TopMitre(8)
	writeJSON(w, http.StatusOK, map[string]any{
		"counts":             counts,
		"severity":           sev,
		"events_by_category": cats,
		"timeline":           timeline,
		"top_mitre":          mitre,
	})
}

func (s *Server) siemExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	kind := q.Get("kind")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch kind {
	case "detections":
		dets, _ := s.store.ListDetections(1000, "")
		for _, d := range dets {
			io.WriteString(w, siem.DetectionCEF(d)+"\n")
		}
	default:
		evs, _ := s.store.QueryEvents(store.EventFilter{Limit: 1000})
		for _, e := range evs {
			if format == "ecs" {
				io.WriteString(w, siem.EventECS(e)+"\n")
			} else {
				io.WriteString(w, siem.EventCEF(e)+"\n")
			}
		}
	}
}

// ---------- console writes ----------

func (s *Server) setDetectionStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := readJSON(r, &req, 1<<16); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	st := model.DetectionStatus(req.Status)
	if st != model.DetOpen && st != model.DetAck && st != model.DetClosed {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	user := auth.UserFromContext(r.Context())
	if err := s.store.UpdateDetectionStatus(r.PathValue("id"), st, user); err != nil {
		serverError(w, err)
		return
	}
	d, err := s.store.GetDetection(r.PathValue("id"))
	if err != nil || d == nil {
		// The update committed; only the re-fetch failed. Acknowledge success without a
		// null body so callers don't dereference nil.
		writeJSON(w, http.StatusOK, map[string]string{"id": r.PathValue("id"), "status": string(st)})
		return
	}
	s.bcast.Broadcast("detection", d)
	writeJSON(w, http.StatusOK, d)
}

type respondReq struct {
	Type        string         `json:"type"`
	AgentID     string         `json:"agent_id"`
	Target      map[string]any `json:"target"`
	Reason      string         `json:"reason"`
	DetectionID string         `json:"detection_id"`
}

func (s *Server) issueResponse(w http.ResponseWriter, r *http.Request) {
	var req respondReq
	if err := readJSON(r, &req, 1<<16); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !validResponseType(req.Type) || req.AgentID == "" {
		http.Error(w, "invalid response request", http.StatusBadRequest)
		return
	}
	a := &model.ResponseAction{
		Type: model.ResponseType(req.Type), AgentID: req.AgentID, Target: req.Target,
		Reason: req.Reason, DetectionID: req.DetectionID,
		IssuedBy: auth.UserFromContext(r.Context()),
	}
	if a.Target == nil {
		a.Target = map[string]any{}
	}
	out, err := s.respond.Issue(a)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------- websockets ----------

func (s *Server) consoleWS(w http.ResponseWriter, r *http.Request) {
	// Token is carried in the Sec-WebSocket-Protocol header (["bearer", <jwt>]),
	// keeping it out of the URL/query string and access logs.
	tok := ""
	protos := websocket.Subprotocols(r)
	for i, p := range protos {
		if p == "bearer" && i+1 < len(protos) {
			tok = protos[i+1]
		}
	}
	if tok == "" {
		if c, err := r.Cookie("sentinel_session"); err == nil {
			tok = c.Value
		}
		if tok == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
	}
	if _, _, err := s.auth.Verify(tok); err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	respHeader := http.Header{}
	respHeader.Set("Sec-WebSocket-Protocol", "bearer")
	conn, err := s.upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		return
	}
	s.hub.AddConsole(conn)
	defer s.hub.RemoveConsole(conn)
	conn.SetReadLimit(4096)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

// ---------- SPA + readiness ----------

func (s *Server) requireAgentMTLS(next http.HandlerFunc) http.HandlerFunc {
	if !s.cfg.MTLSEnabled() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "agent client certificate required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if _, err := s.store.Counts(); err != nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready"))
}

// metrics exposes Prometheus-format gauges scraped from the store. When SENTINEL_METRICS_TOKEN
// is set it requires that bearer token (fleet/security counters shouldn't be world-readable);
// left open otherwise for standard internal Prometheus scraping.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsToken != "" && strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != s.cfg.MetricsToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	counts, err := s.store.Counts()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if err != nil {
		http.Error(w, "# metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	gauges := map[string]string{
		"agents_total":        "Enrolled endpoints",
		"agents_online":       "Endpoints currently online",
		"agents_isolated":     "Endpoints under network isolation",
		"events_24h":          "Events ingested in the last 24h",
		"detections_open":     "Open detections",
		"detections_critical": "Open critical detections",
		"dlp_24h":             "DLP incidents in the last 24h",
		"responses_total":     "Total response actions issued",
	}
	for k, help := range gauges {
		metric := "sentinel_" + k
		io.WriteString(w, "# HELP "+metric+" "+help+"\n")
		io.WriteString(w, "# TYPE "+metric+" gauge\n")
		io.WriteString(w, metric+" "+strconv.Itoa(counts[k])+"\n")
	}
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	webfs := s.webFS()
	upath := strings.TrimPrefix(r.URL.Path, "/")
	if upath == "" {
		upath = "index.html"
	}
	f, err := webfs.Open(upath)
	if err != nil {
		// SPA fallback
		idx, ierr := webfs.Open("index.html")
		if ierr != nil {
			http.Error(w, "console not built", http.StatusNotFound)
			return
		}
		defer idx.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.Copy(w, idx)
		return
	}
	defer f.Close()
	if ct := contentType(upath); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	io.Copy(w, f)
}

func (s *Server) webFS() fs.FS {
	if s.cfg.WebDir != "" {
		return os.DirFS(s.cfg.WebDir)
	}
	if sub, err := embeddedWeb(); err == nil {
		return sub
	}
	return os.DirFS(".")
}

// ---------- helpers ----------

func validResponseType(t string) bool {
	switch model.ResponseType(t) {
	case model.RespKillProcess, model.RespIsolate, model.RespUnisolate,
		model.RespDisableAccount, model.RespBlockUpload, model.RespBlockUSB:
		return true
	}
	return false
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// HSTS is honored only over HTTPS (ignored on plain HTTP per spec), so setting it
		// unconditionally is safe and protects TLS deployments from SSL-stripping.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any, max int64) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, max)).Decode(v)
}

func serverError(w http.ResponseWriter, err error) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func constTimeEqual(a, b string) bool {
	return a != "" && b != "" && hmac.Equal([]byte(a), []byte(b))
}

// discardRW is unused after refactor; kept out intentionally.

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func (s *Server) clientIP(r *http.Request, fallback string) string {
	remote := remoteHost(r.RemoteAddr)
	if remote != "" && trustedProxy(remote, s.cfg.TrustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// nginx APPENDS the real peer to any client-supplied XFF, so the leftmost entry is
			// attacker-controlled. Walk right→left, skipping trusted proxies; the first
			// untrusted hop is the genuine client. This prevents XFF spoofing (which would let
			// an attacker mint unbounded rate-limiter buckets → memory-exhaustion DoS).
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip == "" || trustedProxy(ip, s.cfg.TrustedProxies) {
					continue
				}
				return ip
			}
		}
	}
	if remote != "" {
		return remote
	}
	return fallback
}

func remoteHost(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func trustedProxy(remote string, trusted []string) bool {
	ip := net.ParseIP(remote)
	if ip == nil {
		return false
	}
	for _, raw := range trusted {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(raw); err == nil && cidr.Contains(ip) {
			return true
		}
		if tip := net.ParseIP(raw); tip != nil && tip.Equal(ip) {
			return true
		}
	}
	return false
}

func contentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".woff2"):
		return "font/woff2"
	}
	return ""
}
