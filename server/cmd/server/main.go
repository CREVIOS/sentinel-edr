// Command server is the Sentinel control plane. A single binary runs any tier via
// SENTINEL_ROLE: `all` (dev / single-node), `ingest`, `worker`, `correlator`, `gateway`.
// Tiers are decoupled by the event bus (NATS JetStream) and control mesh (NATS core),
// so each scales independently behind a load balancer.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sentinel/server/internal/api"
	"github.com/sentinel/server/internal/auth"
	"github.com/sentinel/server/internal/behavior"
	"github.com/sentinel/server/internal/bus"
	"github.com/sentinel/server/internal/config"
	"github.com/sentinel/server/internal/detect"
	"github.com/sentinel/server/internal/dlp"
	"github.com/sentinel/server/internal/hub"
	"github.com/sentinel/server/internal/intel"
	"github.com/sentinel/server/internal/mesh"
	"github.com/sentinel/server/internal/notify"
	"github.com/sentinel/server/internal/pipeline"
	"github.com/sentinel/server/internal/respond"
	"github.com/sentinel/server/internal/store"
	"github.com/sentinel/server/internal/transport"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}
	if !cfg.IsProduction() {
		log.Warn("running in DEVELOPMENT mode — ephemeral secrets, relaxed TLS. Set SENTINEL_ENV=production for hardened gates")
	}
	log.Info("starting sentinel", "role", cfg.Role, "env", cfg.Env, "addr", cfg.HTTPAddr,
		"tls", cfg.TLSEnabled(), "mtls", cfg.MTLSEnabled(), "nats", cfg.NatsURL != "")

	st, err := openStoreWithRetry(cfg.DatabaseURL, log)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	authMgr, err := auth.New(cfg.JWTSecret, cfg.AdminUser, cfg.AdminPass)
	if err != nil {
		log.Error("auth", "err", err)
		os.Exit(1)
	}

	det := detect.New()
	if n, err := det.LoadDir(cfg.RulesDir); err != nil {
		log.Warn("rules", "err", err, "loaded", n)
	} else {
		log.Info("rules loaded", "count", n)
	}
	dlpEng := dlp.New()

	// Threat-intel IOC engine (optional). Loads hash/ip/domain feeds from SENTINEL_IOC_DIR.
	intelEng := intel.New()
	if cfg.IOCDir != "" {
		if n, err := intelEng.LoadDir(cfg.IOCDir); err != nil {
			log.Warn("ioc feeds", "err", err, "dir", cfg.IOCDir)
		} else {
			log.Info("ioc feeds loaded", "indicators", n)
		}
	}

	busB, err := bus.Open(cfg.NatsURL)
	if err != nil {
		log.Error("bus", "err", err)
		os.Exit(1)
	}
	defer busB.Close()

	h := hub.New()

	// Control-plane transport: in-process hub for `all`, NATS mesh when scaled out.
	var bcast transport.Broadcaster = h
	var cmder transport.Commander = h
	var meshConn *mesh.Mesh
	if cfg.NatsURL != "" && cfg.Role != "all" {
		m, err := mesh.New(cfg.NatsURL)
		if err != nil {
			log.Error("mesh", "err", err)
			os.Exit(1)
		}
		meshConn = m
		bcast, cmder = m, m
		defer m.Close()
	}

	resp := respond.New(st, cmder, bcast)

	// Behavioral correlator state is local to the correlator tier.
	var behaviorEng *behavior.Engine
	if cfg.Correlate && cfg.RunsRole("correlator") {
		behaviorEng = behavior.New()
	}
	notifier := notify.New(notify.Config{
		MinSeverity: cfg.AlertMinSev,
		WebhookURL:  cfg.AlertWebhook, WebhookKind: notify.Kind(cfg.AlertKind),
		SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUser: cfg.SMTPUser, SMTPPass: cfg.SMTPPass,
		MailFrom: cfg.AlertMailFrom, MailTo: cfg.AlertMailTo, SMTPTLS: cfg.SMTPTLS,
	}, log)
	if notifier != nil {
		log.Info("alerting enabled", "sinks", notifier.Sinks(), "min_severity", cfg.AlertMinSev)
	}
	proc := pipeline.New(st, det, dlpEng, behaviorEng, resp, bcast, log).WithIntel(intelEng).WithNotify(notifier)

	if cfg.RunsRole("worker") {
		if err := proc.StartProcessors(busB); err != nil {
			log.Error("processors", "err", err)
			os.Exit(1)
		}
		log.Info("processors started")
	}
	if cfg.RunsRole("correlator") && behaviorEng != nil {
		if err := proc.StartCorrelator(busB); err != nil {
			log.Error("correlator", "err", err)
			os.Exit(1)
		}
		log.Info("correlator started")
	}

	// background: flip silent agents to offline
	stopTicker := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = st.MarkStaleOffline(2 * time.Minute)
			case <-stopTicker:
				return
			}
		}
	}()

	var srv *http.Server
	servesHTTP := cfg.Role == "all" || cfg.RunsRole("ingest") || cfg.RunsRole("gateway")
	if servesHTTP {
		// In scaled mode, a gateway bridges its local agent/console WebSockets to the mesh.
		if cfg.NatsURL != "" && cfg.Role == "gateway" {
			if _, err := mesh.BridgeGateway(cfg.NatsURL, h); err != nil {
				log.Error("gateway bridge", "err", err)
				os.Exit(1)
			}
			log.Info("gateway bridge active")
		}
		apiSrv := api.New(api.Deps{
			Cfg: cfg, Store: st, Auth: authMgr, Hub: h, Bcast: bcast, Bus: busB,
			Detect: det, DLP: dlpEng, Respond: resp, Log: log,
		})
		srv = &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           apiSrv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      0, // streaming WebSockets
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			var err error
			if cfg.TLSEnabled() {
				srv.TLSConfig = buildTLS(cfg, log)
				log.Info("https listening", "addr", cfg.HTTPAddr)
				err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
			} else {
				log.Info("http listening", "addr", cfg.HTTPAddr)
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("http server", "err", err)
				os.Exit(1)
			}
		}()
	}

	_ = meshConn
	// graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Info("shutting down")
	close(stopTicker)
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func openStoreWithRetry(dsn string, log *slog.Logger) (store.Store, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		st, err := store.Open(dsn)
		if err == nil {
			return st, nil
		}
		lastErr = err
		log.Warn("waiting for database", "attempt", i+1, "err", err)
		time.Sleep(2 * time.Second)
	}
	return nil, lastErr
}

func buildTLS(cfg *config.Config, log *slog.Logger) *tls.Config {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.MTLSEnabled() {
		caPEM, err := os.ReadFile(cfg.TLSClientCA)
		if err != nil {
			log.Error("read client CA", "err", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			log.Error("client CA parse failed")
			os.Exit(1)
		}
		tc.ClientCAs = pool
		// Request and verify a client cert when one is presented, but do not
		// require it at the listener: console browsers share this listener.
		// Agent-only routes enforce the verified client certificate in API
		// middleware.
		tc.ClientAuth = tls.VerifyClientCertIfGiven
		log.Info("mutual TLS requested at handshake and enforced on agent routes")
	}
	return tc
}
