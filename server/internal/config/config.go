// Package config loads runtime configuration from the environment. Secrets never live in
// code; every credential and endpoint is injected via env (12-factor).
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Config is the resolved server configuration.
type Config struct {
	Env            string // development | production — production enforces hard security gates
	Role           string // all | ingest | worker | correlator | gateway
	HTTPAddr       string // listen address for the HTTP/API/WS server
	DatabaseURL    string // postgres:// DSN (TimescaleDB)
	NatsURL        string // nats:// URL ("" => in-process memory bus, all-in-one only)
	RedisURL       string // optional, for distributed rate limiting / cache
	JWTSecret      string // HMAC secret for console JWTs
	EnrollToken    string // shared secret required to enroll a new agent
	AdminUser      string
	AdminPass      string // bootstrap admin password (bcrypt-hashed at startup)
	TLSCert        string // path to server TLS cert (enables HTTPS)
	TLSKey         string // path to server TLS key
	TLSClientCA    string // path to CA that signs agent client certs (enables mTLS)
	BehindProxy    bool   // TLS terminated by an upstream proxy (skips the prod TLS-required gate)
	RulesDir       string // directory of Sigma-style YAML rules
	WebDir         string // optional external dir for the built console (else embedded)
	Correlate      bool   // worker also runs behavioral correlation
	AllowOrigins   []string
	TrustedProxies []string // CIDR/IP list allowed to set X-Forwarded-For
	MetricsToken   string   // if set, /metrics requires this bearer token
}

// Load reads configuration from the environment with sensible, secure defaults.
func Load() *Config {
	c := &Config{
		Env:          env("SENTINEL_ENV", "development"),
		Role:         env("SENTINEL_ROLE", "all"),
		HTTPAddr:     env("SENTINEL_HTTP_ADDR", ":8080"),
		DatabaseURL:  env("SENTINEL_DATABASE_URL", "postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable"),
		NatsURL:      env("SENTINEL_NATS_URL", ""),
		RedisURL:     env("SENTINEL_REDIS_URL", ""),
		JWTSecret:    env("SENTINEL_JWT_SECRET", ""),
		EnrollToken:  env("SENTINEL_ENROLL_TOKEN", ""),
		AdminUser:    env("SENTINEL_ADMIN_USER", "admin"),
		AdminPass:    env("SENTINEL_ADMIN_PASS", ""),
		TLSCert:      env("SENTINEL_TLS_CERT", ""),
		TLSKey:       env("SENTINEL_TLS_KEY", ""),
		TLSClientCA:  env("SENTINEL_TLS_CLIENT_CA", ""),
		RulesDir:     env("SENTINEL_RULES_DIR", "rules"),
		WebDir:       env("SENTINEL_WEB_DIR", ""),
		Correlate:    env("SENTINEL_CORRELATE", "true") != "false",
		BehindProxy:  env("SENTINEL_BEHIND_PROXY", "") == "true",
		MetricsToken: env("SENTINEL_METRICS_TOKEN", ""),
	}
	if o := env("SENTINEL_ALLOW_ORIGINS", ""); o != "" {
		c.AllowOrigins = strings.Split(o, ",")
	}
	if p := env("SENTINEL_TRUSTED_PROXIES", ""); p != "" {
		c.TrustedProxies = strings.Split(p, ",")
	}
	// In development, generate ephemeral secrets so the stack "just works".
	// In production, Validate() refuses to start unless every secret is supplied.
	if !c.IsProduction() {
		if c.JWTSecret == "" {
			c.JWTSecret = randHex(32)
		}
		if c.EnrollToken == "" {
			c.EnrollToken = randHex(16)
		}
		if c.AdminPass == "" {
			c.AdminPass = "sentinel-admin" // dev-only default
		}
	}
	return c
}

// IsProduction reports whether production security gates apply.
func (c *Config) IsProduction() bool { return strings.EqualFold(c.Env, "production") }

// Validate enforces production security requirements; returns a list of fatal problems.
func (c *Config) Validate() error {
	if !c.IsProduction() {
		return nil
	}
	var problems []string
	if len(c.JWTSecret) < 32 {
		problems = append(problems, "SENTINEL_JWT_SECRET must be set (>=32 chars)")
	}
	if c.EnrollToken == "" {
		problems = append(problems, "SENTINEL_ENROLL_TOKEN must be set")
	}
	if c.AdminPass == "" || c.AdminPass == "sentinel-admin" {
		problems = append(problems, "SENTINEL_ADMIN_PASS must be set to a strong, non-default value")
	}
	if !c.TLSEnabled() && !c.BehindProxy {
		problems = append(problems, "TLS is required in production (set SENTINEL_TLS_CERT and SENTINEL_TLS_KEY, or SENTINEL_BEHIND_PROXY=true if TLS is terminated upstream)")
	}
	if len(c.AllowOrigins) == 0 {
		problems = append(problems, "SENTINEL_ALLOW_ORIGINS must be set to restrict console origins")
	}
	if len(problems) > 0 {
		return fmt.Errorf("insecure production configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// TLSEnabled reports whether HTTPS should be served.
func (c *Config) TLSEnabled() bool { return c.TLSCert != "" && c.TLSKey != "" }

// MTLSEnabled reports whether agent client-certificate auth is enforced.
func (c *Config) MTLSEnabled() bool { return c.TLSEnabled() && c.TLSClientCA != "" }

// RunsRole reports whether this process should run the given role's workload.
func (c *Config) RunsRole(role string) bool { return c.Role == "all" || c.Role == role }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
