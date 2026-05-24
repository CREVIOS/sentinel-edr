// Package auth handles console authentication and authorization: bcrypt-hashed
// credentials, short-lived HMAC-signed JWTs, role-based access control (admin > analyst >
// viewer), and a per-IP rate limiter for the public auth surface.
package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Role is a console authorization level.
type Role string

const (
	RoleAdmin   Role = "admin"   // full control incl. response actions, settings
	RoleAnalyst Role = "analyst" // triage, acknowledge, issue responses
	RoleViewer  Role = "viewer"  // read-only
)

func roleRank(r Role) int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

type user struct {
	hash []byte
	role Role
}

// Manager validates credentials and tokens.
type Manager struct {
	secret []byte
	mu     sync.RWMutex
	users  map[string]user
}

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxRole
)

// claims is the JWT body.
type claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// New creates a Manager seeded with the bootstrap admin account.
func New(secret, adminUser, adminPass string) (*Manager, error) {
	if len(secret) < 16 {
		return nil, errors.New("auth: JWT secret too short")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Manager{
		secret: []byte(secret),
		users:  map[string]user{adminUser: {hash: hash, role: RoleAdmin}},
	}, nil
}

// AddUser registers an additional console user.
func (m *Manager) AddUser(username, password string, role Role) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.users[username] = user{hash: hash, role: role}
	m.mu.Unlock()
	return nil
}

// Login verifies credentials and returns a signed JWT.
func (m *Manager) Login(username, password string) (string, Role, error) {
	m.mu.RLock()
	u, ok := m.users[username]
	m.mu.RUnlock()
	if !ok {
		// constant-time-ish: still run a bcrypt compare against a dummy hash
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv"), []byte(password))
		return "", "", errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword(u.hash, []byte(password)); err != nil {
		return "", "", errors.New("invalid credentials")
	}
	now := time.Now()
	c := claims{
		Role: string(u.role),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(12 * time.Hour)),
			Issuer:    "sentinel",
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(m.secret)
	return tok, u.role, err
}

// Verify validates a token and returns its subject and role.
func (m *Manager) Verify(tokenStr string) (string, Role, error) {
	c, err := m.parse(tokenStr)
	if err != nil {
		return "", "", err
	}
	return c.Subject, Role(c.Role), nil
}

func (m *Manager) parse(tokenStr string) (*claims, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(tokenStr, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Require returns middleware enforcing a minimum role.
func (m *Manager) Require(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		c, err := m.parse(tok)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if roleRank(Role(c.Role)) < roleRank(min) {
			http.Error(w, "insufficient role", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, c.Subject)
		ctx = context.WithValue(ctx, ctxRole, c.Role)
		next(w, r.WithContext(ctx))
	}
}

// UserFromContext returns the authenticated subject set by Require.
func UserFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxUser).(string); ok {
		return v
	}
	return ""
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("sentinel_session"); err == nil {
		return c.Value
	}
	return ""
}

// ---------- per-IP rate limiter ----------

// Limiter is a simple token-bucket limiter keyed by client IP. The bucket map is bounded:
// idle buckets are swept and a hard key cap prevents memory-exhaustion if the key space is
// flooded (e.g. spoofed source IPs).
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	limiterIdleTTL = 10 * time.Minute // forget a key after this much inactivity
	limiterGCEvery = time.Minute      // sweep cadence
	limiterMaxKeys = 100_000          // hard cap on distinct keys held at once
)

// NewLimiter creates a limiter allowing `burst` requests with `rate` refill/sec.
func NewLimiter(rate, burst float64) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, rate: rate, burst: burst, lastGC: time.Now()}
}

// gc evicts idle buckets (caller holds the lock). Runs at most once per limiterGCEvery, or
// immediately when the key cap is hit. If still over cap after sweeping, the map is reset —
// a coarse but safe backstop against unbounded growth under a flood.
func (l *Limiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < limiterGCEvery && len(l.buckets) < limiterMaxKeys {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > limiterIdleTTL {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) > limiterMaxKeys {
		l.buckets = map[string]*bucket{}
	}
}

// Allow reports whether a request from key may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.gc(now)
	b := l.buckets[key]
	if b == nil {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Middleware rate-limits by client IP.
func (l *Limiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !l.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	if i := strings.LastIndex(r.RemoteAddr, ":"); i >= 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
