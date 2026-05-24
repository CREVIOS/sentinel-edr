package api

import (
	"net/http"
	"testing"

	"github.com/sentinel/server/internal/config"
)

// N1: clientIP must return the real client (rightmost untrusted XFF hop), not an entry the
// attacker prepended — otherwise spoofed X-Forwarded-For mints unbounded limiter buckets.
func TestClientIPRejectsSpoofedXFF(t *testing.T) {
	s := &Server{cfg: &config.Config{TrustedProxies: []string{"172.16.0.0/12"}}}

	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		// nginx (trusted) appends the real peer; attacker prepended a fake leftmost entry.
		{"spoofed leftmost ignored", "172.16.0.5:443", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		// multiple trusted hops are skipped right-to-left.
		{"skip trusted hops", "172.16.0.5:443", "203.0.113.9, 172.16.0.9, 172.18.0.2", "203.0.113.9"},
		// no XFF → fall back to the direct peer.
		{"no xff", "203.0.113.50:443", "", "203.0.113.50"},
		// untrusted direct peer → never honor its XFF.
		{"untrusted peer ignores xff", "8.8.8.8:443", "1.2.3.4", "8.8.8.8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := s.clientIP(r, ""); got != c.want {
				t.Fatalf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}
