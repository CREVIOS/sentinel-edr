package auth

import (
	"testing"
	"time"
)

// N1: idle buckets must be evicted so a flood of distinct keys can't grow the map forever.
func TestLimiterEvictsIdleBuckets(t *testing.T) {
	l := NewLimiter(100, 100)
	l.Allow("idle")
	if _, ok := l.buckets["idle"]; !ok {
		t.Fatal("bucket not created")
	}
	// Age the bucket past the idle TTL and force a sweep on the next call.
	l.buckets["idle"].last = time.Now().Add(-2 * limiterIdleTTL)
	l.lastGC = time.Now().Add(-2 * limiterGCEvery)
	l.Allow("fresh") // triggers gc()
	if _, ok := l.buckets["idle"]; ok {
		t.Fatal("idle bucket was not evicted")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Fatal("active bucket should remain")
	}
}

// N1: the hard key cap is a backstop against unbounded growth under a flood.
func TestLimiterHardCap(t *testing.T) {
	l := NewLimiter(1000, 1000)
	for i := 0; i < limiterMaxKeys+10; i++ {
		l.Allow(string(rune(i%256)) + itoaTest(i))
	}
	if len(l.buckets) > limiterMaxKeys {
		t.Fatalf("bucket map exceeded cap: %d > %d", len(l.buckets), limiterMaxKeys)
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
