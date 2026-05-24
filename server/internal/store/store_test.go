package store

import (
	"strings"
	"testing"
)

func TestLimitOffsetClampsAndDefaults(t *testing.T) {
	if got := limitOffset(50, 10); got != " LIMIT 50 OFFSET 10" {
		t.Fatalf("got %q", got)
	}
	// out-of-range limits fall back to the safe default (200)
	for _, bad := range []int{0, -5, 5000} {
		if got := limitOffset(bad, 0); !strings.Contains(got, "LIMIT 200") {
			t.Fatalf("limit %d should clamp to 200, got %q", bad, got)
		}
	}
}

func TestItoaMatchesStdlib(t *testing.T) {
	for _, n := range []int{0, 1, 9, 10, 42, 100, 999, 1000000} {
		want := ""
		x := n
		if x == 0 {
			want = "0"
		}
		for x > 0 {
			want = string(rune('0'+x%10)) + want
			x /= 10
		}
		if got := itoa(n); got != want {
			t.Fatalf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}
