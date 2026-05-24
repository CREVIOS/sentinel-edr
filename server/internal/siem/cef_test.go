package siem

import (
	"strings"
	"testing"
)

// N4: attacker-controlled fields must not be able to inject a forged CEF/syslog line.
func TestCEFEscapeStripsControlChars(t *testing.T) {
	in := "ok\rCEF:0|Evil|forged|line\nmsg\x00\x07tail"
	got := cefEscapeVal(in)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("newline/CR leaked through cefEscapeVal: %q", got)
	}
	if strings.ContainsRune(got, 0x00) || strings.ContainsRune(got, 0x07) {
		t.Fatalf("control char leaked through cefEscapeVal: %q", got)
	}
	// \r and \n become spaces; the visible text survives.
	if !strings.Contains(got, "ok") || !strings.Contains(got, "tail") {
		t.Fatalf("visible text lost: %q", got)
	}
}

func TestCEFHeaderEscapeStripsControl(t *testing.T) {
	if strings.ContainsAny(cefEscape("a\rb\nc"), "\r\n") {
		t.Fatal("cefEscape (header) leaked CR/LF")
	}
}
