package auth

import (
	"strings"
	"testing"
)

func mgr(t *testing.T) *Manager {
	t.Helper()
	m, err := New("a-sufficiently-long-jwt-secret-string", "admin", "s3cret-pass")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNewRejectsShortSecret(t *testing.T) {
	if _, err := New("short", "admin", "pw"); err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestLoginVerifyRoundtrip(t *testing.T) {
	m := mgr(t)
	tok, role, err := m.Login("admin", "s3cret-pass")
	if err != nil || tok == "" {
		t.Fatalf("login failed: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("role = %v, want admin", role)
	}
	sub, r, err := m.Verify(tok)
	if err != nil || sub != "admin" || r != RoleAdmin {
		t.Fatalf("verify roundtrip failed: sub=%q role=%v err=%v", sub, r, err)
	}
}

func TestLoginWrongAndUnknown(t *testing.T) {
	m := mgr(t)
	if _, _, err := m.Login("admin", "wrong"); err == nil {
		t.Fatal("wrong password should fail")
	}
	if _, _, err := m.Login("ghost", "whatever"); err == nil {
		t.Fatal("unknown user should fail")
	}
}

func TestVerifyRejectsTamperedAndForeignToken(t *testing.T) {
	m := mgr(t)
	tok, _, _ := m.Login("admin", "s3cret-pass")

	// tamper: flip a char in the signature
	bad := tok[:len(tok)-2] + "xy"
	if _, _, err := m.Verify(bad); err == nil {
		t.Fatal("tampered token should fail")
	}

	// token signed by a different secret must not verify here
	other, _ := New("a-totally-different-secret-value-here", "admin", "s3cret-pass")
	otok, _, _ := other.Login("admin", "s3cret-pass")
	if _, _, err := m.Verify(otok); err == nil {
		t.Fatal("foreign-signed token should fail")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	m := mgr(t)
	// header {"alg":"none","typ":"JWT"} . {"role":"admin"} . (empty sig)
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJhZG1pbiJ9."
	if _, _, err := m.Verify(none); err == nil {
		t.Fatal("alg=none token must be rejected (alg-confusion)")
	}
}

func TestAddUserAndRoleRank(t *testing.T) {
	m := mgr(t)
	if err := m.AddUser("ana", "analyst-pass", RoleAnalyst); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, role, err := m.Login("ana", "analyst-pass")
	if err != nil || role != RoleAnalyst {
		t.Fatalf("analyst login: role=%v err=%v", role, err)
	}
	if !(roleRank(RoleAdmin) > roleRank(RoleAnalyst) && roleRank(RoleAnalyst) > roleRank(RoleViewer) && roleRank(RoleViewer) > roleRank(Role("bogus"))) {
		t.Fatal("role rank ordering wrong")
	}
}

func TestTokenHasThreeParts(t *testing.T) {
	m := mgr(t)
	tok, _, _ := m.Login("admin", "s3cret-pass")
	if n := strings.Count(tok, "."); n != 2 {
		t.Fatalf("JWT should have 3 dot-separated parts, got %d dots", n)
	}
}
