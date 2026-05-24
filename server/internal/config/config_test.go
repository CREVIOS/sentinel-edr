package config

import "testing"

func base() *Config {
	return &Config{
		Env:          "production",
		JWTSecret:    "0123456789abcdef0123456789abcdef", // 32 chars
		EnrollToken:  "enrolltoken",
		AdminPass:    "a-strong-admin-pass",
		AllowOrigins: []string{"https://app2.makebell.com"},
		BehindProxy:  true,
	}
}

func TestValidateDevSkipsGates(t *testing.T) {
	c := &Config{Env: "development"}
	if err := c.Validate(); err != nil {
		t.Fatalf("dev should not enforce gates: %v", err)
	}
}

func TestValidateProductionHappyBehindProxy(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("valid prod config rejected: %v", err)
	}
}

func TestValidateRejectsWeakSecret(t *testing.T) {
	c := base()
	c.JWTSecret = "tooshort"
	if err := c.Validate(); err == nil {
		t.Fatal("short JWT secret must be rejected in production")
	}
}

func TestValidateRejectsDefaultAdminPass(t *testing.T) {
	c := base()
	c.AdminPass = "sentinel-admin"
	if err := c.Validate(); err == nil {
		t.Fatal("default admin password must be rejected")
	}
	c.AdminPass = ""
	if err := c.Validate(); err == nil {
		t.Fatal("empty admin password must be rejected")
	}
}

func TestValidateRequiresOrigins(t *testing.T) {
	c := base()
	c.AllowOrigins = nil
	if err := c.Validate(); err == nil {
		t.Fatal("production must require an origin allowlist")
	}
}

func TestValidateRequiresTLSorBehindProxy(t *testing.T) {
	c := base()
	c.BehindProxy = false // and no TLS cert/key
	if err := c.Validate(); err == nil {
		t.Fatal("production must require TLS unless behind a terminating proxy")
	}
	// supplying TLS instead of BehindProxy also satisfies the gate
	c.TLSCert, c.TLSKey = "/x/cert.pem", "/x/key.pem"
	if err := c.Validate(); err != nil {
		t.Fatalf("TLS-configured prod should pass: %v", err)
	}
}
