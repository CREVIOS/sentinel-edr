package dlp

import "testing"

func TestCreditCardLuhn(t *testing.T) {
	e := New()
	// 4111 1111 1111 1111 is a valid Luhn test card.
	f := e.Scan("payment card 4111 1111 1111 1111 on file")
	if !hasClassifier(f, "pci_card") {
		t.Fatalf("expected pci_card finding")
	}
	// invalid Luhn must not match
	f2 := e.Scan("number 4111 1111 1111 1112")
	if hasClassifier(f2, "pci_card") {
		t.Fatalf("invalid card should not match")
	}
}

func TestSSNAndAWS(t *testing.T) {
	e := New()
	f := e.Scan("ssn 123-45-6789 key AKIAIOSFODNN7EXAMPLE")
	if !hasClassifier(f, "pii_ssn") {
		t.Fatalf("expected ssn")
	}
	if !hasClassifier(f, "secret_aws") {
		t.Fatalf("expected aws key")
	}
}

func TestEntropyGate(t *testing.T) {
	e := New()
	// low-entropy ordinary identifier should NOT be flagged as a token
	if hasClassifier(e.Scan("this_is_a_normal_function_name_here"), "secret_token") {
		t.Fatalf("low-entropy string flagged as token")
	}
	// high-entropy mixed token should be flagged
	if !hasClassifier(e.Scan("Xa9Kd72LpQ1mZ4Rb8Wc3Yt6Vn0Hf5Gj2Ds"), "secret_token") {
		t.Fatalf("high-entropy token not flagged")
	}
}

func TestVerdictPolicy(t *testing.T) {
	e := New()
	if v := e.Verdict("secret_aws", "usb"); v != "block" {
		t.Fatalf("aws key over usb should block, got %s", v)
	}
	if v := e.Verdict("pii_ssn", "usb"); v != "block" {
		t.Fatalf("ssn over usb should block, got %s", v)
	}
	if v := e.Verdict("pii_email", "http_upload"); v != "audit" {
		t.Fatalf("bulk email default should audit, got %s", v)
	}
}

func TestRedaction(t *testing.T) {
	e := New()
	f := e.Scan("AKIAIOSFODNN7EXAMPLE")
	for _, x := range f {
		if x.Classifier == "secret_aws" && x.Sample == "AKIAIOSFODNN7EXAMPLE" {
			t.Fatalf("sample was not redacted: %s", x.Sample)
		}
	}
}

func hasClassifier(fs []Finding, name string) bool {
	for _, f := range fs {
		if f.Classifier == name {
			return true
		}
	}
	return false
}
