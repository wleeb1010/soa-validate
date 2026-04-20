package agentcard

import (
	"os"
	"path/filepath"
	"testing"
)

func specDir(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SOA_HARNESS_SPEC_PATH"); p != "" {
		return p
	}
	candidate := filepath.Join("..", "..", "..", "soa-harness=specification")
	if _, err := os.Stat(candidate); err == nil {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	t.Skip("spec repo not available; set SOA_HARNESS_SPEC_PATH")
	return ""
}

func TestValidateJSON_PinnedVector(t *testing.T) {
	root := specDir(t)
	card, err := os.ReadFile(filepath.Join(root, "test-vectors", "agent-card.json"))
	if err != nil {
		t.Fatalf("read card vector: %v", err)
	}
	schemaPath := filepath.Join(root, "schemas", "agent-card.schema.json")
	if err := ValidateJSON(schemaPath, card); err != nil {
		t.Errorf("pinned vector does not validate against its schema: %v", err)
	}
}

func TestValidateJSON_RejectsMissingRequired(t *testing.T) {
	root := specDir(t)
	schemaPath := filepath.Join(root, "schemas", "agent-card.schema.json")
	bad := []byte(`{"name":"x"}`)
	if err := ValidateJSON(schemaPath, bad); err == nil {
		t.Error("expected schema error for minimal object, got nil")
	}
}

func TestParseJWS_PinnedVector(t *testing.T) {
	root := specDir(t)
	jws, err := os.ReadFile(filepath.Join(root, "test-vectors", "agent-card.json.jws"))
	if err != nil {
		t.Fatalf("read jws vector: %v", err)
	}
	parsed, err := ParseJWS(jws)
	if err != nil {
		t.Fatalf("parse jws: %v", err)
	}
	if !parsed.Detached {
		t.Error("expected detached JWS (empty payload segment)")
	}
	if parsed.Header.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", parsed.Header.Alg)
	}
	if parsed.Header.Typ != "soa-agent-card+jws" {
		t.Errorf("typ = %q, want soa-agent-card+jws", parsed.Header.Typ)
	}
	if parsed.Header.Kid == "" {
		t.Error("kid is empty in protected header")
	}
	if !IsPlaceholderSignature(parsed.SignatureEncoded) {
		t.Error("expected pinned vector to carry placeholder ('0'-repeating) signature segment")
	}
}

func TestParseJWS_RejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"two segments", "aa.bb"},
		{"four segments", "a.b.c.d"},
		{"bad base64 header", "!!bad!!..AAAA"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseJWS([]byte(c.input)); err == nil {
				t.Errorf("expected error for %s, got nil", c.name)
			}
		})
	}
}
