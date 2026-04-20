package permprompt

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

func TestParseAndMatchPinnedVectors(t *testing.T) {
	root := specDir(t)
	pb, err := os.ReadFile(filepath.Join(root, "test-vectors", "permission-prompt", "permission-prompt.json"))
	if err != nil {
		t.Fatalf("read prompt: %v", err)
	}
	db, err := os.ReadFile(filepath.Join(root, "test-vectors", "permission-prompt", "canonical-decision.json"))
	if err != nil {
		t.Fatalf("read decision: %v", err)
	}
	prompt, err := ParsePrompt(pb)
	if err != nil {
		t.Fatalf("parse prompt: %v", err)
	}
	decision, err := ParseDecision(db)
	if err != nil {
		t.Fatalf("parse decision: %v", err)
	}
	if err := CheckNonceEquality(prompt, decision); err != nil {
		t.Errorf("UV-P-18 nonce equality: %v", err)
	}
	if err := CheckPromptIDEquality(prompt, decision); err != nil {
		t.Errorf("prompt_id equality: %v", err)
	}
	schemaPath := filepath.Join(root, "schemas", "canonical-decision.schema.json")
	if err := ValidateDecisionSchema(schemaPath, db); err != nil {
		t.Errorf("canonical-decision schema: %v", err)
	}
}

func TestParsePromptRejectsWrongType(t *testing.T) {
	bad := []byte(`{"type":"Bogus","payload":{"prompt_id":"x","nonce":"aaaaaaaaaaaaaaaaaaaaaa"}}`)
	if _, err := ParsePrompt(bad); err == nil {
		t.Error("expected error for non-PermissionPrompt type")
	}
}

func TestParsePromptRejectsShortNonce(t *testing.T) {
	bad := []byte(`{"type":"PermissionPrompt","payload":{"prompt_id":"x","nonce":"short"}}`)
	if _, err := ParsePrompt(bad); err == nil {
		t.Error("expected error for short nonce")
	}
}

func TestCheckNonceEqualityRejectsMismatch(t *testing.T) {
	p := &Prompt{Payload: PromptPayload{PromptID: "p1", Nonce: "q9Zt-X8bL4rFvH2kNpR7wS"}}
	d := &Decision{PromptID: "p1", Nonce: "qqqqqqqqqqqqqqqqqqqqqq"}
	if err := CheckNonceEquality(p, d); err == nil {
		t.Error("expected nonce-mismatch error")
	}
}
