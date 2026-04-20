// Package permprompt implements SV-PERM-01 assertions against the pinned
// PermissionPrompt + canonical_decision + PDA-JWS vector set in the spec
// repo. See test-vectors/permission-prompt/README.md for vector semantics.
package permprompt

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Prompt is the wire shape of a PermissionPrompt StreamEvent — we don't need
// a full schema validator for the whole envelope; we only inspect payload
// fields SV-PERM-01 requires.
type Prompt struct {
	Type    string         `json:"type"`
	Payload PromptPayload  `json:"payload"`
}

type PromptPayload struct {
	PromptID string `json:"prompt_id"`
	Nonce    string `json:"nonce"`
	Deadline string `json:"deadline"`
}

type Decision struct {
	PromptID    string `json:"prompt_id"`
	SessionID   string `json:"session_id"`
	Nonce       string `json:"nonce"`
	ToolName    string `json:"tool_name"`
	ArgsDigest  string `json:"args_digest"`
	Decision    string `json:"decision"`
	Scope       string `json:"scope"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

// nonce pattern from UI §11.4.1: URL-safe base64, ≥22 chars → ≥132 bits.
var noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,}$`)

func ParsePrompt(data []byte) (*Prompt, error) {
	var p Prompt
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse prompt: %w", err)
	}
	if p.Type != "PermissionPrompt" {
		return nil, fmt.Errorf("type = %q, want PermissionPrompt", p.Type)
	}
	if p.Payload.PromptID == "" {
		return nil, fmt.Errorf("payload.prompt_id empty")
	}
	if !noncePattern.MatchString(p.Payload.Nonce) {
		return nil, fmt.Errorf("payload.nonce %q does not match nonce pattern", p.Payload.Nonce)
	}
	return &p, nil
}

func ParseDecision(data []byte) (*Decision, error) {
	var d Decision
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse decision: %w", err)
	}
	return &d, nil
}

// ValidateDecisionSchema checks decisionBytes against canonical-decision.schema.json.
func ValidateDecisionSchema(schemaPath string, decisionBytes []byte) error {
	c := jsonschema.NewCompiler()
	schemaRaw, err := readFile(schemaPath)
	if err != nil {
		return err
	}
	if err := c.AddResource(schemaPath, strings.NewReader(string(schemaRaw))); err != nil {
		return fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := c.Compile(schemaPath)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	var v interface{}
	if err := json.Unmarshal(decisionBytes, &v); err != nil {
		return fmt.Errorf("parse decision: %w", err)
	}
	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

// CheckNonceEquality enforces UV-P-18: decision.nonce MUST equal
// prompt.payload.nonce. Returns nil if equal, error with both values if not.
func CheckNonceEquality(p *Prompt, d *Decision) error {
	if p.Payload.Nonce != d.Nonce {
		return fmt.Errorf("nonce mismatch: prompt=%q decision=%q", p.Payload.Nonce, d.Nonce)
	}
	return nil
}

// CheckPromptIDEquality: decision.prompt_id MUST equal prompt.payload.prompt_id.
func CheckPromptIDEquality(p *Prompt, d *Decision) error {
	if p.Payload.PromptID != d.PromptID {
		return fmt.Errorf("prompt_id mismatch: prompt=%q decision=%q", p.Payload.PromptID, d.PromptID)
	}
	return nil
}
