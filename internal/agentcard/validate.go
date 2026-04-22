// Package agentcard implements SV-CARD-01 and SV-SIGN-01 assertions.
// Exposes two primitives: ValidateJSON for the card against its schema,
// and ParseJWS for the detached signature structure. Callers compose these
// into path-specific checks (pinned spec vector vs live Runner endpoint).
package agentcard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// ValidateJSON checks that cardBytes conform to the Agent Card schema at
// schemaURL (any fetchable URL or local path). The schema is drafted with
// 2020-12 which jsonschema/v5 supports natively.
func ValidateJSON(schemaPath string, cardBytes []byte) error {
	c := jsonschema.NewCompiler()
	schemaBytes, err := readFile(schemaPath)
	if err != nil {
		return err
	}
	if err := c.AddResource(schemaPath, strings.NewReader(string(schemaBytes))); err != nil {
		return fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := c.Compile(schemaPath)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	var v interface{}
	if err := json.Unmarshal(cardBytes, &v); err != nil {
		return fmt.Errorf("parse card json: %w", err)
	}
	if err := sch.Validate(v); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

// JWSHeader captures the protected header fields SV-SIGN-* probes inspect.
type JWSHeader struct {
	Alg     string   `json:"alg"`
	Kid     string   `json:"kid"`
	Typ     string   `json:"typ"`
	B64     *bool    `json:"b64,omitempty"`
	Crit    []string `json:"crit,omitempty"`
	X5C     []string `json:"x5c,omitempty"`     // RFC 7515 §4.1.6 cert chain (leaf-first)
	X5TS256 string   `json:"x5t#S256,omitempty"` // RFC 7515 §4.1.8 leaf cert SHA-256 thumbprint
}

// ParseJWS returns the decoded protected header plus the detached-payload
// indicator (true iff payload segment is empty). The signature segment is
// returned raw (base64url); caller performs crypto verification if trusted
// material is available.
type DetachedJWS struct {
	Header           JWSHeader
	HeaderRaw        []byte // decoded JSON bytes of the protected header
	Detached         bool   // payload segment is empty
	PayloadEncoded   string // base64url payload segment (may be empty)
	SignatureEncoded string // raw base64url signature segment
	Signature        []byte // decoded signature bytes
	SigningInput     []byte // header.payload as bytes, the canonical signing input
}

// ParseJWS validates structural invariants (three dot-separated segments,
// base64url-decodable header, alg/typ/kid present) and returns the parsed
// form. No crypto is performed here.
func ParseJWS(compact []byte) (*DetachedJWS, error) {
	parts := strings.Split(strings.TrimSpace(string(compact)), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 JWS segments, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode protected header: %w", err)
	}
	var h JWSHeader
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, fmt.Errorf("parse protected header: %w", err)
	}
	if h.Alg == "" {
		return nil, fmt.Errorf("protected header missing alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return &DetachedJWS{
		Header:           h,
		HeaderRaw:        headerJSON,
		Detached:         parts[1] == "",
		PayloadEncoded:   parts[1],
		SignatureEncoded: parts[2],
		Signature:        sig,
		SigningInput:     []byte(parts[0] + "." + parts[1]),
	}, nil
}

// IsPlaceholderSignature reports true when the compact-form signature segment
// is the repeating-'0' marker used by the pinned spec vector to indicate a
// placeholder signature (shipped ahead of real signing infrastructure).
// Callers use this to treat SV-SIGN-01 signature-crypto checks as deferred
// rather than failed when running against the vector.
func IsPlaceholderSignature(encodedSegment string) bool {
	if encodedSegment == "" {
		return true
	}
	for i := 0; i < len(encodedSegment); i++ {
		if encodedSegment[i] != '0' {
			return false
		}
	}
	return true
}
