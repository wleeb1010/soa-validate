// Package inittrust implements the Core §5.3 post-parse semantic gates
// the Runner MUST apply after initial-trust.json passes schema validation.
// The package is pure (no I/O); callers provide bundle bytes + reference
// clock. Reason strings come from Core §24's HostHardeningInsufficient
// closed-set.
package inittrust

import (
	"encoding/json"
	"fmt"
	"time"
)

type Bundle struct {
	SoaHarnessVersion     string `json:"soaHarnessVersion"`
	PublisherKid          string `json:"publisher_kid"`
	SpkiSha256            string `json:"spki_sha256"`
	Issuer                string `json:"issuer"`
	IssuedAt              string `json:"issued_at,omitempty"`
	NotAfter              string `json:"not_after,omitempty"`
	SuccessorPublisherKid string `json:"successor_publisher_kid,omitempty"`
	Channel               string `json:"channel,omitempty"`
}

// Reason is a closed-set string from Core §24 HostHardeningInsufficient
// reason codes. Empty string means "accept; no semantic rejection".
type Reason string

const (
	ReasonAccept           Reason = ""
	ReasonBootstrapExpired Reason = "bootstrap-expired"
)

func Parse(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse initial-trust bundle: %w", err)
	}
	return &b, nil
}

// SemanticValidate applies the post-schema gates Core §5.3 specifies.
// Schema validity MUST be confirmed separately before calling this.
// Currently enforces only not_after (§5.3 "bootstrap-expired"); the
// rotation-overlap and successor_publisher_kid handling from §5.3.1 is
// out of scope for the HR-01 M1 coverage.
func SemanticValidate(b *Bundle, now time.Time) Reason {
	if b.NotAfter != "" {
		na, err := time.Parse(time.RFC3339, b.NotAfter)
		if err != nil {
			return ReasonBootstrapExpired // unparseable not_after fails closed
		}
		if !now.Before(na) {
			return ReasonBootstrapExpired
		}
	}
	return ReasonAccept
}
