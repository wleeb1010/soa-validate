// Package crlstate classifies a CRL body per the Core §7.3.1 three-state
// freshness machine: fresh | stale-but-valid | expired. Pure functions;
// caller provides parsed CRL and reference clock. This is the validator's
// independent re-implementation of the classifier the Runner MUST match.
package crlstate

import (
	"encoding/json"
	"fmt"
	"time"
)

// Spec §7.3.1 defaults: refresh_interval = 1h, hard_ceiling = 2h.
const (
	DefaultRefreshInterval = 1 * time.Hour
	HardStaleCeiling       = 2 * time.Hour
)

type State string

const (
	StateFresh         State = "fresh"
	StateStaleButValid State = "stale-but-valid"
	StateExpired       State = "expired"
)

// Reason is from Core §24 CardSignatureFailed closed-set.
type Reason string

const (
	ReasonAccept     Reason = ""
	ReasonCRLExpired Reason = "crl-expired"
)

type CRL struct {
	Issuer      string          `json:"issuer"`
	IssuedAt    string          `json:"issued_at"`
	NotAfter    string          `json:"not_after"`
	RevokedKids []RevokedKidRef `json:"revoked_kids"`
}

type RevokedKidRef struct {
	Kid       string `json:"kid"`
	RevokedAt string `json:"revoked_at"`
	Reason    string `json:"reason"`
}

type Classification struct {
	State          State
	RefreshNeeded  bool   // true iff caller MUST queue a background refresh
	Accept         bool   // true iff verification proceeds (fresh or stale)
	FailureReason  Reason // non-empty only when Accept=false
}

func Parse(data []byte) (*CRL, error) {
	var c CRL
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse crl: %w", err)
	}
	return &c, nil
}

// Classify returns the §7.3.1 state of this CRL at `now`. Uses default
// refresh_interval (1h) and hard ceiling (2h). Invariants the test harness
// asserts:
//
//	fresh           → Accept=true,  RefreshNeeded=false, FailureReason=""
//	stale-but-valid → Accept=true,  RefreshNeeded=true,  FailureReason=""
//	expired         → Accept=false, RefreshNeeded=false, FailureReason="crl-expired"
func Classify(crl *CRL, now time.Time) Classification {
	issued, errI := time.Parse(time.RFC3339, crl.IssuedAt)
	notAfter, errN := time.Parse(time.RFC3339, crl.NotAfter)
	if errI != nil || errN != nil {
		return Classification{State: StateExpired, FailureReason: ReasonCRLExpired}
	}

	// Hard horizon: past not_after → expired.
	if !now.Before(notAfter) {
		return Classification{State: StateExpired, FailureReason: ReasonCRLExpired}
	}
	age := now.Sub(issued)
	switch {
	case age <= DefaultRefreshInterval:
		return Classification{State: StateFresh, Accept: true}
	case age <= HardStaleCeiling:
		return Classification{State: StateStaleButValid, Accept: true, RefreshNeeded: true}
	default:
		// Over the 2h hard ceiling but not yet past not_after: treated as
		// expired per spec — the 2h ceiling is a stricter bound than not_after.
		return Classification{State: StateExpired, FailureReason: ReasonCRLExpired}
	}
}
