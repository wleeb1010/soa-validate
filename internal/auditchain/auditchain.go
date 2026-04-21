// Package auditchain verifies the hash-chain integrity of audit records
// per spec §10.5. Independent re-implementation of the chain MUST so the
// validator can check what a conformant Runner claims its chain is.
package auditchain

import (
	"fmt"
	"strings"
)

// Record is the on-the-wire shape of a single audit row as returned by
// GET /audit/records (schema §10.5.3). Only fields load-bearing on chain
// integrity are required here; additional fields round-trip through raw.
type Record struct {
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	SessionID   string `json:"session_id"`
	SubjectID   string `json:"subject_id"`
	Tool        string `json:"tool"`
	ArgsDigest  string `json:"args_digest"`
	Capability  string `json:"capability"`
	Control     string `json:"control"`
	Handler     string `json:"handler"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	SignerKeyID string `json:"signer_key_id"`
	PrevHash    string `json:"prev_hash"`
	ThisHash    string `json:"this_hash"`
}

// VerifyChain walks records earliest-first and checks the §10.5 invariants:
//   - records[0].prev_hash == "GENESIS"
//   - for i > 0: records[i].prev_hash == records[i-1].this_hash
//
// Returns nil on success; on failure returns the 0-based break index and
// a human-readable error.
func VerifyChain(records []Record) (breakIdx int, err error) {
	if len(records) == 0 {
		return -1, nil
	}
	if records[0].PrevHash != "GENESIS" {
		return 0, fmt.Errorf("records[0].prev_hash = %q, want 'GENESIS'", records[0].PrevHash)
	}
	for i := 1; i < len(records); i++ {
		want := records[i-1].ThisHash
		got := records[i].PrevHash
		if got != want {
			return i, fmt.Errorf("records[%d].prev_hash = %s, want records[%d].this_hash = %s",
				i, abbrev(got), i-1, abbrev(want))
		}
	}
	return -1, nil
}

func abbrev(h string) string {
	if h == "GENESIS" {
		return "GENESIS"
	}
	if len(h) > 12 {
		return h[:8] + "…" + h[len(h)-4:]
	}
	return h
}

// Tamper returns a new slice where the record at idx has its prev_hash
// replaced with a definitely-wrong value. Original slice is not mutated.
// Used by HR-14 chain-tamper to construct a known-broken chain and confirm
// VerifyChain reports the break at exactly idx.
func Tamper(records []Record, idx int) []Record {
	out := make([]Record, len(records))
	copy(out, records)
	if idx < 0 || idx >= len(out) {
		return out
	}
	orig := out[idx].PrevHash
	// Flip the hex with a synthetic but valid-looking 64-char value so the
	// failure is specifically about chain-link mismatch, not schema shape.
	out[idx].PrevHash = strings.Repeat("0", 64)
	if orig == out[idx].PrevHash {
		// Astronomically unlikely, but handle: flip to all-ones instead.
		out[idx].PrevHash = strings.Repeat("f", 64)
	}
	return out
}
