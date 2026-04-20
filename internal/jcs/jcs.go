package jcs

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Canonicalize returns the RFC 8785 canonical JSON bytes for v.
//
// IMPORTANT: this uses github.com/gowebpki/jcs (actual RFC 8785), NOT
// github.com/gibson042/canonicaljson-go (which implements a different
// canonical-JSON specification with capital-E exponents and different
// escape rules, and would silently produce bytes that do not match
// the TS side's `canonicalize` output).
//
// Byte-equivalence with the TS impl's `canonicalize` (Erdtman) output is
// the load-bearing invariant; any divergence blocks M1 on both sides.
//
// Canonicalize takes an arbitrary Go value. It re-encodes through
// encoding/json.Marshal first (to get a stable JSON byte form), then
// feeds that to jcs.Transform which produces the RFC 8785 canonical form.
func Canonicalize(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: pre-encode: %w", err)
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: transform: %w", err)
	}
	return out, nil
}
