package jcs

import (
	"fmt"

	canonicaljson "github.com/gibson042/canonicaljson-go"
)

// Canonicalize returns the RFC 8785 canonical JSON bytes for v. v must already
// be a Go value produced by encoding/json decoding (map[string]interface{},
// []interface{}, float64, string, bool, nil) or a struct whose json tags
// match the intended canonical form.
//
// Byte-equivalence with the TS impl's `canonicalize` (Erdtman) output is the load-bearing
// invariant; any divergence blocks M1 on both sides.
func Canonicalize(v interface{}) ([]byte, error) {
	b, err := canonicaljson.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return b, nil
}
