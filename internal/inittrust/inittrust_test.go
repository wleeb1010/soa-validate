package inittrust

import (
	"testing"
	"time"
)

func TestSemanticValidate_AcceptsValid(t *testing.T) {
	b := &Bundle{NotAfter: "2099-12-31T23:59:59Z"}
	if r := SemanticValidate(b, time.Now()); r != ReasonAccept {
		t.Errorf("valid bundle: got reason %q, want accept", r)
	}
}

func TestSemanticValidate_RejectsExpired(t *testing.T) {
	b := &Bundle{NotAfter: "2020-06-30T23:59:59Z"}
	if r := SemanticValidate(b, time.Now()); r != ReasonBootstrapExpired {
		t.Errorf("expired bundle: got reason %q, want bootstrap-expired", r)
	}
}

func TestSemanticValidate_NoNotAfter(t *testing.T) {
	// not_after is optional per schema; absent → accept.
	b := &Bundle{}
	if r := SemanticValidate(b, time.Now()); r != ReasonAccept {
		t.Errorf("bundle without not_after: got %q, want accept", r)
	}
}
