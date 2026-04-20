package crlstate

import (
	"testing"
	"time"
)

// T_ref = 2026-04-20T12:00:00Z — the clock the spec's CRL README pins.
var tRef = time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)

func TestClassify_Fresh(t *testing.T) {
	c := &CRL{IssuedAt: "2026-04-20T12:00:00Z", NotAfter: "2026-04-21T12:00:00Z"}
	got := Classify(c, tRef)
	if got.State != StateFresh {
		t.Errorf("state = %s, want fresh", got.State)
	}
	if !got.Accept || got.RefreshNeeded || got.FailureReason != ReasonAccept {
		t.Errorf("fresh classification wrong: %+v", got)
	}
}

func TestClassify_StaleButValid(t *testing.T) {
	// 90 min old → past 1h refresh interval, within 2h ceiling
	c := &CRL{IssuedAt: "2026-04-20T10:30:00Z", NotAfter: "2026-04-21T12:00:00Z"}
	got := Classify(c, tRef)
	if got.State != StateStaleButValid {
		t.Errorf("state = %s, want stale-but-valid", got.State)
	}
	if !got.Accept || !got.RefreshNeeded || got.FailureReason != ReasonAccept {
		t.Errorf("stale classification wrong: %+v", got)
	}
}

func TestClassify_ExpiredPastNotAfter(t *testing.T) {
	c := &CRL{IssuedAt: "2020-01-01T00:00:00Z", NotAfter: "2020-06-30T23:59:59Z"}
	got := Classify(c, tRef)
	if got.State != StateExpired {
		t.Errorf("state = %s, want expired", got.State)
	}
	if got.Accept || got.FailureReason != ReasonCRLExpired {
		t.Errorf("expired classification wrong: %+v", got)
	}
}

func TestClassify_ExpiredPastHardCeiling(t *testing.T) {
	// 3 h old, but not_after still in future → hits 2h ceiling first
	c := &CRL{IssuedAt: "2026-04-20T09:00:00Z", NotAfter: "2026-04-21T12:00:00Z"}
	got := Classify(c, tRef)
	if got.State != StateExpired {
		t.Errorf("state = %s, want expired (over 2h ceiling)", got.State)
	}
}
