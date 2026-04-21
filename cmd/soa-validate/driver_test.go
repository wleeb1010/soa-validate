package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestDriverHandlesRateLimitRetry: server returns 429 with Retry-After:0
// for the first 2 calls, then 201. Driver MUST retry the same record on
// 429 (not count it) and ultimately succeed.
func TestDriverHandlesRateLimitRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	stats, err := driveAuditRecordsWith(context.Background(),
		&http.Client{Timeout: 3 * time.Second}, srv.URL,
		"ses_test1234567890abcdef", "bearer-x",
		[]string{"fs__read_file"}, 1, 0)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	if stats.Written != 1 {
		t.Errorf("Written=%d, want 1", stats.Written)
	}
	if stats.RetriedAfter429 != 2 {
		t.Errorf("RetriedAfter429=%d, want 2", stats.RetriedAfter429)
	}
}

// TestDriverTolerates503PdaVerifyUnavailable: every call returns 503
// pda-verify-unavailable (Prompt-resolving tool against deployment without
// PDA verify wired). Driver MUST count those as SkippedPdaUnavail and
// continue past them — does NOT fail the run.
func TestDriverTolerates503PdaVerifyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"pda-verify-unavailable","reason":"pda-verify-unavailable"}`))
	}))
	defer srv.Close()

	stats, err := driveAuditRecordsWith(context.Background(),
		&http.Client{Timeout: 3 * time.Second}, srv.URL,
		"ses_test1234567890abcdef", "bearer-x",
		[]string{"net__http_get", "fs__delete_file"}, 5, 0)
	if err != nil {
		t.Fatalf("driver should not error on 503 pda-verify-unavailable: %v", err)
	}
	if stats.Written != 0 {
		t.Errorf("Written=%d, want 0 (all 503'd)", stats.Written)
	}
	if stats.SkippedPdaUnavail != 5 {
		t.Errorf("SkippedPdaUnavail=%d, want 5", stats.SkippedPdaUnavail)
	}
}

// TestDriverMixedSuccessAnd503: alternating 201 / 503-pda response.
// Driver writes the 201s, skips the 503s, completes the loop.
func TestDriverMixedSuccessAnd503(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n%2 == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"pda-verify-unavailable","reason":"pda-verify-unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	stats, err := driveAuditRecordsWith(context.Background(),
		&http.Client{Timeout: 3 * time.Second}, srv.URL,
		"ses_test1234567890abcdef", "bearer-x",
		[]string{"fs__read_file", "net__http_get"}, 6, 0)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	// 6 calls; odd #s 201, even #s 503 → 3 written, 3 skipped.
	if stats.Written != 3 || stats.SkippedPdaUnavail != 3 {
		t.Errorf("got Written=%d Skipped=%d; want 3 each", stats.Written, stats.SkippedPdaUnavail)
	}
}

// TestDriverFailsLoudlyOnUnknownStatus: server returns 401 (unknown
// failure mode for driver). Driver MUST stop and return error rather
// than treating it as a quiet skip.
func TestDriverFailsLoudlyOnUnknownStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"missing-or-invalid-bootstrap-bearer"}`))
	}))
	defer srv.Close()

	_, err := driveAuditRecordsWith(context.Background(),
		&http.Client{Timeout: 3 * time.Second}, srv.URL,
		"ses_x", "bearer-x", []string{"fs__read_file"}, 3, 0)
	if err == nil {
		t.Error("expected loud error on 401, got nil")
	}
}
