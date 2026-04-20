package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBearerInjected(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, BearerToken: "tok-abc"})
	resp, err := c.Do(context.Background(), http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer tok-abc" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok-abc")
	}
}

func TestHealthProbeOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, Timeout: 2 * time.Second})
	if err := c.Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestHealthProbeFailsOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, Timeout: 2 * time.Second})
	if err := c.Health(context.Background()); err == nil {
		t.Error("expected error on 500, got nil")
	}
}

func TestTLSWithPinnedTrustAnchor(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Write the server's cert to a PEM file on disk so we exercise the real
	// loadTrustAnchor code path (file → x509.CertPool).
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.pem")
	writeCertPEM(t, caPath, srv.Certificate())

	tlsCfg, err := BuildTLSConfig(TLSOptions{TrustAnchorPEMPath: caPath})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	c := New(Config{BaseURL: srv.URL, TLSConfig: tlsCfg, Timeout: 3 * time.Second})
	if err := c.Health(context.Background()); err != nil {
		t.Errorf("Health over pinned-TLS: %v", err)
	}
}

func TestTLSRejectsUnpinnedServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Empty trust anchor (system roots) won't trust httptest's self-signed cert.
	tlsCfg, err := BuildTLSConfig(TLSOptions{TrustAnchorPEMPath: ""})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	// BuildTLSConfig returns nil for fully-empty options; construct one manually.
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := New(Config{BaseURL: srv.URL, TLSConfig: tlsCfg, Timeout: 3 * time.Second})
	err = c.Health(context.Background())
	if err == nil {
		t.Error("expected TLS verification error against self-signed server without pinned anchor")
		return
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

func TestBuildTLSConfig_ValidatesClientCertPair(t *testing.T) {
	// Client key without cert (and vice versa) must fail loudly.
	_, err := BuildTLSConfig(TLSOptions{ClientCertPEMPath: "x.pem"})
	if err == nil {
		t.Error("expected error for cert without key, got nil")
	}
	_, err = BuildTLSConfig(TLSOptions{ClientKeyPEMPath: "x.key"})
	if err == nil {
		t.Error("expected error for key without cert, got nil")
	}
}

func TestBuildTLSConfig_ZeroReturnsNil(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSOptions{})
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil tls.Config for zero opts, got %+v", cfg)
	}
}

// SSE happy path: server emits two events, client's handler receives both.
func TestStreamConsumesSSEEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/stream/v1/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `data: {"event_id":"evt_abc1234567890000","sequence":0,"session_id":"s1","type":"SessionStart","payload":{},"timestamp":"2026-04-20T00:00:00Z"}`+"\n\n")
		io.WriteString(w, `data: {"event_id":"evt_abc1234567890001","sequence":1,"session_id":"s1","type":"SessionEnd","payload":{},"timestamp":"2026-04-20T00:00:01Z"}`+"\n\n")
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, Timeout: 3 * time.Second})
	var got []string
	err := c.Stream(context.Background(), "s1", func(ev StreamEvent) error {
		got = append(got, ev.Type)
		return nil
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if len(got) != 2 || got[0] != "SessionStart" || got[1] != "SessionEnd" {
		t.Errorf("got events %v, want [SessionStart SessionEnd]", got)
	}
}

// helper — writes an x509.Certificate to a PEM file. Uses cert.Raw so we
// don't need to reach into httptest internals.
func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}
