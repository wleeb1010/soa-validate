package runner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSOptions describes how the runner client should establish TLS. Matches
// the spec's mTLS profile: the client verifies the server against a pinned
// trust anchor, and optionally presents a client cert for mTLS.
type TLSOptions struct {
	// TrustAnchorPEMPath is the path to a PEM file containing the CA cert(s)
	// the client should trust. Empty → use system roots.
	TrustAnchorPEMPath string

	// Optional client cert for mTLS. Both must be set or both empty.
	ClientCertPEMPath string
	ClientKeyPEMPath  string

	// ServerName overrides SNI / verification hostname if set.
	ServerName string

	// InsecureSkipVerify disables TLS verification. For local testing only.
	InsecureSkipVerify bool
}

// BuildTLSConfig turns options into a *tls.Config ready for an http.Transport.
// Returns (nil, nil) when all fields are empty — caller should leave TLS alone.
func BuildTLSConfig(o TLSOptions) (*tls.Config, error) {
	if (o.ClientCertPEMPath == "") != (o.ClientKeyPEMPath == "") {
		return nil, fmt.Errorf("ClientCertPEMPath and ClientKeyPEMPath must be set together")
	}
	if o == (TLSOptions{}) {
		return nil, nil
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         o.ServerName,
		InsecureSkipVerify: o.InsecureSkipVerify,
	}
	if o.TrustAnchorPEMPath != "" {
		pool, err := loadTrustAnchor(o.TrustAnchorPEMPath)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if o.ClientCertPEMPath != "" {
		cert, err := tls.LoadX509KeyPair(o.ClientCertPEMPath, o.ClientKeyPEMPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadTrustAnchor(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust anchor %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certs in %s", path)
	}
	return pool, nil
}
