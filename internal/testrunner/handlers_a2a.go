package testrunner

// M9 A2A-surface probes (spec §17; v1.3).
//
// Registration strategy: handler wiring lands now; the live-probe bodies
// promote to real HTTP exercises in M9 W5 (validator-probes milestone).
// Until then each handler returns a skip with a precise rationale pointing
// at the impl-unit-test that carries current coverage.
//
// This file is forward-compatible with must-map entries that exist in the
// spec repo at commit ≥ ff702f4 but have not yet propagated to this
// repo's soa-validate.lock pin (still at c958bf9, v1.2.0 era). When the
// pin bumps at the v1.3.0 ceremony, these handlers become the dispatch
// targets for the newly-reachable test IDs. Until then the handler map
// entries are dormant (runner dispatches by ID presence in the pinned
// must-map, not by handler map membership).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wleeb1010/soa-validate/internal/jcs"
)

// loadA2aProbeEd25519Key parses an Ed25519 private key from the PEM at
// SOA_A2A_PROBE_CALLER_KEY_PEM. Returns (nil, "", "") when the env var
// is unset so callers can cleanly skip.
func loadA2aProbeEd25519Key() (ed25519.PrivateKey, string) {
	keyPath := os.Getenv("SOA_A2A_PROBE_CALLER_KEY_PEM")
	if keyPath == "" {
		return nil, ""
	}
	kid := os.Getenv("SOA_A2A_PROBE_CALLER_KID")
	if kid == "" {
		return nil, ""
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ""
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ""
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, ""
	}
	return priv, kid
}

// signA2aProbeJwt signs a compact JWS with EdDSA over the caller's
// Ed25519 key. header.alg + header.kid are set; caller supplies the
// payload. Returns the compact JWT string.
func signA2aProbeJwt(priv ed25519.PrivateKey, kid string, payload map[string]any) (string, error) {
	header := map[string]any{"alg": "EdDSA", "kid": kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// a2aJwtAudience returns the callee URL the JWT aud claim must equal.
// If SOA_A2A_AUDIENCE is unset, JWT-mode probes skip.
func a2aJwtAudience() string {
	return os.Getenv("SOA_A2A_AUDIENCE")
}

// craftA2aJwt builds a compact JWT (header.payload.signature) with the
// given protected header + payload. `signature` is the base64url-encoded
// signature bytes — for probes that exercise pre-signature-verify failure
// paths (alg-allowlist rejection, claim-shape rejection, jti replay,
// key-not-found), the signature can be an arbitrary non-empty base64url
// sequence since the Runner MUST reject before verify.
func craftA2aJwt(header, payload map[string]any, signature string) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(pb) + "." + signature, nil
}

// baseA2aJwtPayload returns a well-formed §17.1 JWT payload using the
// given audience. iat/exp are set against the given `now` (unix seconds)
// with a 60s lifetime well under the §17.1 300s cap.
func baseA2aJwtPayload(aud string, now int64, jti string) map[string]any {
	return map[string]any{
		"iss":             "sv-a2a-probe-caller",
		"sub":             "https://probe.caller.test.local",
		"aud":             aud,
		"iat":             now,
		"exp":             now + 60,
		"jti":             jti,
		"agent_card_etag": "\"probe-etag-placeholder\"",
	}
}

// computeA2aDigest returns the §17.2 digest of v as sha256:<64-hex-lowercase>.
// Uses the same JCS library that guarantees byte-equivalence with the TS impl's
// canonicalize output — mismatches here are spec bugs, not transport artifacts.
func computeA2aDigest(v any) (string, error) {
	canonical, err := jcs.Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ─── A2A live-probe helpers (§17 wire, bearer auth) ───────────────────────

// a2aProbeEnv resolves the a2a endpoint URL + bearer token from env vars.
// Returns empty strings when the probe should skip (no live target configured).
func a2aProbeEnv(h HandlerCtx) (a2aURL, bearer string) {
	if !h.Live {
		return "", ""
	}
	bearer = os.Getenv("SOA_A2A_BEARER")
	if bearer == "" {
		return "", ""
	}
	a2aURL = os.Getenv("SOA_A2A_URL")
	if a2aURL == "" {
		a2aURL = h.Client.BaseURL() + "/a2a/v1"
	}
	return
}

// a2aRpc fires a single JSON-RPC 2.0 request and returns parsed body + status.
// On transport error returns (nil, 0, error).
func a2aRpc(ctx context.Context, a2aURL, bearer, method string, params any, id string) (map[string]any, int, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", a2aURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("non-JSON a2a response (status=%d): %s", resp.StatusCode, string(rb))
	}
	return parsed, resp.StatusCode, nil
}

// a2aFetchCard fetches the Runner's Agent Card at .well-known/agent-card.json.
func a2aFetchCard(ctx context.Context, h HandlerCtx) (map[string]any, error) {
	url := h.Client.BaseURL() + "/.well-known/agent-card.json"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s status=%d", url, resp.StatusCode)
	}
	var card map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, err
	}
	return card, nil
}

// SV-A2A-10 through SV-A2A-16: JWT profile + digest + HandoffStatus + deadlines
// probes. Each returns skip-with-rationale until the SOA_A2A_* env vars that
// enable a real probe run are set. Unit-test-level coverage for these
// assertions lives in soa-harness-impl/packages/runner/test/a2a-{jwt,signer-
// discovery,digest-check}.test.ts.

// SV-A2A-10: §17.1 step 1 JWT alg allowlist — LIVE.
//
// Crafts a JWT with header.alg="HS256" (not in the §17.1 allowlist of
// {EdDSA, ES256, RS256≥3072}) + an otherwise well-formed payload. Sends
// it as the Authorization: Bearer <jwt>. Expects HandoffRejected(-32051)
// with reason=bad-alg because §17.1 step 1 rejects on alg BEFORE
// signature verify or claim validation.
//
// No cooperating signing key required — the probe never gets past the
// alg check. Skips cleanly when SOA_A2A_AUDIENCE is unset (Runner not
// configured in JWT mode).
func handleSVA2A10(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-10: SOA_IMPL_URL unset"}}
	}
	aud := a2aJwtAudience()
	if aud == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-10: set SOA_A2A_AUDIENCE to activate the JWT-mode probe. Unit coverage at soa-harness-impl/packages/runner/test/a2a-jwt.test.ts (alg-outside-allowlist test)."}}
	}
	a2aURL := os.Getenv("SOA_A2A_URL")
	if a2aURL == "" {
		a2aURL = h.Client.BaseURL() + "/a2a/v1"
	}
	now := time.Now().Unix()
	header := map[string]any{"alg": "HS256", "kid": "probe-bad-alg"}
	payload := baseA2aJwtPayload(aud, now, fmt.Sprintf("jti-sv-a2a-10-%d", now))
	jwt, err := craftA2aJwt(header, payload, "ZmFrZXNpZ25hdHVyZQ")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-10: JWT craft failed: %v", err)}}
	}
	body := map[string]any{"jsonrpc": "2.0", "id": "10", "method": "agent.describe"}
	bb, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", a2aURL, bytes.NewReader(bb))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-10: rpc transport error: %v", err)}}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-10: non-JSON response (status=%d): %s", resp.StatusCode, string(rb))}}
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok || int(coerceFloat(errObj["code"])) != -32051 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-10: expected -32051 HandoffRejected; got %v", parsed)}}
	}
	data, _ := errObj["data"].(map[string]any)
	if data["reason"] != "bad-alg" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-10: expected reason=bad-alg; got %v", errObj)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-A2A-10: alg=HS256 JWT rejected with -32051 reason=bad-alg before signature verify"}}
}

// SV-A2A-11: §17.1 step 2 signing-key discovery (Agent-Card-kid path) — LIVE.
//
// Sends one signed JWT and asserts the Runner successfully resolves the
// signing key + verifies the signature (200 with a result member). The
// mTLS x5t#S256 path (step 2 bullet 2) is out of Slice 5 scope — live
// probing it requires a cooperating mTLS client cert harness.
func handleSVA2A11(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-11: SOA_IMPL_URL unset"}}
	}
	aud := a2aJwtAudience()
	priv, kid := loadA2aProbeEd25519Key()
	if aud == "" || priv == nil {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-11: set SOA_A2A_AUDIENCE + SOA_A2A_PROBE_CALLER_KEY_PEM + SOA_A2A_PROBE_CALLER_KID (same env as SV-A2A-12) to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a-signer-discovery.test.ts (27 assertions)."}}
	}
	a2aURL := os.Getenv("SOA_A2A_URL")
	if a2aURL == "" {
		a2aURL = h.Client.BaseURL() + "/a2a/v1"
	}
	now := time.Now().Unix()
	payload := baseA2aJwtPayload(aud, now, fmt.Sprintf("jti-sv-a2a-11-%d", now))
	jwt, err := signA2aProbeJwt(priv, kid, payload)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-11: JWT sign: %v", err)}}
	}
	bodyReq := map[string]any{"jsonrpc": "2.0", "id": "11", "method": "agent.describe"}
	bb, _ := json.Marshal(bodyReq)
	req, _ := http.NewRequestWithContext(ctx, "POST", a2aURL, bytes.NewReader(bb))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-11: rpc: %v", err)}}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-11: non-JSON (status=%d): %s", resp.StatusCode, string(rb))}}
	}
	if _, ok := parsed["result"]; !ok {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-11: signed JWT not accepted — signing-key discovery failed. Response: %v", parsed)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-A2A-11: signed JWT accepted (Agent-Card-kid resolution succeeded per §17.1 step 2 first bullet)."}}
}

// SV-A2A-12: §17.1 step 3 jti replay cache — LIVE.
//
// Sends the same signed JWT twice within the exp+30s retention window.
// First send MUST succeed (200 OK with the agent.describe result);
// second send MUST be rejected with -32051 HandoffRejected reason=
// jti-replay per §17.1 step 3's register-only-after-verify invariant.
//
// Requires a cooperating signing key — the Runner under test must be
// configured with a resolver that returns the validator's Ed25519
// public key for the kid specified. Conformance-test convention:
//   SOA_A2A_PROBE_CALLER_KEY_PEM  — Ed25519 private key PEM (PKCS#8)
//   SOA_A2A_PROBE_CALLER_KID       — kid the Runner resolver accepts
//   SOA_A2A_AUDIENCE               — callee URL; JWT aud claim target
// Skips cleanly when any of those are unset.
func handleSVA2A12(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-12: SOA_IMPL_URL unset"}}
	}
	aud := a2aJwtAudience()
	priv, kid := loadA2aProbeEd25519Key()
	if aud == "" || priv == nil {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-12: set SOA_A2A_AUDIENCE + SOA_A2A_PROBE_CALLER_KEY_PEM (Ed25519 PKCS#8 PEM) + SOA_A2A_PROBE_CALLER_KID (kid the Runner resolver accepts) to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a-jwt.test.ts (replayed-jti test)."}}
	}
	a2aURL := os.Getenv("SOA_A2A_URL")
	if a2aURL == "" {
		a2aURL = h.Client.BaseURL() + "/a2a/v1"
	}
	now := time.Now().Unix()
	jti := fmt.Sprintf("jti-sv-a2a-12-replay-%d", now)
	payload := baseA2aJwtPayload(aud, now, jti)
	jwt, err := signA2aProbeJwt(priv, kid, payload)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-12: JWT sign: %v", err)}}
	}

	// Send twice. Either (a) both attempts succeed (jti cache not enforced —
	// fail the probe) or (b) first succeeds + second rejects with jti-replay
	// (pass) or (c) first fails (something upstream is wrong — error, not fail).
	bodyReq := map[string]any{"jsonrpc": "2.0", "id": "12", "method": "agent.describe"}
	bb, _ := json.Marshal(bodyReq)

	doCall := func() (map[string]any, error) {
		req, _ := http.NewRequestWithContext(ctx, "POST", a2aURL, bytes.NewReader(bb))
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		var parsed map[string]any
		if err := json.Unmarshal(rb, &parsed); err != nil {
			return nil, fmt.Errorf("non-JSON (status=%d): %s", resp.StatusCode, string(rb))
		}
		return parsed, nil
	}

	first, err := doCall()
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-12: first call: %v", err)}}
	}
	if _, hasResult := first["result"]; !hasResult {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-12: first call did not succeed — probe needs a working cooperating key (verify SOA_A2A_PROBE_CALLER_* env matches Runner resolver). Response: %v", first)}}
	}
	second, err := doCall()
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-12: second call: %v", err)}}
	}
	errObj, ok := second["error"].(map[string]any)
	if !ok || int(coerceFloat(errObj["code"])) != -32051 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-12: replayed JWT was accepted (expected -32051 jti-replay); got %v", second)}}
	}
	data, _ := errObj["data"].(map[string]any)
	if data["reason"] != "jti-replay" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-12: replayed JWT rejected with -32051 but reason=%v (expected jti-replay)", data["reason"])}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-A2A-12: replayed jti rejected with -32051 reason=jti-replay per §17.1 step 3"}}
}

// SV-A2A-13: §17.1 step 4 agent_card_etag drift — LIVE.
//
// Signs a JWT whose agent_card_etag claim is a deliberately-stale
// value ("sv-a2a-13-deliberately-stale"). Runner fetches the caller's
// card, computes the real etag via §17.2.4 formula, mismatches,
// rejects with -32051 reason=card-version-drift (byte-exact) per the
// §17.1 step 4 normative clause (spec f4087a7).
func handleSVA2A13(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-13: SOA_IMPL_URL unset"}}
	}
	aud := a2aJwtAudience()
	priv, kid := loadA2aProbeEd25519Key()
	if aud == "" || priv == nil {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-13: set SOA_A2A_AUDIENCE + SOA_A2A_PROBE_CALLER_KEY_PEM + SOA_A2A_PROBE_CALLER_KID (same env as SV-A2A-12) to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a-signer-discovery.test.ts (checkAgentCardEtagDrift match/drift/unreachable)."}}
	}
	a2aURL := os.Getenv("SOA_A2A_URL")
	if a2aURL == "" {
		a2aURL = h.Client.BaseURL() + "/a2a/v1"
	}
	now := time.Now().Unix()
	payload := baseA2aJwtPayload(aud, now, fmt.Sprintf("jti-sv-a2a-13-%d", now))
	payload["agent_card_etag"] = "\"sv-a2a-13-deliberately-stale\""
	jwt, err := signA2aProbeJwt(priv, kid, payload)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-13: JWT sign: %v", err)}}
	}
	bodyReq := map[string]any{"jsonrpc": "2.0", "id": "13", "method": "agent.describe"}
	bb, _ := json.Marshal(bodyReq)
	req, _ := http.NewRequestWithContext(ctx, "POST", a2aURL, bytes.NewReader(bb))
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-13: rpc: %v", err)}}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-13: non-JSON (status=%d): %s", resp.StatusCode, string(rb))}}
	}
	errObj, ok := parsed["error"].(map[string]any)
	if !ok || int(coerceFloat(errObj["code"])) != -32051 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-13: expected -32051 HandoffRejected for stale agent_card_etag; got %v", parsed)}}
	}
	data, _ := errObj["data"].(map[string]any)
	if data["reason"] != "card-version-drift" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-13: expected reason=card-version-drift (byte-exact); got reason=%v", data["reason"])}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-A2A-13: stale agent_card_etag → -32051 reason=card-version-drift per §17.1 step 4 (byte-exact match)"}}
}

// SV-A2A-14: §17.2.5 per-method digest recompute — LIVE.
//
// Offer-then-transfer flow exercising the handoff.transfer row of the
// §17.2.5 matrix against a real Runner. Three assertions:
//   1. Matching-digest transfer → accept.
//   2. Tampered-messages transfer (same task_id, different payload) →
//      HandoffRejected(reason=digest-mismatch).
//   3. Never-seen task_id transfer → HandoffRejected(reason=workflow-
//      state-incompatible) (§17.2.5 restart-crash observability row).
//
// Each uses a fresh task_id per subtest so offer-state retention
// doesn't cross-contaminate.
func handleSVA2A14(ctx context.Context, h HandlerCtx) []Evidence {
	a2aURL, bearer := a2aProbeEnv(h)
	if a2aURL == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-14: set SOA_A2A_BEARER to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a-digest-check.test.ts (16 assertions across the §17.2.5 matrix)."}}
	}

	messages := []any{map[string]any{"role": "user", "content": "hello"}}
	// Per-assertion workflow objects constructed below (each uses its own
	// task_id → distinct workflow_digest). The messages payload is shared
	// across assertions 1 + 3; assertion 2 tampers messages explicitly.
	msgDigest, err := computeA2aDigest(messages)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14: JCS canonicalize messages: %v", err)}}
	}

	out := []Evidence{}

	// Assertion 1: offer-then-transfer with matching digests → accept.
	taskID1 := fmt.Sprintf("t_sv_a2a_14_accept_%d", time.Now().UnixNano())
	wf1 := map[string]any{"task_id": taskID1, "status": "Handoff", "side_effects": []any{}}
	wf1Digest, _ := computeA2aDigest(wf1)
	_, _, err = a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id": taskID1, "summary": "accept probe",
		"messages_digest": msgDigest, "workflow_digest": wf1Digest,
		"capabilities_needed": []string{},
	}, "14a-offer")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14 [accept]: offer rpc error: %v", err)})
	} else {
		body, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.transfer", map[string]any{
			"task_id": taskID1, "messages": messages, "workflow": wf1,
			"billing_tag": "tenant/env", "correlation_id": "cor_" + stringRepeat("c", 20),
		}, "14a-xfer")
		if err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("SV-A2A-14 [accept]: transfer rpc error: %v", err)})
		} else if res, ok := body["result"].(map[string]any); !ok || res["destination_session_id"] == nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-14 [accept]: expected result.destination_session_id; got %v", body)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "SV-A2A-14 [accept]: matching-digest transfer accepted"})
		}
	}

	// Assertion 2: offer with correct digest, transfer tampered messages → digest-mismatch.
	taskID2 := fmt.Sprintf("t_sv_a2a_14_tamper_%d", time.Now().UnixNano())
	wf2 := map[string]any{"task_id": taskID2, "status": "Handoff", "side_effects": []any{}}
	wf2Digest, _ := computeA2aDigest(wf2)
	_, _, err = a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id": taskID2, "summary": "tamper probe",
		"messages_digest": msgDigest, "workflow_digest": wf2Digest,
		"capabilities_needed": []string{},
	}, "14b-offer")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14 [tamper]: offer rpc error: %v", err)})
	} else {
		tampered := []any{map[string]any{"role": "user", "content": "TAMPERED"}}
		body, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.transfer", map[string]any{
			"task_id": taskID2, "messages": tampered, "workflow": wf2,
			"billing_tag": "tenant/env", "correlation_id": "cor_" + stringRepeat("c", 20),
		}, "14b-xfer")
		if err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("SV-A2A-14 [tamper]: transfer rpc error: %v", err)})
		} else if errObj, ok := body["error"].(map[string]any); !ok || int(coerceFloat(errObj["code"])) != -32051 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-14 [tamper]: expected -32051 HandoffRejected; got %v", body)})
		} else if data, _ := errObj["data"].(map[string]any); data["reason"] != "digest-mismatch" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-14 [tamper]: expected reason=digest-mismatch; got %v", errObj)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "SV-A2A-14 [tamper]: tampered-messages transfer → -32051 reason=digest-mismatch"})
		}
	}

	// Assertion 3: transfer for never-seen task_id → workflow-state-incompatible.
	neverSeen := fmt.Sprintf("t_sv_a2a_14_neverseen_%d", time.Now().UnixNano())
	wf3 := map[string]any{"task_id": neverSeen, "status": "Handoff", "side_effects": []any{}}
	body3, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.transfer", map[string]any{
		"task_id": neverSeen, "messages": messages, "workflow": wf3,
		"billing_tag": "tenant/env", "correlation_id": "cor_" + stringRepeat("c", 20),
	}, "14c-xfer")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14 [never-seen]: rpc error: %v", err)})
	} else if errObj, ok := body3["error"].(map[string]any); !ok || int(coerceFloat(errObj["code"])) != -32051 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-14 [never-seen]: expected -32051 HandoffRejected; got %v", body3)})
	} else if data, _ := errObj["data"].(map[string]any); data["reason"] != "workflow-state-incompatible" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-14 [never-seen]: expected reason=workflow-state-incompatible; got %v", errObj)})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "SV-A2A-14 [never-seen]: no-offer-state transfer → -32051 reason=workflow-state-incompatible"})
	}

	return out
}

// SV-A2A-15: §17.2.1 HandoffStatus enum + transition matrix — LIVE (partial).
//
// Covers the transitions that are observable TODAY against the v1.3.0
// reference Runner (which auto-transitions accepted → completed when
// handoff.return fires; the accepted → executing → completed full
// lifecycle requires a Runner-side slow-task fixture not yet shipped).
//
// Six assertions, each an independent Evidence row:
//   (a) handoff.status on unknown task_id → HandoffStateIncompatible (-32052).
//   (b) status after successful transfer → "accepted".
//   (c) status enum value ∈ §17.2.1 closed-set {accepted, executing,
//       completed, rejected, failed, timed-out}.
//   (d) status response carries last_event_id key (string|null per enum row).
//   (e) status after handoff.return → "completed".
//   (f) terminal monotonicity: second status call after completed still
//       returns "completed" (MUST NOT transition forward).
//
// Partial scope: the accepted → executing intermediate step is NOT
// observable against the current Runner (which has no execute hook
// wired). Closing that gap is Slice 6b — Runner-side work under L-70.
func handleSVA2A15(ctx context.Context, h HandlerCtx) []Evidence {
	a2aURL, bearer := a2aProbeEnv(h)
	if a2aURL == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-15: set SOA_A2A_BEARER to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a.test.ts (A2aTaskRegistry monotonicity tests)."}}
	}
	validStatus := map[string]bool{
		"accepted": true, "executing": true, "completed": true,
		"rejected": true, "failed": true, "timed-out": true,
	}
	validDigest := "sha256:" + stringRepeat("a", 64)
	out := []Evidence{}

	// (a) Unknown task_id → HandoffStateIncompatible (-32052).
	unknownID := fmt.Sprintf("t_sv_a2a_15_unknown_%d", time.Now().UnixNano())
	body, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.status", map[string]any{"task_id": unknownID}, "15a")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15 [unknown]: rpc: %v", err)})
	} else if errObj, ok := body["error"].(map[string]any); !ok || int(coerceFloat(errObj["code"])) != -32052 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-15 [unknown task_id]: expected -32052 HandoffStateIncompatible; got %v", body)})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "SV-A2A-15 [unknown task_id] → -32052 HandoffStateIncompatible"})
	}

	// Setup: offer + transfer so the Runner has retained offer state + "accepted" status.
	taskID := fmt.Sprintf("t_sv_a2a_15_flow_%d", time.Now().UnixNano())
	messages := []any{map[string]any{"role": "user", "content": "probe"}}
	workflow := map[string]any{"task_id": taskID, "status": "Handoff", "side_effects": []any{}}
	msgDigest, _ := computeA2aDigest(messages)
	wfDigest, _ := computeA2aDigest(workflow)
	_, _, err = a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id": taskID, "summary": "SV-A2A-15",
		"messages_digest": msgDigest, "workflow_digest": wfDigest,
		"capabilities_needed": []string{},
	}, "15-offer")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15: setup offer rpc: %v", err)})
		return out
	}
	_, _, err = a2aRpc(ctx, a2aURL, bearer, "handoff.transfer", map[string]any{
		"task_id": taskID, "messages": messages, "workflow": workflow,
		"billing_tag": "tenant/env", "correlation_id": "cor_" + stringRepeat("c", 20),
	}, "15-xfer")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15: setup transfer rpc: %v", err)})
		return out
	}

	// (b + c + d) Status after transfer → accepted + enum membership + last_event_id key present.
	body1, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.status", map[string]any{"task_id": taskID}, "15b")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15 [status-after-transfer]: rpc: %v", err)})
	} else if res, ok := body1["result"].(map[string]any); !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-15 [status-after-transfer]: no result member: %v", body1)})
	} else {
		status, _ := res["status"].(string)
		if status != "accepted" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-15 [status-after-transfer]: expected status=accepted; got %q", status)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "SV-A2A-15 [status-after-transfer] → accepted"})
		}
		if !validStatus[status] {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-15 [enum membership]: observed status %q not in §17.2.1 closed-set", status)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: fmt.Sprintf("SV-A2A-15 [enum membership]: %q ∈ §17.2.1 closed-set", status)})
		}
		if _, has := res["last_event_id"]; !has {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: "SV-A2A-15 [last_event_id key]: result missing required last_event_id field"})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "SV-A2A-15 [last_event_id key]: result carries last_event_id (string|null per §17.2.1)"})
		}
	}

	// (e) handoff.return → status transitions to completed.
	_, _, err = a2aRpc(ctx, a2aURL, bearer, "handoff.return", map[string]any{
		"task_id": taskID, "result_digest": validDigest, "final_messages": []any{},
	}, "15-return")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15 [return]: rpc: %v", err)})
		return out
	}
	body2, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.status", map[string]any{"task_id": taskID}, "15e")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15 [status-after-return]: rpc: %v", err)})
	} else if res, ok := body2["result"].(map[string]any); !ok || res["status"] != "completed" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-15 [status-after-return]: expected status=completed; got %v", body2)})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "SV-A2A-15 [status-after-return] → completed"})
	}

	// (f) Terminal monotonicity: second status call still completed.
	body3, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.status", map[string]any{"task_id": taskID}, "15f")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-15 [terminal monotonicity]: rpc: %v", err)})
	} else if res, ok := body3["result"].(map[string]any); !ok || res["status"] != "completed" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-15 [terminal monotonicity]: second status must still return completed; got %v", body3)})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "SV-A2A-15 [terminal monotonicity]: repeat handoff.status returns completed (§17.2.1 MUST)"})
	}

	return out
}

func handleSVA2A16Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-16: §17.2.2 per-method deadlines + env-var overrides. Live probe requires booting a Runner with a specific SOA_A2A_*_DEADLINE_S env override and timing request round-trips; unit coverage at packages/runner/test/a2a.test.ts (resolveA2aDeadlines env-override tests).",
	}}
}

// SV-A2A-03: §17.2.4 agent.describe result envelope — LIVE.
//
// Asserts the §17.2.4 result shape: two required fields (card, jws),
// correct JSON types (card=object, jws=string), compact-detached JWS
// shape (^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$), unknown-fields tolerated
// (additive-minor). §6.1.1 JWS-crypto coverage composes from SV-SIGN-
// 01..05 and SV-CARD-01..11 — SV-A2A-03 does NOT duplicate those.
func handleSVA2A03(ctx context.Context, h HandlerCtx) []Evidence {
	a2aURL, bearer := a2aProbeEnv(h)
	if a2aURL == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-03: set SOA_A2A_BEARER to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a-boot.test.ts (7 end-to-end §17.2.4 assertions)."}}
	}
	body, _, err := a2aRpc(ctx, a2aURL, bearer, "agent.describe", nil, "a03")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-03: rpc error: %v", err)}}
	}
	res, ok := body["result"].(map[string]any)
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-03: result member absent or not an object; body=%v", body)}}
	}
	card, hasCard := res["card"].(map[string]any)
	jws, hasJws := res["jws"].(string)
	if !hasCard {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-A2A-03: result.card absent or not a JSON object"}}
	}
	if !hasJws {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-A2A-03: result.jws absent or not a string"}}
	}
	// Compact-detached shape: two dots, non-empty header + signature, empty body.
	parts := splitDots(jws)
	if len(parts) != 3 || parts[0] == "" || parts[1] != "" || parts[2] == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-03: result.jws is not compact-detached shape (<header>..<signature>); got %q", jws)}}
	}
	_ = card // card shape checks are composed via SV-CARD-01..11 at the conformance layer
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-A2A-03: §17.2.4 envelope shape OK — {card:object, jws:string(%d chars, compact-detached)}", len(jws))}}
}

// SV-A2A-04: §17.2 handoff.offer accept — LIVE.
//
// Asserts the generic accept path: a well-formed offer with empty
// capabilities_needed returns {accept:true} on capability grounds per
// §17.2.3 truth-table row 1/3. Trigger-condition discrimination is the
// remit of SV-A2A-17; SV-A2A-04 asserts only that the accept surface
// exists and produces the expected shape.
func handleSVA2A04(ctx context.Context, h HandlerCtx) []Evidence {
	a2aURL, bearer := a2aProbeEnv(h)
	if a2aURL == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-04: set SOA_A2A_BEARER to activate. Unit coverage at soa-harness-impl/packages/runner/test/a2a.test.ts (accept-path test)."}}
	}
	validDigest := "sha256:" + stringRepeat("a", 64)
	body, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id":             "t_sv_a2a_04_accept",
		"summary":             "well-formed accept probe",
		"messages_digest":     validDigest,
		"workflow_digest":     validDigest,
		"capabilities_needed": []string{},
	}, "a04")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-04: rpc error: %v", err)}}
	}
	res, ok := body["result"].(map[string]any)
	if !ok || res["accept"] != true {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-04: expected {accept:true}; got %v", body)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-A2A-04: handoff.offer accept path returns {accept:true} for empty capabilities_needed"}}
}

func splitDots(s string) []string {
	out := []string{""}
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, "")
		} else {
			out[len(out)-1] += string(s[i])
		}
	}
	return out
}

// SV-A2A-17: §17.2.3 A2A capability advertisement and matching — LIVE.
//
// Slice 1 of L-70 v1.3.x live-probe promotion. Bearer-mode auth
// (SOA_A2A_BEARER env required). Probe introspects the Runner's Agent
// Card to learn its advertised `a2a.capabilities` set, then exercises
// the three observable cells of the §17.2.3 truth table:
//   - Row 2 or Row 3 depending on advertised state: capabilities_needed
//     containing a token NOT in the advertised set.
//       • Serves-none   → {accept:false, reason:"no-a2a-capabilities-advertised"}
//       • Serves set S  → -32003 CapabilityMismatch with error.data.missing_capabilities
//   - Accept on empty needed (always {accept:true} on capability grounds).
//   - Subset-accept (only when advertised set is non-empty): first advertised
//     token → {accept:true}.
//
// Each assertion is emitted as its own Evidence row so a single failure
// doesn't mask downstream passes.
func handleSVA2A17(ctx context.Context, h HandlerCtx) []Evidence {
	a2aURL, bearer := a2aProbeEnv(h)
	if a2aURL == "" {
		return []Evidence{{
			Path: PathLive, Status: StatusSkip,
			Message: "SV-A2A-17: set SOA_A2A_BEARER (and optionally SOA_A2A_URL) to activate live probe. Unit coverage at soa-harness-impl/packages/runner/test/a2a.test.ts (40 assertions).",
		}}
	}
	card, err := a2aFetchCard(ctx, h)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-17: a2aFetchCard failed: %v", err)}}
	}
	advertised := extractA2aCapabilities(card)
	validDigest := "sha256:" + stringRepeat("a", 64)

	out := []Evidence{}

	// Assertion 1: empty capabilities_needed → {accept:true} on capability grounds.
	body1, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id": "t_sv_a2a_17_empty", "summary": "empty-needed",
		"messages_digest": validDigest, "workflow_digest": validDigest,
		"capabilities_needed": []string{},
	}, "a1")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-17 [empty needed]: rpc error: %v", err)})
	} else if res, ok := body1["result"].(map[string]any); !ok || res["accept"] != true {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-A2A-17 [empty needed]: expected {accept:true}; got %v", body1)})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "SV-A2A-17 [empty needed]: {accept:true} on capability grounds"})
	}

	// Assertion 2: unmatched needed.
	// Serves-none advertised → {accept:false, reason:"no-a2a-capabilities-advertised"}.
	// Serves set S → -32003 CapabilityMismatch with error.data.missing_capabilities.
	body2, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
		"task_id": "t_sv_a2a_17_unmatched", "summary": "unmatched",
		"messages_digest": validDigest, "workflow_digest": validDigest,
		"capabilities_needed": []string{"definitely-not-advertised-" + stringRepeat("x", 8)},
	}, "a2")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-17 [unmatched needed]: rpc error: %v", err)})
	} else if len(advertised) == 0 {
		// Serves-none path.
		res, ok := body2["result"].(map[string]any)
		if !ok || res["accept"] != false || res["reason"] != "no-a2a-capabilities-advertised" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-17 [serves-none × unmatched]: expected {accept:false, reason:\"no-a2a-capabilities-advertised\"}; got %v", body2)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "SV-A2A-17 [serves-none × unmatched]: byte-exact reason matches"})
		}
	} else {
		// Serves-set-S path.
		errObj, ok := body2["error"].(map[string]any)
		if !ok || int(coerceFloat(errObj["code"])) != -32003 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-17 [serves-S × unmatched]: expected -32003 CapabilityMismatch; got %v", body2)})
		} else {
			data, _ := errObj["data"].(map[string]any)
			missing, _ := data["missing_capabilities"].([]any)
			if len(missing) == 0 {
				out = append(out, Evidence{Path: PathLive, Status: StatusFail,
					Message: "SV-A2A-17 [serves-S × unmatched]: -32003 OK but error.data.missing_capabilities empty or absent"})
			} else {
				out = append(out, Evidence{Path: PathLive, Status: StatusPass,
					Message: fmt.Sprintf("SV-A2A-17 [serves-S × unmatched]: -32003 + error.data.missing_capabilities=%v", missing)})
			}
		}
	}

	// Assertion 3 (only when Runner advertises at least one capability): subset-accept.
	if len(advertised) > 0 {
		body3, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.offer", map[string]any{
			"task_id": "t_sv_a2a_17_subset", "summary": "subset-accept",
			"messages_digest": validDigest, "workflow_digest": validDigest,
			"capabilities_needed": []string{advertised[0]},
		}, "a3")
		if err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("SV-A2A-17 [subset accept]: rpc error: %v", err)})
		} else if res, ok := body3["result"].(map[string]any); !ok || res["accept"] != true {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-A2A-17 [subset accept]: expected {accept:true} for needed=[%q]; got %v", advertised[0], body3)})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: fmt.Sprintf("SV-A2A-17 [subset accept]: {accept:true} for needed=[%q]", advertised[0])})
		}
	}

	return out
}

func extractA2aCapabilities(card map[string]any) []string {
	a2a, ok := card["a2a"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := a2a["capabilities"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func coerceFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	if i, ok := v.(int); ok {
		return float64(i)
	}
	return 0
}

func stringRepeat(s string, n int) string {
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}
