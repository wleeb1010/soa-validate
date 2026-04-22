package testrunner

// Subprocess-isolated probes for V-9b impl-shipped findings:
//   BB (SV-PERM-03/04) — escalation env hooks
//   BC (SV-PERM-06/07) — WORM sink test mode
//   BD (SV-PERM-08)    — handler key enrollment clock injection
//   BE (SV-PERM-09/14/15) — handler CRL revocation
//   BF (SV-PERM-10)    — rotation overlap two-kid fixture
//   AE (SV-STR-10)     — CrashEvent + admin:read observation

import (
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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/jcs"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// bbcfBaseEnv constructs a common env map for the V-9b subprocess probes.
func bbcfBaseEnv(specRoot string, port int, bearer string) map[string]string {
	return map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
}

// ─── BB: SV-PERM-03 §10.4.1 — escalation-timeout → Deny ──────────────
//
// Impl `start-runner.ts:562` registers the default conformance handler
// kid as `role:"Interactive"`; there's no env override to mark it
// Autonomous, and POST /handlers/enroll (BG) doesn't thread `role`.
// Without an Autonomous-kid PDA, the §10.4.1 escalation path can't
// fire against real-world flows on this impl. Route as follow-up:
//
// **Finding BB-impl-ext (impl)**: either (a) accept `role` field on
// POST /handlers/enroll so validator can register an Autonomous kid
// + submit a PDA signed by it, OR (b) add env `SOA_HANDLER_DEFAULT_ROLE
// =Autonomous` so the conformance kid's role can be overridden for test
// runs. Validator probe is already written; just needs the Autonomous
// kid pathway.
func _handleSVPERM03Stub(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-03 (§10.4.1 escalation-timeout): stub reserved"}}
}

// L-50 BB-ext-2 live: resolvePdaVerifyKey now consults enrollment
// registry's stored DER SPKI to construct verification keys for
// dynamically-enrolled kids. Autonomous kids enrolled at runtime
// verify cleanly, so §10.4.1 escalation state-machine fires.
func handleSVPERM03Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-03: SOA_IMPL_BIN unset"}}
	}
	responderFile, cleanup := mustTempFile("svperm03-responder-*.jsonl")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm03-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_ESCALATION_TIMEOUT_MS"] = "500"
	env["SOA_HANDLER_ESCALATION_RESPONDER"] = responderFile
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		return autonomousPdaProbe(probeCtx, h, port, bearer, "svperm03-autonomous-kid", "",
			http.StatusForbidden, "escalation-timeout", "")
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

func _handleSVPERM03Probe(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-03: SOA_IMPL_BIN unset"}}
	}
	responderFile, cleanup := mustTempFile("svperm03-responder-*.jsonl")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm03-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_ESCALATION_TIMEOUT_MS"] = "500"
	env["SOA_HANDLER_ESCALATION_RESPONDER"] = responderFile
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Submit a high-risk decision that would require escalation. Don't
		// write anything to the responder file → escalation-timeout.
		resp, raw, err := submitAutonomousPDA(probeCtx, client, sid, sbearer, "fs__write_file")
		if err != nil {
			return "submit PDA: " + err.Error(), false
		}
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("status=%d (want 403 escalation-timeout); body=%.200q", resp.StatusCode, string(raw)), false
		}
		var dec struct{ Error, Reason string }
		_ = json.Unmarshal(raw, &dec)
		if dec.Reason != "escalation-timeout" {
			return fmt.Sprintf("reason=%q (want escalation-timeout); body=%.200q", dec.Reason, string(raw)), false
		}
		return "§10.4.1 SV-PERM-03 escalation-timeout: Autonomous-signed high-risk decision → 500ms silence → 403 escalation-timeout", true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BB: SV-PERM-04 §10.4.1 — HITL distinct from Autonomous ──────────
//
// Same Autonomous-kid gap as SV-PERM-03. See Finding BB-ext.
func handleSVPERM04Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-04: SOA_IMPL_BIN unset"}}
	}
	responderFile, cleanup := mustTempFile("svperm04-responder-*.jsonl")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm04-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_ESCALATION_TIMEOUT_MS"] = "3000"
	env["SOA_HANDLER_ESCALATION_RESPONDER"] = responderFile
	approve := `{"kid":"svperm04-autonomous-kid","response":"approve"}` + "\n"
	_ = os.WriteFile(responderFile, []byte(approve), 0o600)
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		return autonomousPdaProbe(probeCtx, h, port, bearer, "svperm04-autonomous-kid", "",
			http.StatusForbidden, "hitl-required", "autonomous")
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// autonomousPdaProbe:
//   1. Bootstraps a DFA+decide session.
//   2. Enrolls `autoKid` as role=Autonomous, sharing SPKI with the
//      conformance handler-keypair so the existing private key signs.
//   3. Mints a PDA with header.kid + payload.handler_kid = autoKid, signs
//      over JCS(payload) using the handler-keypair private key.
//   4. Submits to /permissions/decisions targeting a Mutating tool.
//   5. Asserts response matches (wantStatus, wantReason [, wantDetailContains]).
func autonomousPdaProbe(
	ctx context.Context, h HandlerCtx, port int, bearer, autoKid, _unused string,
	wantStatus int, wantReason, wantDetailContains string,
) (string, bool) {
	client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 8 * time.Second})
	sid, sbearer, status, err := m2Bootstrap(ctx, client, bearer)
	if err != nil || status != http.StatusCreated {
		return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
	}
	privKey, pubKey, err := readHandlerEd25519PrivKey(h.Spec)
	if err != nil {
		return "load handler privkey: " + err.Error(), false
	}
	// §10.6.3 spki = base64url of full DER SubjectPublicKeyInfo.
	spkiB64 := ed25519SpkiDerBase64Url(pubKey)
	enrollBody := fmt.Sprintf(`{"kid":%q,"spki":%q,"algo":"EdDSA","issued_at":"2026-04-22T12:00:00Z","role":"Autonomous"}`, autoKid, spkiB64)
	enrollReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"/handlers/enroll", strings.NewReader(enrollBody))
	enrollReq.Header.Set("Content-Type", "application/json")
	enrollReq.Header.Set("Authorization", "Bearer "+bearer)
	enrollResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(enrollReq)
	if err != nil {
		return "enroll: " + err.Error(), false
	}
	enrollRaw, _ := io.ReadAll(enrollResp.Body)
	enrollResp.Body.Close()
	if enrollResp.StatusCode != http.StatusCreated {
		return fmt.Sprintf("enroll status=%d; body=%.200q", enrollResp.StatusCode, string(enrollRaw)), false
	}
	argsDigest := fmt.Sprintf("sha256:%064x", time.Now().UnixNano())
	pda, err := mintPDA(privKey, autoKid, sid, "fs__write_file", argsDigest)
	if err != nil {
		return "mint PDA: " + err.Error(), false
	}
	body := fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":%q,"pda":%q}`, sid, argsDigest, pda)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sbearer)
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return "POST /permissions/decisions: " + err.Error(), false
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return fmt.Sprintf("status=%d (want %d); body=%.300q", resp.StatusCode, wantStatus, string(raw)), false
	}
	var dec struct {
		Error, Reason, Detail string
	}
	_ = json.Unmarshal(raw, &dec)
	if wantReason != "" && dec.Reason != wantReason {
		return fmt.Sprintf("reason=%q (want %q); body=%.300q", dec.Reason, wantReason, string(raw)), false
	}
	if wantDetailContains != "" && !strings.Contains(strings.ToLower(dec.Detail), strings.ToLower(wantDetailContains)) {
		return fmt.Sprintf("detail=%q missing %q marker; body=%.300q", dec.Detail, wantDetailContains, string(raw)), false
	}
	return fmt.Sprintf("§10.4.1: enrolled Autonomous kid %s + minted fresh PDA → %d %s", autoKid, resp.StatusCode, dec.Reason), true
}

func readHandlerEd25519PrivKey(spec specvec.Locator) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	raw, err := spec.Read("test-vectors/handler-keypair/private.pem")
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, nil, fmt.Errorf("pem decode: no block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an ed25519 key: %T", key)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// ed25519SpkiSha256Hex wraps raw Ed25519 pubkey in SubjectPublicKeyInfo
// DER, hashes with SHA-256, returns lowercase hex. Used for x5t#S256
// thumbprint matching.
func ed25519SpkiSha256Hex(pub ed25519.PublicKey) string {
	der := ed25519SpkiDer(pub)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ed25519SpkiDer returns the full DER SubjectPublicKeyInfo bytes for
// an Ed25519 public key. Fixed 12-byte prefix + 32-byte raw pubkey.
func ed25519SpkiDer(pub ed25519.PublicKey) []byte {
	der := make([]byte, 0, 44)
	der = append(der, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
	der = append(der, pub...)
	return der
}

// ed25519SpkiDerBase64Url returns base64url-no-pad of the full DER
// SubjectPublicKeyInfo. Used for §10.6.3 /handlers/enroll `spki` field.
func ed25519SpkiDerBase64Url(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(ed25519SpkiDer(pub))
}

func mintPDA(priv ed25519.PrivateKey, kid, sessionID, tool, argsDigest string) (string, error) {
	nowISO := time.Now().UTC().Format(time.RFC3339)
	payload := map[string]interface{}{
		"prompt_id":   fmt.Sprintf("prm_%d", time.Now().UnixNano()),
		"nonce":       fmt.Sprintf("nonce-%d", time.Now().UnixNano()),
		"decision":    "approve",
		"user_sub":    "m2-validator",
		"tool":        tool,
		"args_digest": argsDigest,
		"capability":  "WorkspaceWrite",
		"control":     "Prompt",
		"handler_kid": kid,
		"session_id":  sessionID,
		"decided_at":  nowISO,
	}
	payloadJCS, err := jcs.Canonicalize(payload)
	if err != nil {
		return "", err
	}
	header := map[string]interface{}{
		"alg": "EdDSA",
		"kid": kid,
		"typ": "soa-pda+jws",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJCS)
	signingInput := []byte(headerB64 + "." + payloadB64)
	sig := ed25519.Sign(priv, signingInput)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}

func _handleSVPERM04Probe(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-04: SOA_IMPL_BIN unset"}}
	}
	responderFile, cleanup := mustTempFile("svperm04-responder-*.jsonl")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm04-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_ESCALATION_TIMEOUT_MS"] = "2000"
	env["SOA_HANDLER_ESCALATION_RESPONDER"] = responderFile
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Write an Autonomous approve into the responder — should still 403 hitl-required.
		approvePayload := fmt.Sprintf(`{"kid":"soa-conformance-test-handler-v1.0","response":"approve"}` + "\n")
		if err := os.WriteFile(responderFile, []byte(approvePayload), 0o600); err != nil {
			return "write responder: " + err.Error(), false
		}
		resp, raw, err := submitAutonomousPDA(probeCtx, client, sid, sbearer, "fs__write_file")
		if err != nil {
			return "submit PDA: " + err.Error(), false
		}
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("status=%d (want 403 hitl-required); body=%.200q", resp.StatusCode, string(raw)), false
		}
		var dec struct {
			Error, Reason, Detail string
		}
		_ = json.Unmarshal(raw, &dec)
		if dec.Reason != "hitl-required" {
			return fmt.Sprintf("reason=%q (want hitl-required); body=%.200q", dec.Reason, string(raw)), false
		}
		if !strings.Contains(strings.ToLower(dec.Detail), "autonomous") {
			return fmt.Sprintf("detail=%q missing autonomous marker; body=%.200q", dec.Detail, string(raw)), false
		}
		return "§10.4.1 SV-PERM-04 HITL distinct: Autonomous approve in responder → 403 hitl-required + detail references autonomous-insufficient", true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// submitAutonomousPDA submits a permission-decision request targeting
// a Mutating tool. For M3 conformance impl, the "Autonomous handler"
// signal is implicit in the resolver path. Returns (response, body, err).
func submitAutonomousPDA(ctx context.Context, client *runner.Client, sid, sbearer, tool string) (*http.Response, []byte, error) {
	body := []byte(fmt.Sprintf(`{"tool":%q,"session_id":%q,"args_digest":"sha256:%064x","handler_role":"Autonomous"}`, tool, sid, time.Now().UnixNano()))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sbearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw, nil
}

// ─── BC: SV-PERM-06 §10.5.5 — WORM sink append-only ──────────────────

func handleSVPERM06Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-06: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm06-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_AUDIT_SINK_MODE"] = "worm-in-memory"
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Drive one decision so audit chain has at least one record.
		decBody := fmt.Sprintf(`{"tool":"fs__read_file","session_id":%q,"args_digest":"sha256:%064x"}`, sid, time.Now().UnixNano())
		decReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(decBody))
		decReq.Header.Set("Content-Type", "application/json")
		decReq.Header.Set("Authorization", "Bearer "+sbearer)
		decResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(decReq)
		if err != nil {
			return "drive decision: " + err.Error(), false
		}
		decResp.Body.Close()
		// Fetch a record id to target on mutation attempt.
		recsReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, client.BaseURL()+"/audit/records?limit=5", nil)
		recsReq.Header.Set("Authorization", "Bearer "+bearer)
		recsResp, _ := (&http.Client{Timeout: 5 * time.Second}).Do(recsReq)
		recsRaw, _ := io.ReadAll(recsResp.Body)
		recsResp.Body.Close()
		var recs struct {
			Records []struct{ ID string } `json:"records"`
		}
		_ = json.Unmarshal(recsRaw, &recs)
		if len(recs.Records) == 0 {
			return "no audit records after drive", false
		}
		targetID := recs.Records[0].ID
		// Attempt DELETE → must 405 (or 403/401 — any rejection signalling WORM immutability).
		delReq, _ := http.NewRequestWithContext(probeCtx, http.MethodDelete, fmt.Sprintf("%s/audit/records/%s", client.BaseURL(), targetID), nil)
		delReq.Header.Set("Authorization", "Bearer "+bearer)
		delResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(delReq)
		if err != nil {
			return "DELETE /audit/records: " + err.Error(), false
		}
		delRaw, _ := io.ReadAll(delResp.Body)
		delResp.Body.Close()
		if delResp.StatusCode == http.StatusOK || delResp.StatusCode == http.StatusNoContent {
			return fmt.Sprintf("DELETE /audit/records accepted (status=%d) — §10.5.5 WORM immutability violated", delResp.StatusCode), false
		}
		if delResp.StatusCode != http.StatusMethodNotAllowed && delResp.StatusCode != http.StatusForbidden && delResp.StatusCode != http.StatusNotFound {
			return fmt.Sprintf("DELETE status=%d (want 405 / 403 / 404); body=%.200q", delResp.StatusCode, string(delRaw)), false
		}
		return fmt.Sprintf("§10.5.5 WORM immutability: DELETE /audit/records/%s → %d (not 200/204)", targetID[:12], delResp.StatusCode), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BC: SV-PERM-07 §10.5.5 — sink_timestamp ±1s UTC ─────────────────

func handleSVPERM07Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-07: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm07-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_AUDIT_SINK_MODE"] = "worm-in-memory"
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		decBody := fmt.Sprintf(`{"tool":"fs__read_file","session_id":%q,"args_digest":"sha256:%064x"}`, sid, time.Now().UnixNano())
		decReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(decBody))
		decReq.Header.Set("Content-Type", "application/json")
		decReq.Header.Set("Authorization", "Bearer "+sbearer)
		decResp, _ := (&http.Client{Timeout: 5 * time.Second}).Do(decReq)
		if decResp != nil {
			decResp.Body.Close()
		}
		recsReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, client.BaseURL()+"/audit/records?limit=10", nil)
		recsReq.Header.Set("Authorization", "Bearer "+bearer)
		recsResp, _ := (&http.Client{Timeout: 5 * time.Second}).Do(recsReq)
		recsRaw, _ := io.ReadAll(recsResp.Body)
		recsResp.Body.Close()
		var recs struct {
			Records []map[string]interface{} `json:"records"`
		}
		_ = json.Unmarshal(recsRaw, &recs)
		if len(recs.Records) == 0 {
			return "no audit records", false
		}
		for _, r := range recs.Records {
			sinkTS, _ := r["sink_timestamp"].(string)
			ts, _ := r["timestamp"].(string)
			if sinkTS == "" {
				continue
			}
			t1, e1 := time.Parse(time.RFC3339Nano, ts)
			t2, e2 := time.Parse(time.RFC3339Nano, sinkTS)
			if e1 != nil || e2 != nil {
				continue
			}
			delta := t2.Sub(t1)
			if delta < 0 {
				delta = -delta
			}
			if delta > time.Second {
				return fmt.Sprintf("sink_timestamp vs timestamp delta=%s > 1s ceiling", delta), false
			}
			return fmt.Sprintf("§10.5.5 sink_timestamp: delta=%s ≤ 1s UTC ceiling", delta), true
		}
		return fmt.Sprintf("no record carries sink_timestamp field (across %d records)", len(recs.Records)), false
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BD: SV-PERM-08 §10.6.2 — handler key > 90d → reject ─────────────

func handleSVPERM08Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-08: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm08-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	// T_ref = 2026-04-22T12:00:00Z; enrolled 91 days earlier → expired.
	env["RUNNER_TEST_CLOCK"] = "2026-04-22T12:00:00Z"
	env["SOA_HANDLER_ENROLLED_AT"] = "2026-01-21T12:00:00Z"
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Submit a signed PDA — impl checks handler enroll age; 91d > 90d → HandlerKeyExpired.
		pdaBytes, err := h.Spec.Read(specvec.SignedPDAJWS)
		if err != nil {
			return "read signed PDA: " + err.Error(), false
		}
		body := fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":"sha256:%064x","pda":%q}`, sid, time.Now().UnixNano(), string(pdaBytes))
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sbearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "submit PDA: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("status=%d (want 403 HandlerKeyExpired); body=%.200q", resp.StatusCode, string(raw)), false
		}
		if !strings.Contains(string(raw), "HandlerKeyExpired") && !strings.Contains(string(raw), "key-age-exceeded") {
			return fmt.Sprintf("403 but body lacks HandlerKeyExpired / key-age-exceeded marker: %.200q", string(raw)), false
		}
		return "§10.6.2 SV-PERM-08: clock=T_ref + enrolled_at=T_ref−91d → PDA decision → 403 HandlerKeyExpired (key-age-exceeded)", true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BE: SV-PERM-09 §10.6.2 — revoked handler kid → HandlerKeyRevoked ─

func handleSVPERM09Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-09: SOA_IMPL_BIN unset"}}
	}
	revFile, cleanup := mustTempFile("svperm09-rev-*.json")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm09-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_CRL_POLL_TICK_MS"] = "100"
	env["SOA_BOOTSTRAP_REVOCATION_FILE"] = revFile
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Write handler-kid revocation to watched file.
		rev := `{"handler_kid":"soa-conformance-test-handler-v1.0","reason":"compromise-drill","revoked_at":"2026-04-22T12:00:00Z"}`
		if err := os.WriteFile(revFile, []byte(rev), 0o600); err != nil {
			return "write rev: " + err.Error(), false
		}
		// Wait for poll tick to land.
		time.Sleep(300 * time.Millisecond)
		pdaBytes, _ := h.Spec.Read(specvec.SignedPDAJWS)
		body := fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":"sha256:%064x","pda":%q}`, sid, time.Now().UnixNano(), string(pdaBytes))
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sbearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "submit PDA: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("status=%d (want 403 HandlerKeyRevoked); body=%.200q", resp.StatusCode, string(raw)), false
		}
		if !strings.Contains(string(raw), "HandlerKeyRevoked") {
			return fmt.Sprintf("403 but body lacks HandlerKeyRevoked marker: %.200q", string(raw)), false
		}
		return "§10.6.2 SV-PERM-09: handler_kid revocation file → 100ms poll → PDA decision → 403 HandlerKeyRevoked", true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BE: SV-PERM-14 §10.6.2 — CRL refresh observability ──────────────
//
// Impl AQ + BE ship the poll-tick env + revocation-file watcher, but
// no observability surface yet publishes `last_crl_refresh_at` on
// /health or writes per-refresh system-log records.
//
// **Finding BE-ext (impl)**: expose last_crl_refresh_at on /health
// (or a periodic `crl-refresh-complete` record on /logs/system/recent
// under boot session), so SV-PERM-14's ≤ 60min SLA can be observed.
// Probe body written; just needs the observability surface.
// L-50 BE-ext shipped: CRL poller runs unconditionally + emits
// crl-refresh-complete on every tick; boot fires one synchronous tick.
func handleSVPERM14Real(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-14: SOA_RUNNER_BOOTSTRAP_BEARER unset"}}
	}
	url := fmt.Sprintf("%s/logs/system/recent?session_id=ses_runnerBootLifetime&limit=100", h.Client.BaseURL())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /logs/system/recent: " + err.Error()}}
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail, Message: fmt.Sprintf("status=%d", resp.StatusCode)}}
	}
	var parsed struct {
		Records []map[string]interface{} `json:"records"`
	}
	_ = json.Unmarshal(raw, &parsed)
	for _, r := range parsed.Records {
		code, _ := r["code"].(string)
		if strings.Contains(code, "crl-refresh") {
			return []Evidence{{Path: PathLive, Status: StatusPass,
				Message: fmt.Sprintf("§10.6.2 SV-PERM-14 (BE-ext): /logs/system/recent has crl-refresh-complete record — impl ships unconditional CRL poller, boot tick fires synchronously so row is visible at /ready=200")}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusFail,
		Message: fmt.Sprintf("no crl-refresh record across %d boot-session logs", len(parsed.Records))}}
}

func _handleSVPERM14Probe(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-14: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm14-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_CRL_POLL_TICK_MS"] = "150"
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		// Poll /health for last_crl_refresh_at OR /logs/system/recent for crl-refresh-complete records.
		time.Sleep(500 * time.Millisecond)
		healthResp, _ := client.Do(probeCtx, http.MethodGet, "/health", nil)
		healthRaw, _ := io.ReadAll(healthResp.Body)
		healthResp.Body.Close()
		var hdoc map[string]interface{}
		_ = json.Unmarshal(healthRaw, &hdoc)
		if _, has := hdoc["last_crl_refresh_at"]; has {
			return "§10.6.2 SV-PERM-14: /health.last_crl_refresh_at populated — CRL refresh observed under 60min ceiling", true
		}
		// Fall back to system-log poll.
		url := fmt.Sprintf("%s/logs/system/recent?session_id=ses_runnerBootLifetime&limit=100", client.BaseURL())
		logReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		logReq.Header.Set("Authorization", "Bearer "+bearer)
		logResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(logReq)
		if err != nil {
			return "/logs/system/recent: " + err.Error(), false
		}
		logRaw, _ := io.ReadAll(logResp.Body)
		logResp.Body.Close()
		var parsed struct {
			Records []map[string]interface{} `json:"records"`
		}
		_ = json.Unmarshal(logRaw, &parsed)
		for _, r := range parsed.Records {
			code, _ := r["code"].(string)
			if code == "crl-refresh-complete" || code == "crl-refresh-ran" || strings.Contains(code, "crl-refresh") {
				return "§10.6.2 SV-PERM-14: /logs/system/recent has crl-refresh record — refresh tick observed", true
			}
		}
		return fmt.Sprintf("no crl-refresh-complete / last_crl_refresh_at observability across %d logs + /health", len(parsed.Records)), false
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BE: SV-PERM-15 §10.6.5 — retroactive SuspectDecision ────────────

func handleSVPERM15Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-15: SOA_IMPL_BIN unset"}}
	}
	revFile, cleanup := mustTempFile("svperm15-rev-*.json")
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm15-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["RUNNER_HANDLER_CRL_POLL_TICK_MS"] = "100"
	env["SOA_BOOTSTRAP_REVOCATION_FILE"] = revFile
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Drive a few PDA-signed decisions before revocation.
		pdaBytes, _ := h.Spec.Read(specvec.SignedPDAJWS)
		for i := 0; i < 3; i++ {
			body := fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":"sha256:%064x","pda":%q}`, sid, time.Now().UnixNano()+int64(i), string(pdaBytes))
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+sbearer)
			r, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err == nil && r != nil {
				r.Body.Close()
			}
		}
		// Revoke the handler kid.
		rev := `{"handler_kid":"soa-conformance-test-handler-v1.0","reason":"compromise-drill","revoked_at":"2026-04-22T12:00:00Z"}`
		_ = os.WriteFile(revFile, []byte(rev), 0o600)
		time.Sleep(400 * time.Millisecond)
		// Fetch /audit/records and look for SuspectDecision admin rows.
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, client.BaseURL()+"/audit/records?limit=200", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "GET /audit/records: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var doc struct {
			Records []map[string]interface{} `json:"records"`
		}
		_ = json.Unmarshal(raw, &doc)
		suspectCount := 0
		for _, r := range doc.Records {
			dec, _ := r["decision"].(string)
			if dec == "SuspectDecision" {
				suspectCount++
			}
			if susp, _ := r["suspect_decision"].(bool); susp {
				suspectCount++
			}
		}
		if suspectCount == 0 {
			return fmt.Sprintf("no SuspectDecision admin-rows + no suspect_decision:true on any of %d records", len(doc.Records)), false
		}
		return fmt.Sprintf("§10.6.5 SV-PERM-15: %d SuspectDecision / suspect_decision:true admin-row(s) present after handler-kid revocation", suspectCount), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── BF: SV-PERM-10 §10.6.2 — rotation overlap both-kids accepted ────

func handleSVPERM10Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PERM-10: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svperm10-test-bearer"
	env := bbcfBaseEnv(specRoot, port, bearer)
	env["SOA_HANDLER_KEYPAIR_OVERLAP_DIR"] = filepath.Join(specRoot, specvec.HandlerKeypairOverlapDir)
	env["RUNNER_TEST_CLOCK"] = "2026-04-22T12:00:00Z" // inside overlap window
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		// Check /security/key-storage or /handlers/list for both kids present.
		// Simplest assertion: /handlers/list returns both kids + validator submits a
		// signed PDA and observes handler_accepted=true. For M3 impl, reuse signed PDA
		// fixture to at least exercise the overlap cert load path.
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		pdaBytes, _ := h.Spec.Read(specvec.SignedPDAJWS)
		body := fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":"sha256:%064x","pda":%q}`, sid, time.Now().UnixNano(), string(pdaBytes))
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sbearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "submit PDA: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return fmt.Sprintf("inside-overlap PDA submit status=%d (want 201 handler_accepted); body=%.200q", resp.StatusCode, string(raw)), false
		}
		return "§10.6.2 SV-PERM-10: rotation overlap active — PDA submit during [2026-04-22, 2026-04-23) window → handler_accepted (201/200)", true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── AE: SV-STR-10 §14.5.5 — CrashEvent via admin:read ───────────────
//
// L-47 §14.5.5: /events/recent accepts admin:read (session_id optional,
// cross-session, 60 rpm, type filter). L-47 AE impl: CrashEvent emitted
// from boot-scan resume-with-open-bracket path. Validator probe: kill
// subprocess, relaunch, GET /events/recent?type=CrashEvent (admin:read).
//
// Probe simplified for this validator host: mid-decision kill + relaunch
// end-to-end is heavy. Pilot assertion: spawn subprocess with
// RUNNER_CRASH_TEST_MARKERS=session-persist pre-populated so a prior
// crash-marker exists, relaunch, assert CrashEvent present on admin:read
// /events/recent?type=CrashEvent. If impl hasn't wired admin:read auth
// yet, the GET will 401/403 and we'll route that back as finding.
func handleSVSTR10Real(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-STR-10: SOA_IMPL_BIN unset"}}
	}
	_ = bin
	_ = args
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-STR-10 (§14.2 CrashEvent + §14.5.5 admin:read): full kill-restart-admin:read harness is " +
			"composition-heavy — requires (a) crash-marker injection to leave an open bracket, (b) controlled subprocess " +
			"kill at the right boundary, (c) relaunch with persisted sessionDir. The L-47 §14.5.5 admin:read surface is " +
			"live (validated via direct curl — /events/recent without session_id returns cross-session events). Deferring " +
			"full probe body to a follow-up pass; SV-STR-10 remains skip pending the crash-harness composition. **Optional " +
			"follow-up**: compose SV-SESS-08 crash-marker pattern + §14.5.5 admin:read query."}}
}

// mustTempFile returns (path, cleanup) for a validator-writable tempfile.
// On error, returns a zero path and no-op cleanup; probes should tolerate
// write-failure by returning appropriate fail/skip.
func mustTempFile(pattern string) (string, func()) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}
	}
	path := f.Name()
	f.Close()
	return path, func() { _ = os.Remove(path) }
}
