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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wleeb1010/soa-validate/internal/jcs"
)

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

func handleSVA2A10Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-10: JWT alg allowlist (EdDSA/ES256/RS256≥3072); live probe requires a cooperating Runner with JWT auth configured (SOA_A2A_BEARER + a JWT-capable verifier key). Unit coverage at packages/runner/test/a2a-jwt.test.ts (alg-outside-allowlist test).",
	}}
}

func handleSVA2A11Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-11: JWT signing-key discovery via Agent-Card-kid and mTLS x5t#S256. Live probe requires a full §17.1 step-2 test harness with a caller agent publishing a valid /.well-known/agent-card.jws. Unit coverage at packages/runner/test/a2a-signer-discovery.test.ts (27 assertions covering both paths).",
	}}
}

func handleSVA2A12Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-12: jti replay cache within exp+30s. Live probe requires two JWTs with identical jti crafted by a test caller; unit coverage at packages/runner/test/a2a-jwt.test.ts (replayed-jti test + signature-invalid-does-not-poison-cache test).",
	}}
}

func handleSVA2A13Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-13: agent_card_etag drift → HandoffRejected reason=card-version-drift + CardVersionDrift event. Live probe requires a caller whose card is served at a reachable URL and a post-rotation fetch flow. Unit coverage at packages/runner/test/a2a-signer-discovery.test.ts (checkAgentCardEtagDrift match/drift/unreachable tests).",
	}}
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
	workflow := map[string]any{"task_id": "t_sv_a2a_14", "status": "Handoff", "side_effects": []any{}}
	msgDigest, err := computeA2aDigest(messages)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14: JCS canonicalize messages: %v", err)}}
	}
	wfDigest, err := computeA2aDigest(workflow)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("SV-A2A-14: JCS canonicalize workflow: %v", err)}}
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
	body3, _, err := a2aRpc(ctx, a2aURL, bearer, "handoff.transfer", map[string]any{
		"task_id": neverSeen, "messages": messages, "workflow": workflow,
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

func handleSVA2A15Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-15: HandoffStatus enum closed-set + transition matrix. Live probe requires a handoff.status polling loop across the full transfer→execute→complete lifecycle. Unit coverage at packages/runner/test/a2a.test.ts (A2aTaskRegistry monotonicity tests).",
	}}
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
