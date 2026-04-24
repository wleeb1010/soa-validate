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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

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

func handleSVA2A14Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-14: §17.2.5 per-method digest recompute matrix. Live probe requires an offer→transfer flow with deliberately-tampered messages/workflow; unit coverage at packages/runner/test/a2a-digest-check.test.ts (16 assertions covering the full matrix + JCS canonicalization invariance).",
	}}
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
