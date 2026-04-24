package testrunner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// M7 week 1 (L-62) — §16.3 LLM Dispatcher handlers.
//
// SV-LLM-01 + SV-LLM-02 are VECTOR-PATH probes: they assert the
// schemas/llm-dispatch-request.schema.json and
// schemas/llm-dispatch-response.schema.json artifacts round-trip through
// the ajv-compatible validator in agentcard.ValidateJSON. Positive case
// validates; three negative cases for the request MUST each fail.
//
// SV-LLM-03..07 are LIVE-PATH probes — they exercise dispatcher lifecycle
// via a future /dispatch HTTP route on the impl. The impl side has the
// dispatcher module wired (packages/runner/src/dispatch/ on commit 2835355
// with 31 passing unit tests); HTTP surface is queued as next M7 commit.
// Until then these handlers emit a clean skip with the precise blocker
// so JUnit output names them rather than leaving a coverage hole.

// ─── SV-LLM-01: request schema validity (vector path) ─────────────────────

func handleSVLLM01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{}
	schemaPath := h.Spec.Path(specvec.LlmDispatchRequestSchema)

	// Positive case
	positive := map[string]any{
		"session_id":             "ses_" + fixedSuffix(20, 'a'),
		"turn_id":                "trn_" + fixedSuffix(20, 'b'),
		"model":                  "example-adapter-model-id",
		"messages":               []any{map[string]any{"role": "user", "content": "hello"}},
		"budget_ceiling_tokens":  10000,
		"billing_tag":            "tenant-a/env-test",
		"correlation_id":         "cor_" + fixedSuffix(20, 'c'),
		"idempotency_key":        "idem-" + fixedSuffix(20, 'd'),
		"stream":                 false,
	}
	posBytes, _ := json.Marshal(positive)
	if err := agentcard.ValidateJSON(schemaPath, posBytes); err != nil {
		out = append(out, Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("SV-LLM-01: positive case failed validation: %v", err)})
		return out
	}

	// Negative 1: missing model
	neg1 := cloneMap(positive)
	delete(neg1, "model")
	if err := negativeMustFail(schemaPath, neg1, "missing model"); err != nil {
		out = append(out, *err)
		return out
	}

	// Negative 2: invalid billing_tag (contains space, pattern forbids)
	neg2 := cloneMap(positive)
	neg2["billing_tag"] = "has illegal spaces"
	if err := negativeMustFail(schemaPath, neg2, "invalid billing_tag"); err != nil {
		out = append(out, *err)
		return out
	}

	// Negative 3: budget_ceiling_tokens <= 0
	neg3 := cloneMap(positive)
	neg3["budget_ceiling_tokens"] = 0
	if err := negativeMustFail(schemaPath, neg3, "budget_ceiling_tokens=0"); err != nil {
		out = append(out, *err)
		return out
	}

	out = append(out, Evidence{Path: PathVector, Status: StatusPass,
		Message: "SV-LLM-01: §16.3 request schema — positive round-trip + 3 negatives reject per contract"})
	return out
}

// ─── SV-LLM-02: response schema validity (vector path) ────────────────────

func handleSVLLM02(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{}
	schemaPath := h.Spec.Path(specvec.LlmDispatchResponseSchema)

	// Positive — success response with dispatcher_error_code=null
	positiveSuccess := map[string]any{
		"dispatch_id":            "dsp_" + fixedSuffix(24, 'x'),
		"session_id":             "ses_" + fixedSuffix(20, 'a'),
		"turn_id":                "trn_" + fixedSuffix(20, 'b'),
		"content_blocks":         []any{map[string]any{"type": "text", "text": "hi"}},
		"tool_calls":             []any{},
		"usage":                  map[string]any{"input_tokens": 100, "output_tokens": 50, "cached_tokens": 0},
		"stop_reason":            "NaturalStop",
		"dispatcher_error_code":  nil,
		"latency_ms":             42,
		"provider_request_id":    "test-req-1",
		"provider":               "example-adapter",
		"model_echo":             "example-model-id",
		"billing_tag":            "tenant-a/env-test",
		"correlation_id":         "cor_" + fixedSuffix(20, 'c'),
		"generated_at":           "2026-04-24T00:00:00Z",
	}
	posBytes, _ := json.Marshal(positiveSuccess)
	if err := agentcard.ValidateJSON(schemaPath, posBytes); err != nil {
		out = append(out, Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("SV-LLM-02: positive success case failed: %v", err)})
		return out
	}

	// Positive — DispatcherError response with non-null code
	positiveError := cloneMap(positiveSuccess)
	positiveError["stop_reason"] = "DispatcherError"
	positiveError["dispatcher_error_code"] = "ProviderAuthFailed"
	positiveError["content_blocks"] = []any{}
	posErrBytes, _ := json.Marshal(positiveError)
	if err := agentcard.ValidateJSON(schemaPath, posErrBytes); err != nil {
		out = append(out, Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("SV-LLM-02: positive DispatcherError case failed: %v", err)})
		return out
	}

	// Negative: stop_reason=DispatcherError with dispatcher_error_code=null violates allOf/if
	negInvariant := cloneMap(positiveSuccess)
	negInvariant["stop_reason"] = "DispatcherError"
	negInvariant["dispatcher_error_code"] = nil
	if err := negativeMustFail(schemaPath, negInvariant, "DispatcherError + null code"); err != nil {
		out = append(out, *err)
		return out
	}

	// Negative: stop_reason=NaturalStop with dispatcher_error_code non-null
	negInvariant2 := cloneMap(positiveSuccess)
	negInvariant2["dispatcher_error_code"] = "ProviderRateLimited"
	if err := negativeMustFail(schemaPath, negInvariant2, "NaturalStop + non-null code"); err != nil {
		out = append(out, *err)
		return out
	}

	out = append(out, Evidence{Path: PathVector, Status: StatusPass,
		Message: "SV-LLM-02: §16.3 response schema — positive success + positive DispatcherError + 2 negative invariant violations reject per allOf/if contract"})
	return out
}

// ─── SV-LLM-03..07: live-path probes blocked on impl /dispatch route ──────

func handleSVLLM03Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-LLM-03: impl /dispatch HTTP route not yet shipped; dispatcher module (packages/runner/src/dispatch/) lands at impl commit 2835355 with 31 unit tests including budget-pre-check-before-provider-call. Live probe blocks on HTTP surface."}}
}

func handleSVLLM04Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-LLM-04: same blocker as SV-LLM-03 — billing_tag propagation probe needs /dispatch + /dispatch/recent + /audit/tail live comparison."}}
}

func handleSVLLM05Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-LLM-05: same blocker as SV-LLM-03 — mid-stream cancellation probe needs /dispatch streaming surface."}}
}

func handleSVLLM06Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-LLM-06: same blocker as SV-LLM-03 — dispatch-audit-row-per-dispatch probe needs /dispatch + /audit/tail live correlation."}}
}

func handleSVLLM07Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-LLM-07: same blocker as SV-LLM-03 — §16.3.1 taxonomy mapping probe needs /dispatch fault-injection surface (provider 429/401/5xx/network/content-filter/ctx-length)."}}
}

// ─── helpers ──────────────────────────────────────────────────────────────

func fixedSuffix(n int, c byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func negativeMustFail(schemaPath string, body map[string]any, label string) *Evidence {
	raw, _ := json.Marshal(body)
	if err := agentcard.ValidateJSON(schemaPath, raw); err == nil {
		return &Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("negative case %q unexpectedly validated; schema is under-constrained", label)}
	}
	return nil
}
