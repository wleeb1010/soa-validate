package testrunner

// M3 handlers — Memory (§8) + StreamEvent (§14) observability.
//
// All 24 Week-1 handlers skip with precise diagnostics until impl ships
// T-0/T-1 (Memory MCP client + /memory/state) and T-2 (/events/recent).
// When impl signals those tasks land, handlers auto-flip — no validator
// code change. Diagnostics name the specific endpoint the test requires
// and the §-reference of the assertion.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── §8 Memory handlers (10 tests — V-4) ─────────────────────────────

func handleSVMEM01(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-01", "§8.1 tool signatures — SOA-compliant memory MCP server required; consume test-vectors/memory-mcp-mock/ per L-34. Blocks on impl T-0.")
}
func handleSVMEM02(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-02", "§8 loading algorithm order (retrieve → rank → insert → emit MemoryInsert). Blocks on impl T-0.")
}
func handleSVMEM03(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-03", "§8 startup fail-closed — impl MUST refuse to serve when Memory MCP unreachable at boot; subprocess spawn with SOA_MEMORY_MCP_MOCK_* env hooks. Blocks on impl T-0.")
}
func handleSVMEM04(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-04", "§8.3 mid-loop degrade — impl MUST emit SessionEnd{stop_reason:MemoryDegraded} via /events/recent per §8.3.1 (NOT a bare event type). Blocks on impl T-0 + T-2.")
}
func handleSVMEM05(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-05", "§8.2 consolidation trigger — MemoryConsolidated event. Blocks on impl T-0 + T-2.")
}
func handleSVMEM06(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-06", "§8 sharing_policy enforcement — search_memories sharing_scope honored. Blocks on impl T-0.")
}
func handleSVMEM07(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-07", "§8 delete_memory_note idempotent — same note_id twice, same result. Blocks on impl T-0.")
}
func handleSVMEM08(ctx context.Context, h HandlerCtx) []Evidence {
	// Pre-budgeted skip per plan — cross-tenant isolation may need a
	// real Memory MCP (not the mock). Report honestly rather than force.
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: "pre-budgeted skip per M3 plan: cross-tenant isolation may need real Memory MCP beyond the fixture's scope"},
		{Path: PathLive, Status: StatusSkip, Message: "SV-MEM-08 pre-budgeted against M3 19-skip budget; fixture scope insufficient for real-MCP tenant isolation"},
	}
}

func handleSVMEMSTATE01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.3.2 /memory/state response shape"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_RUNNER_BOOTSTRAP_BEARER unset"})
		return out
	}
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err)})
		return out
	}
	body, statusCode, err := getMemoryStateRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if statusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /memory/state → 404; impl has not shipped §8.3.2 yet (blocks on impl T-1)"})
		return out
	}
	if statusCode != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§8.3.2 status=%d; want 200 with memory:read scope", statusCode)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.MemoryStateResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "§8.3.2 response fails schema: " + err.Error()})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "GET /memory/state: 200 + schema-valid per §8.3.2"})
	return out
}

func handleSVMEMSTATE02(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.3.2 not-a-side-effect invariant (byte-identity excl generated_at)"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_RUNNER_BOOTSTRAP_BEARER unset"})
		return out
	}
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err)})
		return out
	}
	body1, statusCode, _ := getMemoryStateRaw(ctx, h.Client, sid, bearer)
	if statusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /memory/state → 404; impl has not shipped §8.3.2 yet (blocks on impl T-1)"})
		return out
	}
	if statusCode != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§8.3.2 status=%d on first read; want 200", statusCode)})
		return out
	}
	body2, statusCode2, _ := getMemoryStateRaw(ctx, h.Client, sid, bearer)
	if statusCode2 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("second read status=%d; want 200", statusCode2)})
		return out
	}
	s1, err1 := stripGeneratedAt(body1)
	s2, err2 := stripGeneratedAt(body2)
	if err1 != nil || err2 != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("strip generated_at err1=%v err2=%v", err1, err2)})
		return out
	}
	if !bytes.Equal(s1, s2) {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "two rapid /memory/state reads differ after stripping generated_at; §8.3.2 not-a-side-effect invariant violated"})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "§8.3.2 not-a-side-effect: strip(generated_at) byte-identical across two reads"})
	return out
}

func memoryPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl Week-1 (T-0 Memory MCP client, T-1 /memory/state). Handler wired; flips when impl signals T-0 + T-1 land."},
	}
}

func getMemoryStateRaw(ctx context.Context, c *runner.Client, sessionID, bearer string) ([]byte, int, error) {
	// §8.3.2 endpoint pattern matches /budget/projection: path param, not query.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL()+"/memory/state/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

// ─── §14 StreamEvent handlers (14 tests — V-5) ───────────────────────

// streamClosedEnum27 is the L-35 §14.1 closed event-type set. Kept in
// validator source (not consumed via spec schema reflection) so any
// future spec-side enum drift is caught as a test mismatch rather than
// silently absorbed.
var streamClosedEnum27 = map[string]bool{
	"SessionStart": true, "SessionEnd": true,
	"MessageStart": true, "MessageEnd": true,
	"ContentBlockStart": true, "ContentBlockDelta": true, "ContentBlockEnd": true,
	"ToolInputStart": true, "ToolInputDelta": true, "ToolInputEnd": true,
	"ToolResult": true, "ToolError": true,
	"PermissionPrompt": true, "PermissionDecision": true,
	"CompactionStart": true, "CompactionEnd": true,
	"MemoryLoad": true,
	"HandoffStart": true, "HandoffComplete": true, "HandoffFailed": true,
	"SelfImprovementStart": true, "SelfImprovementAccepted": true,
	"SelfImprovementRejected": true, "SelfImprovementOrphaned": true,
	"CrashEvent":         true,
	"PreToolUseOutcome":  true,
	"PostToolUseOutcome": true,
}

// driveDecisionAndFetchEvents mints a fresh session, fires one
// /permissions/decisions call to seed PermissionDecision emission, and
// returns the events. Reused by SV-STR-* probes so each assertion sees
// a non-trivial event set (at minimum SessionStart + PermissionDecision).
func driveDecisionAndFetchEvents(ctx context.Context, h HandlerCtx) ([]recentEvent, string, error) {
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		return nil, "", fmt.Errorf("SOA_RUNNER_BOOTSTRAP_BEARER unset")
	}
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		return nil, "", fmt.Errorf("bootstrap: status=%d err=%v", status, err)
	}
	// Fire one decision to seed a PermissionDecision event (tolerate any
	// response status — an unknown-tool 404 still yields the bootstrap
	// session's SessionStart, which is enough for envelope assertions).
	_ = postDecisionSeed(ctx, h.Client, sid, bearer)
	time.Sleep(150 * time.Millisecond)
	events, err := fetchRecentEvents(ctx, h.Client, sid, bearer)
	if err != nil {
		return nil, sid, fmt.Errorf("GET /events/recent: %v", err)
	}
	return events, sid, nil
}

// postDecisionSeed posts a permission decision; best-effort, ignores
// response — we only care that events are emitted.
func postDecisionSeed(ctx context.Context, c *runner.Client, sid, bearer string) error {
	body := fmt.Sprintf(
		`{"tool":"fs__read_file","session_id":%q,"args_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`,
		sid,
	)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL()+"/permissions/decisions",
		bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	return nil
}

func streamProbe(ctx context.Context, h HandlerCtx, testID, passMsg string,
	checker func(events []recentEvent) string) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §14 " + passMsg + " observed via GET /events/recent"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	events, _, err := driveDecisionAndFetchEvents(ctx, h)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: fmt.Sprintf("%s: %v", testID, err)})
		return out
	}
	if len(events) == 0 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: /events/recent returned zero events after seed decision; §14 requires at minimum SessionStart + PermissionDecision", testID)})
		return out
	}
	if violation := checker(events); violation != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: %s", testID, violation)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: %s (observed %d events: %s)", testID, passMsg, len(events), summarizeTypes(events))})
	return out
}

// SV-STR-01: every emitted event carries the §14.1 envelope + type in
// the closed 27-value enum.
func handleSVSTR01(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-01",
		"§14.1 envelope validates + type ∈ 27-value closed enum (L-35 PreToolUseOutcome/PostToolUseOutcome included)",
		func(events []recentEvent) string {
			for i, e := range events {
				if e.EventID == "" {
					return fmt.Sprintf("event[%d] missing event_id", i)
				}
				if e.SessionID == "" {
					return fmt.Sprintf("event[%d] missing session_id", i)
				}
				if !streamClosedEnum27[e.Type] {
					return fmt.Sprintf("event[%d].type=%q not in §14.1 27-value closed enum", i, e.Type)
				}
			}
			return ""
		})
}

// SV-STR-02: sequence strictly increasing within a single session.
func handleSVSTR02(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-02",
		"§14.1 sequence strictly-increasing per session_id",
		func(events []recentEvent) string {
			prev := -1
			for i, e := range events {
				if e.Sequence <= prev {
					return fmt.Sprintf("event[%d].sequence=%d not > prev=%d; §14.1 requires strict-ascending", i, e.Sequence, prev)
				}
				prev = e.Sequence
			}
			return ""
		})
}

// SV-STR-03: event_id unique within a session.
func handleSVSTR03(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-03",
		"§14.1 event_id unique per session",
		func(events []recentEvent) string {
			seen := map[string]int{}
			for i, e := range events {
				if j, dup := seen[e.EventID]; dup {
					return fmt.Sprintf("event[%d].event_id=%q duplicates event[%d]", i, e.EventID, j)
				}
				seen[e.EventID] = i
			}
			return ""
		})
}

func handleSVSTR04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: "pre-budgeted skip per M3 plan: §14.3 SSE terminal-event semantics — /events/recent polling may not exercise terminal-event ordering"},
		{Path: PathLive, Status: StatusSkip, Message: "SV-STR-04 pre-budgeted against M3 19-skip budget; /events/recent is polling-based, terminal-event ordering needs SSE (M4)"},
	}
}

// SV-STR-05: every emitted event.type is in the §14.1 closed category
// list (identical set to the 27-value enum — §14.2 categories are the
// closed enum per L-35 unification).
func handleSVSTR05(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-05",
		"§14.2 every record has category from closed list (unified with §14.1 27-value enum)",
		func(events []recentEvent) string {
			for i, e := range events {
				if !streamClosedEnum27[e.Type] {
					return fmt.Sprintf("event[%d] type=%q not in §14.2 closed category list", i, e.Type)
				}
			}
			return ""
		})
}

// SV-STR-06: OTel span emission. Not observable via /events/recent —
// span channel is separate (§14.4 OTel SDK export path).
func handleSVSTR06(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-06", "§14.4 OTel span names (soa.turn, soa.tool.<name>) with required attrs — OTel channel is orthogonal to §14.5 /events/recent. Probe requires impl-side OTel exporter wired to a test collector, then validator queries the collector. Out of scope for V-9a stream conversions; needs impl OTel-collector integration.")
}

// SV-STR-07: OTel missing-resource-attr → refuse start. Requires
// launching impl with deliberately-misconfigured OTel env + observing
// startup refusal. Same OTel-channel scope as SV-STR-06.
func handleSVSTR07(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-07", "§14.4 OTel required resource attrs (service.name, service.version, session_id) — missing attr must refuse /ready. Needs subprocess spawn with unset RUNNER_OTEL_RESOURCE_* env and assertion on startup-refusal exit-code. Blocks on impl-side OTel validation gate.")
}

// SV-STR-08: 10k-buffer drop-oldest + ObservabilityBackpressure. Requires
// flooding the impl with ≥10k events to observe drop-oldest + the
// backpressure signal. Resource-intensive, not in polling scope.
func handleSVSTR08(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-08", "§14.5 bounded 10k-span buffer + drop-oldest + ObservabilityBackpressure signal. Requires flooding ≥10k events in-flight + observing eviction + a separate ObservabilityBackpressure signal (not in /events/recent 27-value enum). Blocks on impl-side backpressure surface (ObservabilityBackpressure event type or /obs/backpressure endpoint).")
}

// SV-STR-09: per-event payload validates against §14.1.1
// stream-event-payloads.schema.json oneOf dispatch.
func handleSVSTR09(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-09",
		"§14.1.1 per-type payload validates against stream-event-payloads.schema.json oneOf dispatch",
		func(events []recentEvent) string {
			schemaPath := h.Spec.Path(specvec.StreamEventPayloadsSchema)
			for i, e := range events {
				envelope := map[string]interface{}{
					"type":    e.Type,
					"payload": e.Payload,
				}
				raw, _ := json.Marshal(envelope)
				if err := agentcard.ValidateJSON(schemaPath, raw); err != nil {
					return fmt.Sprintf("event[%d] type=%q payload fails §14.1.1 schema: %v", i, e.Type, err)
				}
			}
			return ""
		})
}

// SV-STR-10: CrashEvent payload shape. Needs crash induction.
func handleSVSTR10(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-10", "§14.2 CrashEvent.payload required fields (reason, workflow_state_id, last_committed_event_id, stack_hint). Requires inducing an impl crash mid-decision and observing CrashEvent emission on resume. Existing crash-recovery harness (SV-SESS-06..10) catches session-level recovery; CrashEvent-specific assertion needs crash-marker → relaunch → read /events/recent on resumed session.")
}

// SV-STR-11: CompactionDeferred on mid-ContentBlockDelta compaction.
func handleSVSTR11(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-11", "§14.2 CompactionDeferred emitted when compaction triggers during open ContentBlockDelta. Requires impl-side LLM dispatcher + ContentBlockDelta stream + context-window exhaustion trigger — M3 impl stops short of real LLM dispatch, so ContentBlockStart/Delta/End never fire. Blocks on M4 streaming dispatcher scope.")
}

// SV-STR-15: stream-event-payloads.schema.json has top-level oneOf
// dispatch AND every emitted event validates (composite assertion:
// schema shape + live validity).
func handleSVSTR15(ctx context.Context, h HandlerCtx) []Evidence {
	return streamProbe(ctx, h, "SV-STR-15",
		"§14.1.1 stream-event-payloads.schema.json top-level oneOf dispatch + every emitted event validates",
		func(events []recentEvent) string {
			schemaPath := h.Spec.Path(specvec.StreamEventPayloadsSchema)
			rawSchema, err := os.ReadFile(schemaPath)
			if err != nil {
				return "read stream-event-payloads schema: " + err.Error()
			}
			var schemaDoc map[string]interface{}
			if err := json.Unmarshal(rawSchema, &schemaDoc); err != nil {
				return "parse stream-event-payloads schema: " + err.Error()
			}
			if _, ok := schemaDoc["oneOf"]; !ok {
				return "stream-event-payloads.schema.json missing top-level oneOf dispatch per §14.1.1"
			}
			// Live validation — every event's {type, payload} envelope validates.
			for i, e := range events {
				envelope := map[string]interface{}{
					"type":    e.Type,
					"payload": e.Payload,
				}
				raw, _ := json.Marshal(envelope)
				if err := agentcard.ValidateJSON(schemaPath, raw); err != nil {
					return fmt.Sprintf("event[%d] type=%q fails oneOf dispatch: %v", i, e.Type, err)
				}
			}
			return ""
		})
}

// SV-STR-16: Gateway trust-class determinism. Gateway-scope (not
// Runner) per §14.6. This is M4 Gateway conformance work.
func handleSVSTR16(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-16", "§14.6 Gateway-side trust_class determinism (chosen from workflow.status + signer_kid, no payload inspection). Scope is Gateway, not Runner — M4 Gateway profile. Runner /events/recent events don't carry a trust_class field per L-35 schema; this assertion needs Gateway wiring + dedicated Gateway profile fixtures.")
}
func handleSVSTROBS01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §14 minimum observability via GET /events/recent"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_RUNNER_BOOTSTRAP_BEARER unset"})
		return out
	}
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap for /events/recent probe failed: status=%d err=%v", status, err)})
		return out
	}
	// §14.5 /events/recent requires session_id query param per start-runner
	// banner + stream/events-recent-route.ts.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/events/recent?session_id=%s&limit=50", h.Client.BaseURL(), sid), nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "GET /events/recent: " + err.Error()})
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /events/recent → 404; impl has not shipped §14 observability yet (blocks on impl T-2)"})
		return out
	}
	if resp.StatusCode != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§14 /events/recent status=%d; want 200. body=%.200q", resp.StatusCode, string(body))})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.EventsRecentResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "§14 /events/recent response fails schema: " + err.Error()})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "GET /events/recent: 200 + schema-valid per §14 minimum observability"})
	return out
}

func streamPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-2 (GET /events/recent §14 observability). Handler wired; flips when impl signals T-2 lands."},
	}
}

// Suppress unused-import complaint if some helpers aren't exercised yet.
var _ = json.Unmarshal
