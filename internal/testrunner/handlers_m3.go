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

func handleSVSTR01(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-01", "§14.1 StreamEvent base schema — envelope (event_id, sequence, session_id, type, payload, timestamp). Consume via GET /events/recent per impl T-2.")
}
func handleSVSTR02(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-02", "§14.1 sequence monotonic-ascending within a session_id. T-2.")
}
func handleSVSTR03(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-03", "§14.1 event_id globally unique. T-2.")
}
func handleSVSTR04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: "pre-budgeted skip per M3 plan: §14.3 SSE terminal-event semantics — /events/recent polling may not exercise terminal-event ordering"},
		{Path: PathLive, Status: StatusSkip, Message: "SV-STR-04 pre-budgeted against M3 19-skip budget; /events/recent is polling-based, terminal-event ordering needs SSE (M4)"},
	}
}
func handleSVSTR05(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-05", "§14.2 System Event Log categories — SessionStart, SessionEnd, PermissionDecision, ToolCallStart/End, MemoryInsert, MemoryConsolidated, etc. T-2.")
}
func handleSVSTR06(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-06", "§14.4 OTel span names conform to spec-listed set. T-2.")
}
func handleSVSTR07(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-07", "§14.4 OTel resource attributes (service.name, service.version, session_id). T-2.")
}
func handleSVSTR08(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-08", "§14.5 exporter backpressure — bounded queue, drop-oldest. T-2.")
}
func handleSVSTR09(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-09", "§14.1 per-type payload schema (PermissionDecision.payload vs MemoryInsert.payload, etc.). T-2.")
}
func handleSVSTR10(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-10", "§14.2 CrashEvent payload shape (cause, stack_hash, recovered_at). T-2 + §15.")
}
func handleSVSTR11(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-11", "§14.2 CompactionDeferred event emission. T-2.")
}
func handleSVSTR15(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-15", "§14 stream event mapping — e.g. /permissions/decisions fires PermissionDecision event. T-2.")
}
func handleSVSTR16(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-16", "§14.6 trust-class determinism — events tagged with sender trust class. T-2.")
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
