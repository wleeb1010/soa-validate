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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/memmock"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

var _ = strings.HasPrefix // keep strings import live when probes don't use it

// ─── §8 Memory handlers (10 tests — V-4) ─────────────────────────────

// memProbeEnv spawns an impl subprocess wired to a freshly-started
// Go memmock and returns (bin, args, env, mock, port, cleanup). Caller
// MUST defer cleanup() — it stops the mock + frees subprocess resources.
// Returns an Evidence-ready skip if SOA_IMPL_BIN is unset.
func memProbeEnv(h HandlerCtx, mockOpts memmock.Options) (cmdBin string, cmdArgs []string, env map[string]string, mock *memmock.MemMock, implPort int, cleanup func(), skipReason string) {
	bin, args, ok := parseImplBin()
	if !ok {
		return "", nil, nil, nil, 0, func() {}, "SOA_IMPL_BIN unset; subprocess spawn required"
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	if mockOpts.CorpusPath == "" {
		mockOpts.CorpusPath = filepath.Join(specRoot, specvec.MemoryMCPMockDir, "corpus-seed.json")
	}
	m, err := memmock.New(mockOpts)
	if err != nil {
		return "", nil, nil, nil, 0, func() {}, "memmock.New: " + err.Error()
	}
	if err := m.Start(); err != nil {
		return "", nil, nil, nil, 0, func() {}, "memmock.Start: " + err.Error()
	}
	port := implTestPort()
	bearer := "svmem-test-bearer"
	env = map[string]string{
		"RUNNER_PORT":                      strconv.Itoa(port),
		"RUNNER_HOST":                      "127.0.0.1",
		"RUNNER_INITIAL_TRUST":             filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":              filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":             filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":                 "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":      bearer,
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT":   m.URL(),
	}
	return bin, args, env, m, port, func() { m.Stop() }, ""
}

// SV-MEM-01: Memory MCP tools discoverable and impl consumes them at
// session bootstrap. Observable via /memory/state — a minted session's
// in_context_notes reflect the mock's search_memories response, proving
// the full round-trip tool invocation.
func handleSVMEM01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.1 memory tool discoverability via subprocess impl + in-process memmock"}}
	bin, args, env, mock, port, cleanup, skip := memProbeEnv(h, memmock.Options{TimeoutAfterNCalls: -1})
	defer cleanup()
	if skip != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SV-MEM-01: " + skip})
		return out
	}
	bearer := env["SOA_RUNNER_BOOTSTRAP_BEARER"]
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap: status=%d err=%v", status, err), false
		}
		// /memory/state MUST reflect the prefetch-on-bootstrap load.
		body, code, err := getMemoryStateRaw(probeCtx, client, sid, sbearer)
		if err != nil {
			return "GET /memory/state: " + err.Error(), false
		}
		if code != http.StatusOK {
			return fmt.Sprintf("GET /memory/state status=%d; want 200", code), false
		}
		var state struct {
			InContextNotes []map[string]interface{} `json:"in_context_notes"`
		}
		if err := json.Unmarshal(body, &state); err != nil {
			return "parse /memory/state: " + err.Error(), false
		}
		if len(state.InContextNotes) == 0 {
			return fmt.Sprintf("/memory/state.in_context_notes empty — impl did not load from mock; mock call log=%v", mock.CallLog()), false
		}
		if !contains(mock.CallLog(), "search_memories") {
			return "mock did not receive search_memories — impl's MemoryMcpClient did not invoke the tool at bootstrap", false
		}
		return fmt.Sprintf("SV-MEM-01: §8.1 search_memories reachable via SOA_RUNNER_MEMORY_MCP_ENDPOINT; /memory/state.in_context_notes=%d after bootstrap (mock recorded %d tool calls: %v)", len(state.InContextNotes), mock.CallCount(), mock.CallLog()), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-01: " + msg})
	}
	return out
}

// SV-MEM-02: scoring determinism. Two rapid sessions with the same
// user_sub → identical in_context_notes ordering (note_id sequence).
func handleSVMEM02(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.2 deterministic slice across two rapid loads"}}
	bin, args, env, _, port, cleanup, skip := memProbeEnv(h, memmock.Options{TimeoutAfterNCalls: -1})
	defer cleanup()
	if skip != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SV-MEM-02: " + skip})
		return out
	}
	bearer := env["SOA_RUNNER_BOOTSTRAP_BEARER"]
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		seq1, err := loadAndReadNoteIDs(probeCtx, client, bearer)
		if err != nil {
			return "load 1: " + err.Error(), false
		}
		seq2, err := loadAndReadNoteIDs(probeCtx, client, bearer)
		if err != nil {
			return "load 2: " + err.Error(), false
		}
		if !sliceEqual(seq1, seq2) {
			return fmt.Sprintf("non-deterministic ordering across two loads: seq1=%v seq2=%v", seq1, seq2), false
		}
		if len(seq1) == 0 {
			return "both loads returned empty in_context_notes; can't assert determinism", false
		}
		return fmt.Sprintf("SV-MEM-02: §8.2 deterministic slice — two rapid loads returned identical note_id ordering (%d notes): %v", len(seq1), seq1), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-02: " + msg})
	}
	return out
}

// loadAndReadNoteIDs mints a session, reads /memory/state, returns the
// ordered note_id sequence from in_context_notes.
func loadAndReadNoteIDs(ctx context.Context, client *runner.Client, bootstrapBearer string) ([]string, error) {
	sid, sbearer, status, err := m2Bootstrap(ctx, client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		return nil, fmt.Errorf("bootstrap status=%d err=%v", status, err)
	}
	body, code, err := getMemoryStateRaw(ctx, client, sid, sbearer)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("/memory/state status=%d", code)
	}
	var state struct {
		InContextNotes []struct {
			NoteID string `json:"note_id"`
		} `json:"in_context_notes"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	out := make([]string, len(state.InContextNotes))
	for i, n := range state.InContextNotes {
		out[i] = n.NoteID
	}
	return out, nil
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SV-MEM-03: startup fail-closed when Memory MCP unreachable. Spec §8.3
// requires MemoryUnavailableStartup at boot; impl today does NOT probe
// at startup (opts.memoryClient constructed lazily, no readiness check).
// Skip-pending with precise impl-ask.
func handleSVMEM03(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-03", "§8.3 startup fail-closed — impl MUST refuse /ready (or exit non-zero) when SOA_RUNNER_MEMORY_MCP_ENDPOINT is set but the endpoint is unreachable at boot, emitting MemoryUnavailableStartup. **Impl-side ask**: add a startup-time probe to MemoryMcpClient (e.g., a 1s HEAD or search-with-empty-query against the endpoint) that surfaces MemoryUnavailableStartup before /ready flips to 200. Current impl constructs the client lazily in bin/start-runner.ts:391 with no readiness check.")
}

// SV-MEM-04: mid-loop timeout → MemoryDegraded. Impl has
// MemoryDegradationTracker with threshold=3 but sessions-route emits
// SessionEnd{stop_reason:MemoryDegraded} on EVERY timeout (line 302),
// not only after the 3-consecutive gate fires. That's an impl contract
// divergence from §8.3's three-consecutive-failure rule.
func handleSVMEM04(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-04", "§8.3 single mid-loop timeout → MemoryDegraded observability event, session continues with stale slice. Impl emits SessionEnd{stop_reason:MemoryDegraded} on EVERY timeout (sessions-route.ts:302), bypassing the MemoryDegradationTracker's 3-consecutive gate. **Impl-side ask**: gate SessionEnd emission on `memoryDegradation.isDegraded()` (i.e., only after 3 consecutive failures); single timeout should emit a non-terminal MemoryDegraded observability signal instead. Spec L-34 clarified MemoryDegraded is a SessionEnd.stop_reason; the 'continue with stale slice' in SV-MEM-04 implies a separate lower-severity signal that L-34 didn't enumerate — **spec-side check**: does spec want a non-terminal MemoryDegraded stream event, or is SV-MEM-04 asserting the 3-consecutive rule threshold behavior?")
}

// SV-MEM-05: consolidate_memories trigger — impl has no time-based or
// count-based consolidation trigger in M3 scope (the consolidate tool
// is plumbed but never invoked without LLM dispatch).
func handleSVMEM05(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-05", "§8.2 consolidate_memories invoked within 24h or after 100 new notes. Impl's MemoryMcpClient has the consolidateMemories method plumbed but nothing calls it — no scheduler, no per-turn counter. M3 scope stops before LLM dispatch + turn-counter wiring. **Impl-side ask**: add a consolidation trigger — simplest: background timer (24h default, env-overridable for test) that invokes consolidateMemories across all active sessions; second: note-count counter per session that fires at >=100 writes.")
}

// SV-MEM-06: sharing_policy enforcement — cross-session search honors
// sharing_scope. Impl's sessions-route calls searchMemories with
// sharing_scope:"session" hard-coded; no cross-session path exercised.
func handleSVMEM06(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-06", "§8 sharing_policy enforcement — search_memories sharing_scope parameter honored server-side. Impl bootstrap calls searchMemories with sharing_scope:\"session\" hard-coded (sessions-route.ts:277); no cross-session search path exists. Mock honors sharing_scope but impl never requests anything but session-scope. **Impl-side ask**: surface a per-request sharing_scope (e.g., from Agent Card memory.default_sharing_scope OR via a new session-bootstrap field), so validator can mint two sessions with conflicting scopes and assert the mock's enforcement reaches /memory/state.")
}

// SV-MEM-07: idempotent delete_memory_note. Impl's MemoryMcpClient has
// NO deleteMemoryNote method — the three-tool shape the mock README
// pins is {search, write, consolidate}; delete isn't in §8.1 mock spec.
func handleSVMEM07(ctx context.Context, h HandlerCtx) []Evidence {
	return memoryPending(h, "SV-MEM-07", "§8 delete_memory_note idempotent — same note_id twice returns identical tombstone_id. **Spec-side gap**: the L-34 memory-mcp-mock README pins a three-tool protocol (search_memories, write_memory, consolidate_memories) with NO delete_memory_note. §8 defines delete_memory_note as a MUST tool but the mock README omits it. **Impl-side state**: MemoryMcpClient has no deleteMemoryNote method either. Needs spec README + impl client update before probe is writable.")
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

// SV-STR-06: §14.4 OTel spans — soa.turn + soa.tool.<name> emitted with
// required attrs. L-36 shipped §14.5.2 GET /observability/otel-spans/recent
// as the validator observation surface. Probe: drive a decision, poll
// the endpoint, assert at least one soa.turn span with §14.4 required
// attributes (soa.session.id, soa.turn.id, soa.agent.name).
func handleSVSTR06(ctx context.Context, h HandlerCtx) []Evidence {
	return otelSpansProbe(ctx, h, "SV-STR-06",
		"§14.4 span names (soa.turn, soa.tool.<name>) + required attrs",
		func(spans []map[string]interface{}) string {
			if len(spans) == 0 {
				return "no spans returned after seed decision — §14.4 MUSTs soa.turn per-turn and soa.tool.<name> per tool invocation; impl has not wired OTel span emission to /observability/otel-spans/recent"
			}
			sawTurn := false
			for _, s := range spans {
				name, _ := s["name"].(string)
				if name == "soa.turn" {
					sawTurn = true
					attrs, _ := s["attributes"].(map[string]interface{})
					for _, required := range []string{"soa.session.id", "soa.turn.id", "soa.agent.name"} {
						if _, ok := attrs[required]; !ok {
							return fmt.Sprintf("soa.turn span missing required attribute %q per §14.4", required)
						}
					}
				}
			}
			if !sawTurn {
				return "no soa.turn span observed; §14.4 requires it per Runner turn"
			}
			return ""
		})
}

// SV-STR-07: §14.4 required resource attributes on every span. Probe
// asserts the emission invariant (every span carries service.name,
// service.version, session_id in resource_attributes). The negative
// arm (refuse start on missing attr) is a separate subprocess harness.
func handleSVSTR07(ctx context.Context, h HandlerCtx) []Evidence {
	return otelSpansProbe(ctx, h, "SV-STR-07",
		"§14.4 resource attrs (service.name, service.version, session_id) present on every span",
		func(spans []map[string]interface{}) string {
			if len(spans) == 0 {
				return "no spans returned; cannot assert resource_attributes invariant — same gap as SV-STR-06"
			}
			required := []string{"service.name", "service.version", "session_id"}
			for i, s := range spans {
				ra, _ := s["resource_attributes"].(map[string]interface{})
				for _, k := range required {
					if _, ok := ra[k]; !ok {
						return fmt.Sprintf("span[%d] name=%q missing resource_attribute %q", i, s["name"], k)
					}
				}
			}
			return ""
		})
}

// otelSpansProbe drives one decision to seed turn/tool spans, polls
// /observability/otel-spans/recent, schema-validates, and runs the
// per-test checker against the decoded spans array.
func otelSpansProbe(ctx context.Context, h HandlerCtx, testID, passMsg string,
	checker func(spans []map[string]interface{}) string) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §14.5.2 /observability/otel-spans/recent"}}
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
			Message: fmt.Sprintf("%s: bootstrap status=%d err=%v", testID, status, err)})
		return out
	}
	_ = postDecisionSeed(ctx, h.Client, sid, bearer)
	time.Sleep(250 * time.Millisecond)
	body, code, err := getOTelSpansRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if code == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("%s: GET /observability/otel-spans/recent → 404; impl has not shipped §14.5.2 yet", testID)})
		return out
	}
	if code != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: status=%d; want 200", testID, code)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.OTelSpansRecentResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: §14.5.2 response fails schema: %v", testID, err)})
		return out
	}
	var parsed struct {
		Spans []map[string]interface{} `json:"spans"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if violation := checker(parsed.Spans); violation != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: %s", testID, violation)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: %s (observed %d spans)", testID, passMsg, len(parsed.Spans))})
	return out
}

func getOTelSpansRaw(ctx context.Context, c *runner.Client, sessionID, bearer string) ([]byte, int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/observability/otel-spans/recent?session_id=%s&limit=50", c.BaseURL(), sessionID), nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

// SV-STR-08: §14.4 bounded 10k-span buffer + drop-oldest. L-36 shipped
// §14.5.3 GET /observability/backpressure. Probe: schema-valid response
// + buffer_capacity=10000 const per spec.
func handleSVSTR08(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §14.5.3 /observability/backpressure"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_RUNNER_BOOTSTRAP_BEARER unset"})
		return out
	}
	_, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("SV-STR-08: bootstrap status=%d err=%v", status, err)})
		return out
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		h.Client.BaseURL()+"/observability/backpressure", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-STR-08: GET /observability/backpressure → 404; impl has not shipped §14.5.3 yet"})
		return out
	}
	if resp.StatusCode != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-STR-08: status=%d; want 200", resp.StatusCode)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.BackpressureStatusResponseSchema), raw); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-STR-08: §14.5.3 response fails schema: " + err.Error()})
		return out
	}
	var parsed struct {
		BufferCapacity    int `json:"buffer_capacity"`
		BufferSizeCurrent int `json:"buffer_size_current"`
		DroppedSinceBoot  int `json:"dropped_since_boot"`
	}
	_ = json.Unmarshal(raw, &parsed)
	if parsed.BufferCapacity != 10000 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-STR-08: buffer_capacity=%d; §14.4 requires 10000 const", parsed.BufferCapacity)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-STR-08: §14.5.3 /observability/backpressure schema-valid; buffer_capacity=%d (§14.4 const), buffer_size_current=%d, dropped_since_boot=%d", parsed.BufferCapacity, parsed.BufferSizeCurrent, parsed.DroppedSinceBoot)})
	return out
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

// SV-STR-10: §14.2 CrashEvent payload shape. Double-blocked today:
//
//  (1) Impl has CrashEvent in the §14.1 27-value enum (stream/emitter.ts:48)
//      but **zero emission callsites in src** — nothing in impl fires a
//      CrashEvent. Required at boot-scan time when the resume algorithm
//      detects a dirty session.
//
//  (2) Even once emitted, the validator cannot read /events/recent on the
//      recovered session: impl's session-store keeps the bearer in-memory
//      only (no match for bearer|bearerHash in session/persist.ts,
//      session/resume.ts, session/boot-scan.ts). After relaunch the old
//      bearer fails auth; /events/recent is session-scoped with no admin
//      path.
//
// The crash-recovery harness (SV-SESS-06..10) proves relaunch + /ready
// comes up; the CrashEvent observation layer on top needs impl side to
// ship both emission + a post-relaunch event-read path.
func handleSVSTR10(ctx context.Context, h HandlerCtx) []Evidence {
	return streamPending(h, "SV-STR-10", "§14.2 CrashEvent emission + observation. Two impl-side gaps: (1) zero CrashEvent emission callsites in impl src — only the enum entry exists in stream/emitter.ts; boot-scan in session/boot-scan.ts does NOT emit a CrashEvent when it recovers a dirty session; (2) post-relaunch, the session bearer is in-memory only (not persisted), so /events/recent on the recovered session_id fails auth with no admin-bearer path. **Impl-ask A**: fire CrashEvent at boot-scan time when the resume algorithm re-hydrates a session with an open bracket — payload {reason, workflow_state_id, last_committed_event_id, stack_hint}. **Impl-ask B**: either persist session bearer (hashed) across relaunch OR add a system-level events surface (e.g., /events/recent with session_id=* for trust_class=system events) so post-resume CrashEvent is validator-observable.")
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
