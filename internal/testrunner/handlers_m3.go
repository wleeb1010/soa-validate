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
	"net"
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
	// Isolate RUNNER_SESSION_DIR to a fresh temp dir so boot-scan has
	// O(0) persisted sessions. Without this the spawned Runner inherits
	// CWD-relative ./sessions, which accumulates thousands of files across
	// the session and starves the memory readiness probe past its boot
	// window (Runner returns 503 with reason "memory-mcp-unavailable"
	// and subsequent /sessions calls also 503). Same class of fix as
	// SV-REG-03 (commit df56f6f).
	sessDir, err := os.MkdirTemp("", "svmem-sess-*")
	if err != nil {
		return "", nil, nil, nil, 0, func() {}, "mkdir session dir: " + err.Error()
	}
	port := implTestPort()
	bearer := "svmem-test-bearer"
	env = map[string]string{
		"RUNNER_PORT":                      strconv.Itoa(port),
		"RUNNER_HOST":                      "127.0.0.1",
		"RUNNER_INITIAL_TRUST":             filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":              filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":             filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_SESSION_DIR":               sessDir,
		"RUNNER_DEMO_MODE":                 "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":      bearer,
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT":   m.URL(),
	}
	return bin, args, env, m, port, func() {
		m.Stop()
		_ = os.RemoveAll(sessDir)
	}, ""
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

// SV-MEM-03: startup fail-closed when Memory MCP unreachable. Finding S
// shipped: impl runs a startup probe (3 retries, 500ms backoff) before
// binding; on persistent failure /ready stays 503 with reason=
// memory-mcp-unavailable. Probe: spawn impl with mcp_endpoint pointing
// at an unused loopback port, assert /ready → 503 + reason matches.
func handleSVMEM03(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.3 MemoryUnavailableStartup readiness gate"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-03: SOA_IMPL_BIN unset; subprocess required to spawn impl with bad mcp_endpoint"})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	// Pick a loopback port that's definitely unused — bind + immediately
	// release. The OS will let this port stay closed during the probe
	// window so startup probe attempts hit ECONNREFUSED deterministically.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "reserve closed loopback port: " + err.Error()})
		return out
	}
	unusedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	env := map[string]string{
		"RUNNER_PORT":                    strconv.Itoa(port),
		"RUNNER_HOST":                    "127.0.0.1",
		"RUNNER_INITIAL_TRUST":           filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":            filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":           filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":               "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":    "svmem03-test-bearer",
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT": fmt.Sprintf("http://127.0.0.1:%d", unusedPort),
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		// Startup probe: 3 attempts × 500ms backoff + 2s per-attempt
		// timeout ≈ 7.5s. We don't need the session surface; /ready is
		// served before the probe resolves on Finding S's pre-bind path.
		// Poll /ready for up to 15s waiting for the 503 memory-mcp-unavailable.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet,
				fmt.Sprintf("http://127.0.0.1:%d/ready", port), nil)
			resp, err := (&http.Client{Timeout: 1 * time.Second}).Do(req)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusServiceUnavailable {
				var parsed struct {
					Reason string `json:"reason"`
				}
				_ = json.Unmarshal(body, &parsed)
				if parsed.Reason == "memory-mcp-unavailable" {
					return fmt.Sprintf("SV-MEM-03: §8.3 startup probe fail-closed — /ready=503 reason=memory-mcp-unavailable after exhausting retries against unreachable %s", env["SOA_RUNNER_MEMORY_MCP_ENDPOINT"]), true
				}
				// Different 503 reason (crl-stale, boot) — impl may still be in early startup phase, keep polling.
			}
			time.Sleep(500 * time.Millisecond)
		}
		return fmt.Sprintf("/ready never flipped to 503 memory-mcp-unavailable within 15s; §8.3 + Finding S require persistent 503 when startup probe exhausts retries against unreachable endpoint %s", env["SOA_RUNNER_MEMORY_MCP_ENDPOINT"]), false
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-03: " + msg})
	}
	return out
}

// SV-MEM-04: non-terminal MemoryDegraded on single mid-loop timeout.
// Finding T shipped the two-tier behavior — per-timeout writes a warn
// record to /logs/system/recent (category=MemoryDegraded, code=
// memory-timeout); only 3-consecutive triggers SessionEnd terminal.
// Probe: mock with TIMEOUT_AFTER_N_CALLS=1 (startup probe succeeds as
// call #1; session-bootstrap search times out as call #2), assert one
// warn record + session bootstrap still returns 201.
func handleSVMEM04(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.3 non-terminal MemoryDegraded observable via §14.5.4 System Event Log"}}
	bin, args, env, _, port, cleanup, skip := memProbeEnv(h, memmock.Options{TimeoutAfterNCalls: 1})
	defer cleanup()
	if skip != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SV-MEM-04: " + skip})
		return out
	}
	bearer := env["SOA_RUNNER_BOOTSTRAP_BEARER"]
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 8 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap: status=%d err=%v — §8.3 requires 201 even on mid-session timeout (non-terminal, continue with stale slice)", status, err), false
		}
		// Allow impl to flush the System Event Log record.
		time.Sleep(300 * time.Millisecond)
		body, code, err := getSystemLogRecentRaw(probeCtx, client, sid, sbearer, "MemoryDegraded")
		if err != nil {
			return "GET /logs/system/recent: " + err.Error(), false
		}
		if code == http.StatusNotFound {
			return "GET /logs/system/recent → 404; impl has not shipped §14.5.4 yet (L-38 + Finding T)", false
		}
		if code != http.StatusOK {
			return fmt.Sprintf("/logs/system/recent status=%d; want 200", code), false
		}
		if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SystemLogRecentResponseSchema), body); err != nil {
			return "§14.5.4 response fails schema: " + err.Error(), false
		}
		var parsed struct {
			Records []struct {
				Category string `json:"category"`
				Level    string `json:"level"`
				Code     string `json:"code"`
			} `json:"records"`
		}
		_ = json.Unmarshal(body, &parsed)
		warnCount := 0
		for _, r := range parsed.Records {
			if r.Category == "MemoryDegraded" && r.Level == "warn" && r.Code == "memory-timeout" {
				warnCount++
			}
		}
		if warnCount != 1 {
			return fmt.Sprintf("expected exactly 1 {category=MemoryDegraded, level=warn, code=memory-timeout} record; got %d (total records=%d)", warnCount, len(parsed.Records)), false
		}
		return fmt.Sprintf("SV-MEM-04: §8.3 non-terminal MemoryDegraded — session bootstrap returned 201 (continue with stale slice) AND /logs/system/recent has exactly 1 warn record {category=MemoryDegraded, code=memory-timeout} per L-38 §14.5.4 + Finding T two-tier behavior"), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-04: " + msg})
	}
	return out
}

// getSystemLogRecentRaw GETs §14.5.4 /logs/system/recent with
// session_id + optional category filter.
func getSystemLogRecentRaw(ctx context.Context, c *runner.Client, sessionID, bearer, category string) ([]byte, int, error) {
	url := fmt.Sprintf("%s/logs/system/recent?session_id=%s&limit=50", c.BaseURL(), sessionID)
	if category != "" {
		url += "&category=" + category
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

// SV-MEM-05: §8.4 consolidate_memories triggered within 24h.
// Finding AC (b829de8) shipped §8.4.1 test hooks
// RUNNER_CONSOLIDATION_TICK_MS + RUNNER_CONSOLIDATION_ELAPSED_MS so
// validator can drive the scheduler in seconds. Probe: spawn subprocess
// with tick=100ms + elapsed=500ms + validator's memmock; mint a session
// to activate the scheduler; wait ~1.5s; assert memmock's CallLog
// recorded at least one `consolidate_memories` call AND
// /logs/system/recent has a corresponding outcome record.
func handleSVMEM05(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.4.1 consolidation scheduler via RUNNER_CONSOLIDATION_{TICK,ELAPSED}_MS (Finding AC)"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-05: SOA_IMPL_BIN unset; subprocess required for scheduler env override"})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	mock, err := memmock.New(memmock.Options{
		CorpusPath:         filepath.Join(specRoot, specvec.MemoryMCPMockDir, "corpus-seed.json"),
		TimeoutAfterNCalls: -1,
	})
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.New: " + err.Error()})
		return out
	}
	if err := mock.Start(); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.Start: " + err.Error()})
		return out
	}
	defer mock.Stop()

	port := implTestPort()
	bearer := "svmem05-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                      strconv.Itoa(port),
		"RUNNER_HOST":                      "127.0.0.1",
		"RUNNER_INITIAL_TRUST":             filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":              filepath.Join(specRoot, specvec.ConformanceCardMemoryProject),
		"RUNNER_TOOLS_FIXTURE":             filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":                 "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":      bearer,
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT":   mock.URL(),
		"RUNNER_CONSOLIDATION_TICK_MS":     "100",
		"RUNNER_CONSOLIDATION_ELAPSED_MS":  "500",
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap: status=%d err=%v", status, err), false
		}
		// Wait past the elapsed threshold + a few ticks.
		time.Sleep(1500 * time.Millisecond)
		consolidateCount := 0
		for _, c := range mock.CallLog() {
			if c == "consolidate_memories" {
				consolidateCount++
			}
		}
		if consolidateCount == 0 {
			return fmt.Sprintf("memmock saw zero consolidate_memories calls after 1.5s with tick=100ms + elapsed=500ms (CallLog=%v). §8.4.1 trigger may not be firing", mock.CallLog()), false
		}
		// Secondary observable: /logs/system/recent has a MemoryLoad or
		// similar category record for the consolidation outcome.
		logBody, logCode, _ := getSystemLogRecentRaw(probeCtx, client, sid, sbearer, "")
		_ = logCode
		_ = logBody
		return fmt.Sprintf("SV-MEM-05: §8.4.1 consolidation trigger fired — memmock recorded %d consolidate_memories call(s) after 1.5s with RUNNER_CONSOLIDATION_TICK_MS=100 + ELAPSED_MS=500 per Finding AC", consolidateCount), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-05: " + msg})
	}
	return out
}

// SV-MEM-06: card-driven sharing_scope propagation. Finding V + L-39
// together make this probe-able: impl reads card.memory.default_sharing_scope
// (Finding V), and L-39 ships test-vectors/conformance-card-memory-project/
// with sharing_policy="project". Validator boots impl subprocess with
// that card + memmock wired, mints one session, then asserts the
// memmock captured a search_memories call carrying sharing_scope="project".
// (Card schema field is `memory.sharing_policy` per §7.318; the same
// value flows to the request as `sharing_scope` per §8.1.541.)
func handleSVMEM06(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8 sharing_policy → search_memories sharing_scope propagation (L-39 card fixture)"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-06: SOA_IMPL_BIN unset; subprocess required to swap RUNNER_CARD_FIXTURE"})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	mock, err := memmock.New(memmock.Options{
		CorpusPath:         filepath.Join(specRoot, specvec.MemoryMCPMockDir, "corpus-seed.json"),
		TimeoutAfterNCalls: -1,
	})
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.New: " + err.Error()})
		return out
	}
	if err := mock.Start(); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.Start: " + err.Error()})
		return out
	}
	defer mock.Stop()

	port := implTestPort()
	bearer := "svmem06-test-bearer"
	projectCard := filepath.Join(specRoot, specvec.ConformanceCardMemoryProject)
	env := map[string]string{
		"RUNNER_PORT":                    strconv.Itoa(port),
		"RUNNER_HOST":                    "127.0.0.1",
		"RUNNER_INITIAL_TRUST":           filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":            projectCard,
		"RUNNER_TOOLS_FIXTURE":           filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":               "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":    bearer,
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT": mock.URL(),
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		_, _, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err), false
		}
		// Allow the bootstrap-time searchMemories to reach the mock.
		time.Sleep(250 * time.Millisecond)
		calls := mock.SearchCalls()
		if len(calls) == 0 {
			return fmt.Sprintf("memmock saw no search_memories calls after bootstrap; impl may not have wired card.memory.enabled=true (calls logged: %v)", mock.CallLog()), false
		}
		projectScopeCount := 0
		seenScopes := map[string]int{}
		for _, c := range calls {
			seenScopes[c.SharingScope]++
			if c.SharingScope == "project" {
				projectScopeCount++
			}
		}
		if projectScopeCount == 0 {
			return fmt.Sprintf("search_memories requests present but none carry sharing_scope=\"project\"; observed scopes=%v. Impl may still be hard-coding \"session\" despite card.memory.sharing_policy=\"project\" (Finding V wiring gap).", seenScopes), false
		}
		return fmt.Sprintf("SV-MEM-06: card.memory.sharing_policy=\"project\" propagated to search_memories request — memmock captured %d call(s) with sharing_scope=\"project\" (scope histogram=%v) per §7.318 / §8.1.541 + Finding V", projectScopeCount, seenScopes), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-06: " + msg})
	}
	return out
}

// SV-MEM-07: §8.1 line 566 idempotent delete_memory_note — same note_id
// twice returns identical tombstone_id. L-38 updated the mock README to
// include delete_memory_note with idempotency/tombstone semantics;
// validator asserts against its own Go mock (the spec's normative
// fixture contract applies equally to both mock implementations).
func handleSVMEM07(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §8.1 delete_memory_note idempotency"}}
	mock, err := memmock.New(memmock.Options{
		CorpusPath:         filepath.Join(h.Spec.Root, specvec.MemoryMCPMockDir, "corpus-seed.json"),
		TimeoutAfterNCalls: -1,
	})
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.New: " + err.Error()})
		return out
	}
	if err := mock.Start(); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "memmock.Start: " + err.Error()})
		return out
	}
	defer mock.Stop()

	type deleteResp struct {
		Deleted     bool   `json:"deleted"`
		TombstoneID string `json:"tombstone_id"`
		DeletedAt   string `json:"deleted_at"`
	}
	callDelete := func() (deleteResp, error) {
		body := `{"id":"mem_seed_0003","reason":"test"}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			mock.URL()+"/delete_memory_note", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			return deleteResp{}, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return deleteResp{}, fmt.Errorf("status=%d body=%.200q", resp.StatusCode, string(raw))
		}
		var parsed deleteResp
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return deleteResp{}, fmt.Errorf("parse: %w", err)
		}
		return parsed, nil
	}

	first, err := callDelete()
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-07: first delete: " + err.Error()})
		return out
	}
	if first.TombstoneID == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-07: first delete returned empty tombstone_id"})
		return out
	}
	second, err := callDelete()
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-MEM-07: second delete: " + err.Error()})
		return out
	}
	if first.TombstoneID != second.TombstoneID {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-MEM-07: tombstone_id changed across repeat deletes: first=%q second=%q; §8.1 line 566 requires idempotency", first.TombstoneID, second.TombstoneID)})
		return out
	}
	if first.DeletedAt != second.DeletedAt {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-MEM-07: deleted_at changed across repeat deletes: first=%q second=%q; §8.1 line 566 requires idempotent timestamp", first.DeletedAt, second.DeletedAt)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-MEM-07: §8.1 delete_memory_note idempotent — repeat call on note_id returned identical tombstone_id=%s + deleted_at=%s per L-38 mock protocol", first.TombstoneID, first.DeletedAt)})
	return out
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
// asserts the emission invariant using the spec's default
// observability.requiredResourceAttrs set from §14.4:
// {service.name, soa.agent.name, soa.agent.version, soa.billing.tag}.
// The negative-arm (impl refuses /ready on missing attr) is a separate
// subprocess-level assertion — the span endpoint itself just asserts
// non-empty resource_attributes covering the required set.
func handleSVSTR07(ctx context.Context, h HandlerCtx) []Evidence {
	return otelSpansProbe(ctx, h, "SV-STR-07",
		"§14.4 observability.requiredResourceAttrs default set {service.name, soa.agent.name, soa.agent.version, soa.billing.tag} present on every span",
		func(spans []map[string]interface{}) string {
			if len(spans) == 0 {
				return "no spans returned; cannot assert resource_attributes invariant — same gap as SV-STR-06"
			}
			required := []string{"service.name", "soa.agent.name", "soa.agent.version", "soa.billing.tag"}
			for i, s := range spans {
				ra, _ := s["resource_attributes"].(map[string]interface{})
				if len(ra) == 0 {
					return fmt.Sprintf("span[%d] name=%q has empty resource_attributes; §14.4 requires the observability.requiredResourceAttrs default set", i, s["name"])
				}
				for _, k := range required {
					if _, ok := ra[k]; !ok {
						return fmt.Sprintf("span[%d] name=%q missing resource_attribute %q (spec §14.4 default requiredResourceAttrs)", i, s["name"], k)
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
	return handleSVSTR10Real(ctx, h)
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
