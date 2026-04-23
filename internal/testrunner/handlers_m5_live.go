package testrunner

// M5 live-mode variants for §8 Memory probes.
//
// Gate 3 mem0 spike (L-56) surfaced that SV-MEM-01/02/07/08 + HR-17 were
// wired subprocess-only: they spawn an impl via SOA_IMPL_BIN with an
// in-process memmock sidecar. When the spike runs against an already-
// started Runner (SOA_IMPL_URL + SOA_RUNNER_BOOTSTRAP_BEARER) the
// subprocess path is unavailable and every probe skips, so no backend
// under test actually sees the probe.
//
// The helpers here provide weaker — but backend-agnostic — live-mode
// fallbacks. Assertion strategy:
//
//   SV-MEM-01  bootstrap session, GET /memory/state, require
//              in_context_notes non-empty (proves the Runner consumed
//              its configured Memory MCP).
//   SV-MEM-02  two bootstraps against the same Runner, compare the
//              note_id sequence returned by /memory/state. §8.2 requires
//              identical ordering for identical user_sub.
//   SV-MEM-08  if SOA_MEMORY_MCP_ENDPOINT is set, drive the backend
//              directly (same pattern SV-MEM-07 uses against memmock):
//              add_memory_note → delete_memory_note → tombstone shape.
//
// HR-17 is registered here with a precise skip diagnostic. A full probe
// needs either a subprocess spawn or §8.7.7 backend fault-injection.
// The paste block from impl session (2026-04-23) confirms §8.7.7 lands
// after Phase 2/3 reveal the env-hook shape. Until then the subprocess
// path is the only way to drive 3 consecutive memory failures, so HR-17
// skips with a structured reason naming the blocker.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// liveRunnerSVMEM01 attempts the running-Runner variant. Returns
// (evidence, tried) — tried=true means the probe executed and evidence
// is authoritative; tried=false means preconditions weren't met and the
// caller should emit its own skip.
func liveRunnerSVMEM01(ctx context.Context, h HandlerCtx) (Evidence, bool) {
	if !h.Live {
		return Evidence{}, false
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		return Evidence{}, false
	}
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("SV-MEM-01 (live-runner): bootstrap status=%d err=%v", status, err)}, true
	}
	body, code, err := getMemoryStateRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError,
			Message: "SV-MEM-01 (live-runner): GET /memory/state: " + err.Error()}, true
	}
	if code == http.StatusNotFound {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-01 (live-runner): /memory/state → 404; Runner has not shipped §8.3.2 yet"}, true
	}
	if code != http.StatusOK {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-MEM-01 (live-runner): /memory/state status=%d; want 200", code)}, true
	}
	var state struct {
		InContextNotes []map[string]interface{} `json:"in_context_notes"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-01 (live-runner): parse /memory/state: " + err.Error()}, true
	}
	if len(state.InContextNotes) == 0 {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-01 (live-runner): /memory/state.in_context_notes empty — Runner did not consume configured Memory MCP at bootstrap"}, true
	}
	return Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-MEM-01 (live-runner): §8.1 Memory MCP consumed by Runner at SOA_IMPL_URL — /memory/state.in_context_notes=%d after bootstrap (backend opaque; assertion is shape + non-emptiness)", len(state.InContextNotes))}, true
}

// liveRunnerSVMEM02 drives two bootstraps and compares note_id ordering.
func liveRunnerSVMEM02(ctx context.Context, h HandlerCtx) (Evidence, bool) {
	if !h.Live {
		return Evidence{}, false
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		return Evidence{}, false
	}
	seq1, err := liveLoadNoteIDs(ctx, h, bootstrapBearer)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-02 (live-runner): load 1: " + err.Error()}, true
	}
	seq2, err := liveLoadNoteIDs(ctx, h, bootstrapBearer)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-02 (live-runner): load 2: " + err.Error()}, true
	}
	if len(seq1) == 0 {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-02 (live-runner): /memory/state.in_context_notes empty on both reads; can't assert §8.2 determinism without seed corpus"}, true
	}
	if !sliceEqual(seq1, seq2) {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-MEM-02 (live-runner): non-deterministic ordering across two reads — seq1=%v seq2=%v", seq1, seq2)}, true
	}
	return Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-MEM-02 (live-runner): §8.2 deterministic slice — two reads against Runner returned identical note_id ordering (%d notes): %v", len(seq1), seq1)}, true
}

// liveLoadNoteIDs bootstraps a session (via shared cache) and returns
// the note_id ordering from /memory/state.in_context_notes. Same shape
// as loadAndReadNoteIDs but uses the already-running Runner (h.Client)
// + sharedBootstrap rather than a fresh subprocess session.
func liveLoadNoteIDs(ctx context.Context, h HandlerCtx, bootstrapBearer string) ([]string, error) {
	sid, bearer, status, err := sharedBootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		return nil, fmt.Errorf("bootstrap status=%d err=%v", status, err)
	}
	body, code, err := getMemoryStateRaw(ctx, h.Client, sid, bearer)
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

// liveBackendSVMEM08 drives SOA_MEMORY_MCP_ENDPOINT directly when set.
// Same pattern SV-MEM-07 uses against its own memmock — but pointed at
// the backend the Runner is configured with, so the test actually
// exercises the backend under test rather than a validator-owned mock.
//
// Flow: add_memory_note (seed) → delete_memory_note → verify tombstone
// shape {tombstone_id, deleted_at, note_id}. §8.1 tombstone contract.
func liveBackendSVMEM08(ctx context.Context, h HandlerCtx) (Evidence, bool) {
	endpoint := strings.TrimRight(os.Getenv("SOA_MEMORY_MCP_ENDPOINT"), "/")
	if endpoint == "" {
		return Evidence{}, false
	}
	noteID, err := backendAddNote(ctx, endpoint)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-MEM-08 (live-backend): add_memory_note: " + err.Error()}, true
	}
	tombstone, err := backendDeleteNote(ctx, endpoint, noteID)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-08 (live-backend): delete_memory_note: " + err.Error()}, true
	}
	if tombstone.TombstoneID == "" {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-08 (live-backend): delete_memory_note response missing tombstone_id"}, true
	}
	if tombstone.DeletedAt == "" {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-MEM-08 (live-backend): delete_memory_note response missing deleted_at"}, true
	}
	if tombstone.NoteID != "" && tombstone.NoteID != noteID {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-MEM-08 (live-backend): tombstone.note_id=%q does not echo request note_id=%q", tombstone.NoteID, noteID)}, true
	}
	return Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-MEM-08 (live-backend): §8.1 delete_memory_note at SOA_MEMORY_MCP_ENDPOINT returned tombstone {tombstone_id=%s, deleted_at=%s} for seeded note_id=%s", tombstone.TombstoneID, tombstone.DeletedAt, noteID)}, true
}

type backendTombstone struct {
	TombstoneID string `json:"tombstone_id"`
	DeletedAt   string `json:"deleted_at"`
	NoteID      string `json:"note_id"`
}

func backendAddNote(ctx context.Context, endpoint string) (string, error) {
	body := `{"note":{"content":"sv-mem-08 seed","tags":["sv-mem-08"],"importance":0.3}}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/add_memory_note", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, truncate(string(raw), 160))
	}
	var parsed struct {
		NoteID string `json:"note_id"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if parsed.NoteID == "" {
		return "", fmt.Errorf("backend returned empty note_id")
	}
	return parsed.NoteID, nil
}

func backendDeleteNote(ctx context.Context, endpoint, noteID string) (backendTombstone, error) {
	body := fmt.Sprintf(`{"note_id":%q}`, noteID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/delete_memory_note", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return backendTombstone{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return backendTombstone{}, fmt.Errorf("status=%d body=%s", resp.StatusCode, truncate(string(raw), 160))
	}
	var parsed backendTombstone
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return backendTombstone{}, fmt.Errorf("parse: %w", err)
	}
	return parsed, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// handleHR17 skips with a precise diagnostic. §8.3.1 three-consecutive-
// failure MemoryDegraded termination requires either (a) a subprocess
// spawn with memmock SOA_MEMORY_MCP_MOCK_TIMEOUT_AFTER_N_CALLS=0 or
// (b) backend fault-injection hooks per §8.7.7 (deferred until Phase
// 2/3 reveal the env-hook shape per 2026-04-23 impl-session Plan).
//
// Wiring this as a registered skip — rather than leaving it as an
// implicit "no handler → default behavior" — so the emitted JUnit
// report names HR-17 explicitly and the blocker is machine-parseable.
func handleHR17(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip,
			Message: "live-only — §8.3.1 SessionEnd{stop_reason:MemoryDegraded} after 3 consecutive memory failures"},
		{Path: PathLive, Status: StatusSkip,
			Message: "HR-17: requires subprocess spawn (SOA_IMPL_BIN + memmock SOA_MEMORY_MCP_MOCK_TIMEOUT_AFTER_N_CALLS=0) OR §8.7.7 backend fault-injection surface; §8.7.7 deferred per 2026-04-23 impl-session Plan until Phase 2/3 reveals env-hook shape. Registered handler so JUnit output names HR-17 explicitly; flips when either driver lands."},
	}
}
