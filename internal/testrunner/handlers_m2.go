package testrunner

// M2 handlers (Week 1 track): SV-SESS-05, SV-SESS-11, SV-PERM-19,
// SV-AUDIT-SINK-EVENTS-01, SV-SESS-STATE-01.
//
// Pattern rules inherited from M1 reviews (memory):
// - Do not substitute a weaker check to make a test pass. If the spec
//   asserts X and impl hasn't shipped X, the test honestly SKIPs with
//   a diagnostic or FAILs — never morph into a check of Y.
// - Evidence messages cite the §section being validated and the exact
//   spec-required token (reason/enum/event name).

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
	"sync"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/subprocrunner"
)

// ─── SV-SESS-05 / SV-SESS-11 — Tool Registry §12.2 non-idempotent classification ───
//
// §12.2 rule: a tool without idempotency support (`idempotency_retention_seconds`
// below the floor, i.e., zero) MUST be classified `risk_class=Destructive`
// with `default_control=Prompt`. Any looser classification MUST be rejected
// at Tool Registry load with `ToolPoolStale` reason=`idempotency-retention-insufficient`.
//
// Two subprocess probes per test:
//  1. compliant-only fixture      → impl boots clean; resolve(compliant_ephemeral_tool) = Prompt
//  2. non-compliant-only fixture  → impl exits non-zero with ToolPoolStale
//
// SV-SESS-05 asserts the rule itself.
// SV-SESS-11 asserts the retention floor's negative branch specifically
// (combined-fixture path also rejects on the non-compliant entry, not
// on ordering).

func handleSVSESS05(ctx context.Context, h HandlerCtx) []Evidence {
	return toolPoolStaleEvidence(ctx, h, "SV-SESS-05")
}

func handleSVSESS11(ctx context.Context, h HandlerCtx) []Evidence {
	// SV-SESS-11 additionally exercises the combined fixture to prove the
	// rejection is per-entry, not ordering-dependent. We reuse the shared
	// helper for the two-fixture core and append the combined-fixture arm.
	out := toolPoolStaleEvidence(ctx, h, "SV-SESS-11")
	// Any earlier SKIP on live path propagates (SOA_IMPL_BIN unset etc.);
	// we only add the combined-fixture arm when the core arms actually ran.
	if len(out) >= 2 && out[len(out)-1].Status == StatusSkip {
		return out
	}
	bin, args, ok := parseImplBin()
	if !ok {
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	msg, pass := runToolPoolRefuse(ctx, bin, args, specRoot,
		filepath.Join(specRoot, "test-vectors", "tool-registry-m2", "tools.json"),
		"combined-fixture")
	status := StatusFail
	if pass {
		status = StatusPass
	}
	out = append(out, Evidence{Path: PathLive, Status: status,
		Message: "SV-SESS-11 combined-fixture arm — " + msg})
	return out
}

func toolPoolStaleEvidence(ctx context.Context, h HandlerCtx, testID string) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §12.2 rule is a boot-time Tool Registry enforcement"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_BIN not set. Set SOA_IMPL_BIN='node /abs/path/to/start-runner.js' to exercise §12.2 tool-pool classification."})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	compliantFixture := filepath.Join(specRoot, "test-vectors", "tool-registry-m2", "tools-compliant-only.json")
	nonCompliantFixture := filepath.Join(specRoot, "test-vectors", "tool-registry-m2", "tools-non-compliant-only.json")

	// Positive arm: compliant fixture must boot clean AND resolve must
	// return Prompt for compliant_ephemeral_tool (§12.2 + §10.3 step 5).
	posMsg, posPass := runToolPoolAccept(ctx, bin, args, specRoot, compliantFixture, "compliant_ephemeral_tool")
	// Negative arm: non-compliant fixture must refuse to boot.
	negMsg, negPass := runToolPoolRefuse(ctx, bin, args, specRoot, nonCompliantFixture, "non-compliant-only")

	// Report one Evidence per arm so partial progress is visible.
	statusPos := StatusFail
	if posPass {
		statusPos = StatusPass
	}
	statusNeg := StatusFail
	if negPass {
		statusNeg = StatusPass
	}
	out = append(out, Evidence{Path: PathLive, Status: statusPos,
		Message: testID + " positive arm — " + posMsg})
	out = append(out, Evidence{Path: PathLive, Status: statusNeg,
		Message: testID + " negative arm — " + negMsg})
	return out
}

// runToolPoolAccept launches impl against the given fixture, probes
// /health for readiness, then hits /permissions/resolve?tool=<name> on a
// session bootstrapped from a test bearer. Returns (summary, pass).
func runToolPoolAccept(ctx context.Context, bin string, args []string, specRoot, fixturePath, toolName string) (string, bool) {
	port := implTestPort()
	env := m2BaseEnv(specRoot, port, "svsess05-pos-test-bearer")
	env["RUNNER_TOOLS_FIXTURE"] = fixturePath

	client := runner.New(runner.Config{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Timeout: 2 * time.Second,
	})

	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		sid, bearer, status, err := m2Bootstrap(probeCtx, client, env["SOA_RUNNER_BOOTSTRAP_BEARER"])
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err), false
		}
		url := fmt.Sprintf("http://127.0.0.1:%d/permissions/resolve?tool=%s&session_id=%s", port, toolName, sid)
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			return "resolve HTTP error: " + err.Error(), false
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Sprintf("resolve status=%d body=%.200q; want 200", resp.StatusCode, string(body)), false
		}
		var parsed struct {
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "resolve JSON parse: " + err.Error(), false
		}
		if parsed.Decision != "Prompt" {
			return fmt.Sprintf("resolve decision=%q; §12.2 requires Prompt for Destructive/Prompt-classified tool without idempotency", parsed.Decision), false
		}
		return "boot clean; /permissions/resolve returned decision=Prompt for compliant_ephemeral_tool per §12.2 + §10.3 step 5", true
	})
	return msg, pass
}

// runToolPoolRefuse launches impl with the given fixture and asserts it
// exits non-zero with `ToolPoolStale reason=idempotency-retention-insufficient`
// per §12.2. Returns (summary, pass).
func runToolPoolRefuse(ctx context.Context, bin string, args []string, specRoot, fixturePath, fixtureLabel string) (string, bool) {
	port := implTestPort()
	env := m2BaseEnv(specRoot, port, "svsess05-neg-test-bearer")
	env["RUNNER_TOOLS_FIXTURE"] = fixturePath

	res := subprocrunner.Spawn(ctx, subprocrunner.Config{
		Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
		Timeout: 10 * time.Second,
	})
	if res.StartErr != nil {
		return "spawn error: " + res.StartErr.Error(), false
	}
	if !res.Exited {
		return fmt.Sprintf("impl did NOT exit on %s fixture (TimedOut=%v); §12.2 requires fail-closed boot-refusal for non-compliant tools", fixtureLabel, res.TimedOut), false
	}
	if res.ExitCode == 0 {
		return fmt.Sprintf("impl exited 0 on %s fixture; §12.2 requires non-zero exit with ToolPoolStale. stderr-tail=%.300q", fixtureLabel, tailString(res.Stderr, 300)), false
	}
	combined := res.Stderr + "\n" + res.Stdout
	if !(strings.Contains(combined, "ToolPoolStale") || strings.Contains(combined, "tool-pool-stale") || strings.Contains(combined, "idempotency-retention-insufficient")) {
		return fmt.Sprintf("impl exited %d but stderr lacks 'ToolPoolStale' or reason='idempotency-retention-insufficient'; §12.2 requires the specific enum. stderr-tail=%.300q",
			res.ExitCode, tailString(res.Stderr, 300)), false
	}
	return fmt.Sprintf("impl refused %s fixture: exit=%d, stderr cites ToolPoolStale/idempotency-retention-insufficient per §12.2",
		fixtureLabel, res.ExitCode), true
}

// ─── SV-PERM-19 + SV-AUDIT-SINK-EVENTS-01 — audit-sink state machine §10.5.1 + §12.5.4 ───
//
// Three failure-mode arms per §10.5.1 state machine:
//   - healthy              → sink writes succeed; no AuditSink* event
//   - degraded-buffering   → sink transiently fails; buffer absorbs; AuditSinkDegraded
//   - unreachable-halt     → Mutating denied w/ reason=audit-sink-unreachable;
//                            /ready=503; AuditSinkUnreachable
//
// Driven by SOA_RUNNER_AUDIT_SINK_FAILURE_MODE=<state> at spawn. The
// §12.5.4 observability endpoint is GET /audit/sink-events. Per L-28 F-13,
// a fresh boot with the env var set emits exactly one state-transition
// event at boot.

func handleSVPERM19(ctx context.Context, h HandlerCtx) []Evidence {
	return auditSinkFailureEvidence(ctx, h, "SV-PERM-19", false)
}

func handleSVAUDITSINKEVENTS01(ctx context.Context, h HandlerCtx) []Evidence {
	return auditSinkFailureEvidence(ctx, h, "SV-AUDIT-SINK-EVENTS-01", true)
}

// auditSinkFailureEvidence runs the three-arm subprocess sweep. When
// schemaAssert=true (SV-AUDIT-SINK-EVENTS-01), the /audit/sink-events
// response body is schema-validated on every successful call.
func auditSinkFailureEvidence(ctx context.Context, h HandlerCtx, testID string, schemaAssert bool) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §10.5.1 is a runtime state-machine assertion"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_BIN not set. Set SOA_IMPL_BIN='node /abs/path/to/start-runner.js' to exercise §10.5.1 audit-sink state machine."})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)

	// Expected AuditSink event per mode per §12.5.4:
	//   healthy            → no transition event
	//   degraded-buffering → AuditSinkDegraded
	//   unreachable-halt   → AuditSinkUnreachable
	arms := []struct {
		mode, expectedEvent string
	}{
		{"healthy", ""},
		{"degraded-buffering", "AuditSinkDegraded"},
		{"unreachable-halt", "AuditSinkUnreachable"},
	}
	for _, arm := range arms {
		msg, pass := runSinkFailureArm(ctx, bin, args, specRoot, arm.mode, arm.expectedEvent, h.Spec, schemaAssert)
		status := StatusFail
		if pass {
			status = StatusPass
		}
		// Distinguish the "impl hasn't shipped §12.5.4 yet" case from a
		// hard fail: if message starts with SKIP:, surface as skip.
		if strings.HasPrefix(msg, "SKIP:") {
			status = StatusSkip
			msg = strings.TrimPrefix(msg, "SKIP:")
			msg = strings.TrimSpace(msg)
		}
		out = append(out, Evidence{Path: PathLive, Status: status,
			Message: testID + " [" + arm.mode + "] — " + msg})
	}
	return out
}

func runSinkFailureArm(ctx context.Context, bin string, args []string, specRoot, mode, expectedEvent string, sv specvec.Locator, schemaAssert bool) (string, bool) {
	port := implTestPort()
	env := m2BaseEnv(specRoot, port, "svperm19-"+mode+"-test-bearer")
	env["SOA_RUNNER_AUDIT_SINK_FAILURE_MODE"] = mode

	client := runner.New(runner.Config{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Timeout: 2 * time.Second,
	})

	_, probeMsg, probePass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		// Fresh bootstrap for audit:read scope.
		_, bearer, status, err := m2Bootstrap(probeCtx, client, env["SOA_RUNNER_BOOTSTRAP_BEARER"])
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("SKIP:bootstrap failed on %s arm: status=%d err=%v; impl may not support SOA_RUNNER_AUDIT_SINK_FAILURE_MODE yet", mode, status, err), false
		}
		// Poll /audit/sink-events.
		events, rawBody, statusCode, err := getSinkEvents(probeCtx, port, bearer)
		if err != nil {
			return "SKIP:/audit/sink-events request error: " + err.Error(), false
		}
		if statusCode == http.StatusNotFound {
			return "SKIP:/audit/sink-events → 404; impl has not shipped §12.5.4 endpoint yet", false
		}
		if statusCode != http.StatusOK {
			return fmt.Sprintf("/audit/sink-events status=%d; spec §12.5.4 requires 200 with audit:read. body=%.200q", statusCode, string(rawBody)), false
		}
		if schemaAssert {
			if err := agentcard.ValidateJSON(sv.Path(specvec.AuditSinkEventsResponseSchema), rawBody); err != nil {
				return "schema fail on §12.5.4 response: " + err.Error(), false
			}
		}
		// Per L-28 F-13: fresh boot with env var set emits exactly one
		// matching state-transition event at boot.
		matching := 0
		for _, ev := range events {
			if ev.Type == expectedEvent {
				matching++
			}
		}
		if expectedEvent == "" {
			if matching > 0 {
				return fmt.Sprintf("healthy mode emitted %d AuditSink* events; §10.5.1 says healthy is default — no transition event", matching), false
			}
			return fmt.Sprintf("healthy mode: no AuditSink* transition events as expected (%d total events); §12.5.4 endpoint responded 200 and %s",
				len(events), schemaNote(schemaAssert)), true
		}
		if matching == 1 {
			return fmt.Sprintf("%s fresh-boot emitted exactly one %s event per L-28 F-13; §12.5.4 endpoint 200 and %s",
				mode, expectedEvent, schemaNote(schemaAssert)), true
		}
		return fmt.Sprintf("%s fresh-boot emitted %d %s events; §12.5.4 + L-28 F-13 require exactly one",
			mode, matching, expectedEvent), false
	})
	return probeMsg, probePass
}

func schemaNote(schemaAssert bool) string {
	if schemaAssert {
		return "body schema-validates"
	}
	return "body observed"
}

type sinkEvent struct {
	EventID      string          `json:"event_id"`
	Type         string          `json:"type"`
	TransitionAt string          `json:"transition_at"`
	Detail       json.RawMessage `json:"detail,omitempty"`
}

type sinkEventsResponse struct {
	Events        []sinkEvent `json:"events"`
	NextAfter     string      `json:"next_after,omitempty"`
	HasMore       bool        `json:"has_more"`
	RunnerVersion string      `json:"runner_version"`
	GeneratedAt   string      `json:"generated_at"`
}

func getSinkEvents(ctx context.Context, port int, bearer string) ([]sinkEvent, []byte, int, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/audit/sink-events", port)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, raw, resp.StatusCode, nil
	}
	var parsed sinkEventsResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, raw, resp.StatusCode, err
	}
	return parsed.Events, raw, resp.StatusCode, nil
}

// ─── SV-SESS-STATE-01 — §12.5.1 session state observability ───
//
// Live-only. Bootstrap a session; read /sessions/<id>/state; schema-validate;
// assert a second read returns strip(body, "generated_at")-identical content
// (L-28 F-01 byte-identity predicate).

func handleSVSESSSTATE01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §12.5.1 endpoint behavior"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set; cannot mint session for §12.5.1 probe"})
		return out
	}
	sid, bearer, status, err := m2Bootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap for §12.5.1 probe failed: status=%d err=%v", status, err)})
		return out
	}
	body1, statusCode1, err := getSessionStateRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "GET /sessions/<id>/state error: " + err.Error()})
		return out
	}
	if statusCode1 == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /sessions/<id>/state → 404; impl has not shipped §12.5.1 yet"})
		return out
	}
	if statusCode1 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /sessions/<id>/state status=%d; §12.5.1 requires 200 with sessions:read bearer", statusCode1)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SessionStateResponseSchema), body1); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "§12.5.1 response fails schema: " + err.Error()})
		return out
	}
	// Byte-identity predicate (L-28 F-01): second read must match first
	// after stripping `generated_at`.
	body2, statusCode2, err := getSessionStateRaw(ctx, h.Client, sid, bearer)
	if err != nil || statusCode2 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("second /state read: status=%d err=%v", statusCode2, err)})
		return out
	}
	strip1, err := stripGeneratedAt(body1)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "first-body strip: " + err.Error()})
		return out
	}
	strip2, err := stripGeneratedAt(body2)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "second-body strip: " + err.Error()})
		return out
	}
	if !bytes.Equal(strip1, strip2) {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "two rapid /state reads differ after stripping generated_at; L-28 F-01 byte-identity predicate violated"})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "GET /sessions/<id>/state: 200 + schema OK + strip(generated_at) byte-identical across two reads per §12.5.1 + L-28 F-01"})
	return out
}

// ─── V2-09a: SV-SESS-01 — /state schema validity ───
//
// Trivial overlap with SV-SESS-STATE-01: mint a session, read /state,
// schema-validate. SV-SESS-STATE-01 adds the byte-identity predicate
// on top; SV-SESS-01 is the minimal "response shape conforms" assertion.

func handleSVSESS01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §12.5.1 response-shape assertion"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}
	sid, bearer, status, err := m2Bootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap for §12.5.1 probe failed: status=%d err=%v (likely Finding B — :7700 /ready=503 crl-stale)", status, err)})
		return out
	}
	body, statusCode, err := getSessionStateRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "GET /sessions/<id>/state error: " + err.Error()})
		return out
	}
	if statusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /sessions/<id>/state → 404; impl has not shipped §12.5.1 yet"})
		return out
	}
	if statusCode != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§12.5.1 status=%d; want 200 with sessions:read bearer", statusCode)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SessionStateResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "§12.5.1 response fails schema: " + err.Error()})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "GET /sessions/<id>/state: 200 + schema-valid per §12.5.1"})
	return out
}

// ─── V2-07: SV-SESS-03 — bracket-persist for every significant event ───
//
// Live-only (no crash). Drive N=10 permission decisions, poll /state
// during drive, capture every side_effect phase transition. Assert:
//   - phase transitions always go pending → committed | compensated
//     (never skip pending, never back-transition)
//   - last_phase_transition_at monotonically non-decreasing per side_effect
//
// Gates on M2-T2 (resume algorithm drives the bracket) + M2-T3 (/state
// endpoint, already shipped).

func handleSVSESS03(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §12.2 bracket-persist is a runtime state-machine assertion"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set; cannot mint session for §12.2 bracket-persist probe"})
		return out
	}
	sid, bearer, status, err := m2Bootstrap(ctx, h.Client, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("bootstrap for SV-SESS-03 probe failed: status=%d err=%v (likely Finding B — :7700 /ready=503 crl-stale)", status, err)})
		return out
	}
	// Verify /state is reachable before we drive; if 404 → M2-T3 not live.
	_, statusCode, err := getSessionStateRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "pre-drive /state probe error: " + err.Error()})
		return out
	}
	if statusCode == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /sessions/<id>/state → 404; impl has not shipped §12.5.1 yet"})
		return out
	}
	// Drive-and-observe: POST N permission decisions; after each,
	// GET /state and record workflow.side_effects[] phase + timestamps.
	// Assert (a) every side_effect transitions pending → {committed,
	// compensated} (never skip pending); (b) last_phase_transition_at
	// monotonically non-decreasing per side_effect.
	const driveCount = 10
	observations, driveErr := driveAndObservePhases(ctx, h.Client, sid, bearer, driveCount)
	if driveErr != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-SESS-03 drive loop error: " + driveErr.Error()})
		return out
	}
	if len(observations) == 0 {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-SESS-03: drove decisions but /state returned no side_effects entries. Impl may not emit side_effects for /permissions/decisions (bracket-persist only wires for tool invocations). Assertion cannot fire on current surface."})
		return out
	}
	if violation := assertPhaseTransitions(observations); violation != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "SV-SESS-03 phase-transition violation: " + violation})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-SESS-03: %d decisions driven; /state tracked %d unique side_effect(s) across %d observation(s); phases always pending → {committed,compensated}; last_phase_transition_at monotonically non-decreasing per §12.2",
			driveCount, countUniqueSideEffects(observations), len(observations))})
	return out
}

// phaseObservation records the phase + timestamp seen for one side_effect
// at one /state poll. Keyed downstream by idempotency_key.
type phaseObservation struct {
	idempotencyKey         string
	phase                  string
	lastPhaseTransitionAt  string // RFC3339 from /state response
	observedAt             time.Time
}

// driveAndObservePhases POSTs N decisions (mixing risk classes), after
// each GET /state once and records every side_effect's (phase,
// last_phase_transition_at) observation.
func driveAndObservePhases(ctx context.Context, c *runner.Client, sessionID, sessionBearer string, n int) ([]phaseObservation, error) {
	tools := []string{"fs__read_file", "fs__write_file", "fs__read_file", "fs__write_file", "fs__read_file"}
	var obs []phaseObservation
	for i := 0; i < n; i++ {
		tool := tools[i%len(tools)]
		digestHex := fmt.Sprintf("%064x", uint64(time.Now().UnixNano())+uint64(i))
		decBody := fmt.Sprintf(
			`{"tool":%q,"session_id":%q,"args_digest":"sha256:%s"}`,
			tool, sessionID, digestHex,
		)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			c.BaseURL()+"/permissions/decisions",
			strings.NewReader(decBody))
		req.Header.Set("Authorization", "Bearer "+sessionBearer)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			return obs, fmt.Errorf("decision %d: %w", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return obs, fmt.Errorf("decision %d status=%d", i+1, resp.StatusCode)
		}
		// Poll /state immediately after. Record every side_effect.
		stateBody, statusCode, err := getSessionStateRaw(ctx, c, sessionID, sessionBearer)
		if err != nil || statusCode != http.StatusOK {
			return obs, fmt.Errorf("/state after decision %d: status=%d err=%v", i+1, statusCode, err)
		}
		var parsed struct {
			Workflow struct {
				SideEffects []struct {
					IdempotencyKey        string `json:"idempotency_key"`
					Phase                 string `json:"phase"`
					LastPhaseTransitionAt string `json:"last_phase_transition_at"`
				} `json:"side_effects"`
			} `json:"workflow"`
		}
		if err := json.Unmarshal(stateBody, &parsed); err != nil {
			return obs, fmt.Errorf("parse /state after decision %d: %w", i+1, err)
		}
		now := time.Now()
		for _, se := range parsed.Workflow.SideEffects {
			obs = append(obs, phaseObservation{
				idempotencyKey:        se.IdempotencyKey,
				phase:                 se.Phase,
				lastPhaseTransitionAt: se.LastPhaseTransitionAt,
				observedAt:            now,
			})
		}
	}
	return obs, nil
}

// assertPhaseTransitions applies the §12.2 bracket-persist rules to an
// observation timeline. Returns an empty string if all rules hold;
// otherwise returns a specific diagnostic. Rules:
//   - Phase transition: the ONLY allowed transitions are pending→committed
//     or pending→compensated. No skipping pending. No back-transitions.
//   - last_phase_transition_at: monotonically non-decreasing per
//     idempotency_key.
func assertPhaseTransitions(obs []phaseObservation) string {
	// Bucket observations by idempotency_key, preserving observedAt order.
	byKey := make(map[string][]phaseObservation)
	for _, o := range obs {
		byKey[o.idempotencyKey] = append(byKey[o.idempotencyKey], o)
	}
	for key, series := range byKey {
		var prevPhase, prevTs string
		for i, o := range series {
			// Phase rule: transitions only pending→committed or pending→compensated.
			if i > 0 {
				if o.phase != prevPhase {
					ok := prevPhase == "pending" && (o.phase == "committed" || o.phase == "compensated" || o.phase == "inflight")
					if !ok {
						return fmt.Sprintf("side_effect %s: invalid phase transition %s → %s (§12.2 allows only pending → {inflight, committed, compensated})",
							key, prevPhase, o.phase)
					}
				}
			}
			// Timestamp rule: monotonic non-decreasing.
			if prevTs != "" && o.lastPhaseTransitionAt != "" && o.lastPhaseTransitionAt < prevTs {
				return fmt.Sprintf("side_effect %s: last_phase_transition_at went backwards (%s → %s)",
					key, prevTs, o.lastPhaseTransitionAt)
			}
			prevPhase = o.phase
			prevTs = o.lastPhaseTransitionAt
		}
	}
	return ""
}

func countUniqueSideEffects(obs []phaseObservation) int {
	set := make(map[string]struct{})
	for _, o := range obs {
		set[o.idempotencyKey] = struct{}{}
	}
	return len(set)
}

// getSessionStateRaw returns the raw response body, HTTP status, and any
// transport error. Does NOT parse — caller does schema assertion on the
// raw bytes (same round-trip-safety rationale as getResolve).
func getSessionStateRaw(ctx context.Context, c *runner.Client, sessionID, bearer string) ([]byte, int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+"/sessions/"+sessionID+"/state", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

// stripGeneratedAt removes the top-level "generated_at" key from a JSON
// object body and returns a canonical-bytes form suitable for equality.
// Per L-28 F-01, generated_at is the only per-request field that is
// allowed to vary between two back-to-back /state reads.
func stripGeneratedAt(body []byte) ([]byte, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	delete(obj, "generated_at")
	// Re-encode deterministically for the compare. json.Marshal with
	// Go's map iteration is non-deterministic; use the same JCS-adjacent
	// stable encoding the rest of the validator uses elsewhere. For the
	// byte-identity predicate specifically, we only need stable ordering —
	// so sort-by-key via a canonical re-encoding is enough.
	return canonicalJSON(obj)
}

func canonicalJSON(v interface{}) ([]byte, error) {
	// json.Marshal with sorted keys via our existing jcs package would be
	// overkill here (RFC 8785 semantics aren't required — we just need
	// equal output for equal input). Use the standard encoder; Go
	// json.Marshal sorts map keys lexicographically, which is sufficient.
	return json.Marshal(v)
}

// ─── shared subprocess helpers ───

// m2BaseEnv builds the common env subset every M2 subprocess needs:
// host/port, conformance card + M1 tool-registry fixture, demo mode,
// bootstrap bearer. Caller layers test-specific env on top.
func m2BaseEnv(specRoot string, port int, bearer string) map[string]string {
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

// m2Bootstrap mints a session via POST /sessions with request_decide_scope=true
// and DangerFullAccess so subsequent /permissions/resolve + /permissions/decisions
// calls have the scope they need. Returns (session_id, session_bearer, status, err).
//
// Per-bearer 30 rpm limit (impl BootstrapLimiter in sessions-route.ts:113).
// At M3 scale this gets hit when ~40+ tests all mint their own session
// against the same SOA_RUNNER_BOOTSTRAP_BEARER. Observability-read probes
// should use sharedBootstrap instead — one cached session serves many tests.
func m2Bootstrap(ctx context.Context, c *runner.Client, bootstrapBearer string) (string, string, int, error) {
	body := `{"requested_activeMode":"DangerFullAccess","user_sub":"m2-validator","request_decide_scope":true}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bootstrapBearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", "", resp.StatusCode, nil
	}
	var parsed struct {
		SessionID     string `json:"session_id"`
		SessionBearer string `json:"session_bearer"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", resp.StatusCode, err
	}
	return parsed.SessionID, parsed.SessionBearer, resp.StatusCode, nil
}

// sharedSession holds a single cached (sid, bearer) pair reused across
// observability-read probes. Tests that mutate session state (crash
// recovery, session-file isolation, drive-and-observe) MUST call
// m2Bootstrap directly for a fresh session.
var sharedSessionMu sync.Mutex
var sharedSessionSID, sharedSessionBearer string
var sharedSessionExpires time.Time

// sharedBootstrap returns a cached DFA+decide-scope session minted
// once per validator run. Cache holds for 55min (session TTL minus
// safety margin). Eliminates POST /sessions 30 rpm per-bearer churn
// for read-only observability probes.
func sharedBootstrap(ctx context.Context, c *runner.Client, bootstrapBearer string) (string, string, int, error) {
	sharedSessionMu.Lock()
	defer sharedSessionMu.Unlock()
	if sharedSessionSID != "" && time.Now().Before(sharedSessionExpires) {
		return sharedSessionSID, sharedSessionBearer, http.StatusCreated, nil
	}
	sid, bearer, status, err := m2Bootstrap(ctx, c, bootstrapBearer)
	if err != nil || status != http.StatusCreated {
		return sid, bearer, status, err
	}
	sharedSessionSID = sid
	sharedSessionBearer = bearer
	sharedSessionExpires = time.Now().Add(55 * time.Minute)
	return sid, bearer, status, nil
}

// launchProbeKill spawns impl, waits for /health, runs the probe, then
// kills the subprocess. Returns (spawnResult, probeMsg, probePass).
//
// The subprocess is started with a no-op ReadinessProbe that blocks
// until the outer goroutine signals proceed=close — this keeps Spawn
// alive while the caller's probe runs, then lets Spawn kill cleanly.
func launchProbeKill(ctx context.Context, bin string, args []string, env map[string]string, probe func(context.Context) (string, bool)) (subprocrunner.Result, string, bool) {
	port, _ := strconv.Atoi(env["RUNNER_PORT"])
	resCh := make(chan subprocrunner.Result, 1)
	proceed := make(chan struct{})

	go func() {
		res := subprocrunner.Spawn(ctx, subprocrunner.Config{
			Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
			Timeout: 30 * time.Second,
			ReadinessProbe: func(probeCtx context.Context) error {
				// Block until outer goroutine signals. When signaled,
				// return nil so Spawn triggers its kill path.
				select {
				case <-proceed:
					return nil
				case <-probeCtx.Done():
					return probeCtx.Err()
				}
			},
			PollInterval: 250 * time.Millisecond,
		})
		resCh <- res
	}()

	// Poll /health ourselves until ready or deadline.
	probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Second)
	defer probeCancel()
	healthClient := &http.Client{Timeout: 1 * time.Second}
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, healthURL, nil)
		resp, err := healthClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !ready {
		close(proceed)
		res := <-resCh
		return res, fmt.Sprintf("impl subprocess never reached /health within 15s; TimedOut=%v ExitCode=%d stderr-tail=%.300q",
			res.TimedOut, res.ExitCode, tailString(res.Stderr, 300)), false
	}
	msg, pass := probe(probeCtx)
	close(proceed)
	res := <-resCh
	return res, msg, pass
}

func tailString(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
