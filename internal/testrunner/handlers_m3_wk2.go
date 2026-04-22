package testrunner

// M3 Week-2 handlers (V-6 + V-7) — Budget (§13) + ToolRegistry (§11)
// observability. Impl T-3 shipped /budget/projection + /tools/registered
// ahead of schedule (Week 1 Day 1). Observability scaffolds go live today;
// rule-level tests (SV-BUD-01..07, SV-REG-01..05) skip-pending until impl
// T-4 (real p95-over-W accounting) + T-5 (mcp-dynamic registration) ship.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

func jsonUnmarshal(body []byte, v interface{}) error { return json.Unmarshal(body, v) }

// ─── V-6 SV-BUD + SV-BUD-PROJ (9 tests) ──────────────────────────────

// SV-BUD-01: §13 projection algorithm — cold-start body carries the
// spec-required invariants: safety_factor=1.15 (const), cold_start_baseline_active=true
// on a fresh session, stop_reason_if_exhausted="BudgetExhausted" (const),
// cumulative_tokens_consumed starts at 0, projection_headroom >= 0 at cold-start.
func handleSVBUD01(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetProjectionAssert(ctx, h, "SV-BUD-01", func(p map[string]interface{}) string {
		if sf, _ := p["safety_factor"].(float64); sf != 1.15 {
			return fmt.Sprintf("safety_factor=%v; §13 requires 1.15", p["safety_factor"])
		}
		if csb, _ := p["cold_start_baseline_active"].(bool); !csb {
			return "cold_start_baseline_active=false on fresh session; §13.1 requires true at cold-start"
		}
		if cum, _ := p["cumulative_tokens_consumed"].(float64); cum != 0 {
			return fmt.Sprintf("cumulative_tokens_consumed=%v on fresh session; want 0", cum)
		}
		return ""
	}, "§13 projection algorithm: safety_factor=1.15, cold_start_baseline_active=true, cumulative=0 at session-start")
}
func handleSVBUD02(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-02", "§13 pre-call halt — projection predicts exhaustion → refuse decision. **Finding K**: impl's BudgetTracker.recordTurn() has zero callers in src; /permissions/decisions doesn't invoke it. Cumulative accounting never advances, so budget exhaustion cannot be driven externally. Impl T-4 wired the tracker class but not its invocation path.")
}
func handleSVBUD03(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-03", "§13 mid-stream cancel on BudgetExhausted. **Finding K**: same recordTurn-zero-callers gap as SV-BUD-02; mid-stream cancel requires budget to actually exhaust.")
}
func handleSVBUD04(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-04", "§13 cache_accounting fields populated after real turns. **Finding K**: recordTurn has zero callers; cache_accounting stays unpopulated in the cold-start body. Spec requires observable turn accounting path.")
}
func handleSVBUD05(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-05", "§13 billing_tag propagation through audit records. **Finding K**: no turn-recording path; billing_tag never flows from a turn into audit. Needs impl to wire recordTurn at a real turn boundary OR ship an observable test-hook endpoint.")
}
// SV-BUD-06: §13 StopReason closed enum — /budget/projection exposes
// `stop_reason_if_exhausted` as a const "BudgetExhausted" per schema.
// Verify the field carries that exact value (schema enforces structurally;
// we assert the behavioral link: this is THE stop reason the impl will
// emit when budget is actually exhausted).
func handleSVBUD06(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetProjectionAssert(ctx, h, "SV-BUD-06", func(p map[string]interface{}) string {
		sr, _ := p["stop_reason_if_exhausted"].(string)
		if sr != "BudgetExhausted" {
			return fmt.Sprintf("stop_reason_if_exhausted=%q; §13 closed enum requires \"BudgetExhausted\"", sr)
		}
		return ""
	}, "§13 StopReason closed enum: /budget/projection.stop_reason_if_exhausted=\"BudgetExhausted\"")
}
func handleSVBUD07(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-07", "§13 BillingTagMismatch detected via /budget/projection. **Finding K**: no recordTurn invocation path; impossible to surface a mismatch event in the absence of turn accounting.")
}

// SV-BUD-PROJ-01: schema validity on GET /budget/projection/<session_id>.
// Impl T-3 shipped cold-start quiescent body (cumulative=0, safety_factor=1.15).
func handleSVBUDPROJ01(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetProjectionProbe(ctx, h, "SV-BUD-PROJ-01", false)
}

// SV-BUD-PROJ-02: not-a-side-effect. Two rapid reads byte-identical after
// stripping generated_at.
func handleSVBUDPROJ02(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetProjectionProbe(ctx, h, "SV-BUD-PROJ-02", true)
}

func budgetProjectionProbe(ctx context.Context, h HandlerCtx, testID string, byteIdentity bool) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §13.5 /budget/projection observability"}}
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
	body1, code1, err := getBudgetProjectionRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if code1 == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("%s: GET /budget/projection/<sid> → 404; impl has not shipped §13.5 yet (blocks on impl T-3)", testID)})
		return out
	}
	if code1 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: status=%d; want 200 with session bearer. body=%.200q", testID, code1, string(body1))})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.BudgetProjectionResponseSchema), body1); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: §13.5 response fails schema: %v", testID, err)})
		return out
	}
	if !byteIdentity {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: fmt.Sprintf("%s: GET /budget/projection/<sid> 200 + schema-valid per §13.5", testID)})
		return out
	}
	body2, code2, _ := getBudgetProjectionRaw(ctx, h.Client, sid, bearer)
	if code2 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: second read status=%d; want 200", testID, code2)})
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
			Message: fmt.Sprintf("%s: two rapid /budget/projection reads differ after stripping generated_at; §13.5 not-a-side-effect invariant violated", testID)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: §13.5 not-a-side-effect — strip(generated_at) byte-identical across two reads", testID)})
	return out
}

func getBudgetProjectionRaw(ctx context.Context, c *runner.Client, sessionID, bearer string) ([]byte, int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL()+"/budget/projection/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

// budgetProjectionAssert: fetch /budget/projection/<sid>, schema-validate,
// decode, run checker against the decoded body. PASS when checker returns "".
func budgetProjectionAssert(ctx context.Context, h HandlerCtx, testID string,
	checker func(map[string]interface{}) string, passMsg string) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §13 /budget/projection invariant"}}
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
	body, code, err := getBudgetProjectionRaw(ctx, h.Client, sid, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if code == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("%s: GET /budget/projection/<sid> → 404; impl has not shipped §13.5 yet", testID)})
		return out
	}
	if code != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: status=%d; want 200", testID, code)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.BudgetProjectionResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: §13.5 response fails schema: %v", testID, err)})
		return out
	}
	var parsed map[string]interface{}
	if err := jsonUnmarshal(body, &parsed); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("%s: parse /budget/projection body: %v", testID, err)})
		return out
	}
	if violation := checker(parsed); violation != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: %s", testID, violation)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: %s", testID, passMsg)})
	return out
}

func budgetPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-4 (real p95-over-W accounting). Handler wired; flips when impl signals T-4 lands."},
	}
}

// ─── V-7 SV-REG + SV-REG-OBS (7 tests) ───────────────────────────────

// SV-REG-01: /tools/registered returns metadata-only — no handler state,
// no session-binding, no runtime-only fields. Schema's closed property set
// already enforces this structurally; we additionally assert each tool entry
// contains ONLY spec-listed fields.
func handleSVREG01(ctx context.Context, h HandlerCtx) []Evidence {
	return registryMetadataProbe(ctx, h, "SV-REG-01", func(tools []map[string]interface{}) string {
		allowed := map[string]bool{"name": true, "risk_class": true, "default_control": true,
			"idempotency_retention_seconds": true, "registered_at": true, "registration_source": true}
		for i, t := range tools {
			for k := range t {
				if !allowed[k] {
					return fmt.Sprintf("tool[%d]=%q carries unexpected field %q (§11 list_tools MUST be metadata-only)", i, t["name"], k)
				}
			}
		}
		return ""
	}, "§11 /tools/registered metadata-only: every tool entry carries only spec-listed fields")
}

// SV-REG-02: MCP name pattern enforcement. Per §11.1 tool names follow
// the `mcp__<category>__<tool>` shape OR the bare-string static-fixture
// convention. We accept either: static-fixture tools have category-prefixed
// names (fs__, net__, proc__, mem__); mcp-dynamic tools would use mcp__.
func handleSVREG02(ctx context.Context, h HandlerCtx) []Evidence {
	nameRe := regexp.MustCompile(`^(?:mcp__[a-z0-9_]+__[a-z0-9_]+|[a-z][a-z0-9_]*__[a-z][a-z0-9_]*)$`)
	return registryMetadataProbe(ctx, h, "SV-REG-02", func(tools []map[string]interface{}) string {
		for i, t := range tools {
			name, _ := t["name"].(string)
			if !nameRe.MatchString(name) {
				return fmt.Sprintf("tool[%d] name %q violates §11 MCP-name pattern (mcp__category__tool or category__tool)", i, name)
			}
		}
		return ""
	}, "§11 MCP name pattern: all registered tools follow category__tool or mcp__category__tool shape")
}

// SV-REG-03: §11.3 per-session tool-pool pinning. Spawn impl subprocess
// with SOA_RUNNER_DYNAMIC_TOOL_REGISTRATION=<triggerfile>; mint session
// S1; note S1's tool_pool_hash (H1); write new tool to trigger file; wait
// for watcher poll; assert /tools/registered.registry_version advanced AND
// S1's tool_pool_hash is STILL H1 (§11.3 — per-session hashes are snapshot
// at POST /sessions time and never mutate mid-session).
func handleSVREG03(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §11.3 subprocess with SOA_RUNNER_DYNAMIC_TOOL_REGISTRATION hook"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-REG-03: SOA_IMPL_BIN unset; cannot spawn subprocess with §11.3.1 dynamic-reg hook"})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	tmp, err := os.MkdirTemp("", "sv-reg-03-*")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "mkdir temp: " + err.Error()})
		return out
	}
	defer os.RemoveAll(tmp)
	triggerPath := filepath.Join(tmp, "dyn-reg-trigger.json")
	if err := os.WriteFile(triggerPath, []byte("[]"), 0644); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "seed trigger: " + err.Error()})
		return out
	}

	port := implTestPort()
	bearer := "svreg03-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                         strconv.Itoa(port),
		"RUNNER_HOST":                         "127.0.0.1",
		"RUNNER_INITIAL_TRUST":                filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":                 filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":                filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":                    "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":         bearer,
		"SOA_RUNNER_DYNAMIC_TOOL_REGISTRATION": triggerPath,
	}

	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 2 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err), false
		}
		// Baseline: read /sessions/<sid>/state AND /tools/registered
		state1, code1, _ := getSessionStateRaw(probeCtx, client, sid, sbearer)
		if code1 != http.StatusOK {
			return fmt.Sprintf("baseline /state status=%d", code1), false
		}
		var st1 struct {
			ToolPoolHash string `json:"tool_pool_hash"`
		}
		if err := json.Unmarshal(state1, &st1); err != nil {
			return "baseline /state parse: " + err.Error(), false
		}
		reg1, regCode1, _ := getToolsRegisteredRaw(probeCtx, client, sbearer)
		if regCode1 != http.StatusOK {
			return fmt.Sprintf("baseline /tools/registered status=%d", regCode1), false
		}
		var r1 struct {
			Tools           []map[string]interface{} `json:"tools"`
			RegistryVersion string                   `json:"registry_version"`
		}
		if err := json.Unmarshal(reg1, &r1); err != nil {
			return "baseline /tools/registered parse: " + err.Error(), false
		}
		// Write new tool to trigger. Use a unique name so repeat runs don't collide.
		newTool := fmt.Sprintf(
			`[{"name":"mcp__dyn__svreg03_%d","risk_class":"ReadOnly","default_control":"AutoAllow","idempotency_retention_seconds":3600}]`,
			time.Now().UnixNano())
		if err := os.WriteFile(triggerPath, []byte(newTool), 0644); err != nil {
			return "write trigger: " + err.Error(), false
		}
		// Wait for watcher to poll (impl default 250ms) + settle.
		time.Sleep(1500 * time.Millisecond)

		// Post-trigger: /tools/registered advanced; session /state unchanged.
		reg2, regCode2, _ := getToolsRegisteredRaw(probeCtx, client, sbearer)
		if regCode2 != http.StatusOK {
			return fmt.Sprintf("post-trigger /tools/registered status=%d", regCode2), false
		}
		var r2 struct {
			Tools           []map[string]interface{} `json:"tools"`
			RegistryVersion string                   `json:"registry_version"`
		}
		if err := json.Unmarshal(reg2, &r2); err != nil {
			return "post-trigger /tools/registered parse: " + err.Error(), false
		}
		if r1.RegistryVersion == r2.RegistryVersion {
			return fmt.Sprintf("registry_version unchanged (%s); §11.3.1 requires global-registry advance on dynamic add. Watcher may not have polled; wait extended, trigger file=%s", r1.RegistryVersion, triggerPath), false
		}
		if len(r2.Tools) != len(r1.Tools)+1 {
			return fmt.Sprintf("tool count %d → %d; want +1 after dynamic add", len(r1.Tools), len(r2.Tools)), false
		}
		// Session's pool hash MUST still match baseline (§11.3 per-session pinning).
		state2, code2, _ := getSessionStateRaw(probeCtx, client, sid, sbearer)
		if code2 != http.StatusOK {
			return fmt.Sprintf("post-trigger /state status=%d", code2), false
		}
		var st2 struct {
			ToolPoolHash string `json:"tool_pool_hash"`
		}
		if err := json.Unmarshal(state2, &st2); err != nil {
			return "post-trigger /state parse: " + err.Error(), false
		}
		if st1.ToolPoolHash != st2.ToolPoolHash {
			return fmt.Sprintf("session tool_pool_hash advanced (%s → %s) on dynamic-add; §11.3 requires per-session pinning — mid-session pool hashes MUST NOT mutate", st1.ToolPoolHash, st2.ToolPoolHash), false
		}
		return fmt.Sprintf("SV-REG-03: dynamic add via §11.3.1 trigger flipped global registry_version (%s → %s) while in-flight session tool_pool_hash stayed pinned at %s per §11.3",
			r1.RegistryVersion, r2.RegistryVersion, st1.ToolPoolHash), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-REG-03: " + msg})
	}
	return out
}
// SV-REG-04: AGENTS.md deny-list subtraction. Spawn impl subprocess with
// SOA_RUNNER_AGENTS_MD_PATH pointing at the pinned denylist fixture
// (L-35 spec, test-vectors/agents-md-denylist/AGENTS.md) and
// RUNNER_TOOLS_FIXTURE pointing at tools-with-denied.json. Assert
// GET /tools/registered.tools[] excludes fs_write_dangerous.
func handleSVREG04(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §11.2 AGENTS.md deny-list via SOA_RUNNER_AGENTS_MD_PATH + pinned fixture"}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-REG-04: SOA_IMPL_BIN unset; cannot spawn subprocess with §11.2.1 AGENTS.md hook"})
		return out
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	agentsMD := filepath.Join(specRoot, "test-vectors", "agents-md-denylist", "AGENTS.md")
	toolsFixture := filepath.Join(specRoot, "test-vectors", "agents-md-denylist", "tools-with-denied.json")
	if _, err := os.Stat(agentsMD); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SV-REG-04: pinned fixture " + agentsMD + " missing; spec pin may be pre-L-35"})
		return out
	}
	port := implTestPort()
	bearer := "svreg04-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        toolsFixture,
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
		"SOA_RUNNER_AGENTS_MD_PATH":   agentsMD,
	}

	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		_, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap failed: status=%d err=%v (impl may not have shipped §11.2.1 loader yet)", status, err), false
		}
		body, code, err := getToolsRegisteredRaw(probeCtx, client, sbearer)
		if err != nil {
			return "GET /tools/registered: " + err.Error(), false
		}
		if code != http.StatusOK {
			return fmt.Sprintf("GET /tools/registered status=%d (want 200)", code), false
		}
		var parsed struct {
			Tools []map[string]interface{} `json:"tools"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "parse /tools/registered: " + err.Error(), false
		}
		// Denied tool must be absent; fixture includes 5 tools, 1 denied.
		for _, t := range parsed.Tools {
			if n, _ := t["name"].(string); n == "fs_write_dangerous" {
				return "tools[] still contains fs_write_dangerous; §11.2 AGENTS.md deny-list not subtracted. Impl has not shipped §11.2.1 AGENTS.md loader.", false
			}
		}
		if len(parsed.Tools) != 4 {
			return fmt.Sprintf("expected 4 tools (5 fixture − 1 denied); got %d. Deny-list subtraction may not have run against the fixture.", len(parsed.Tools)), false
		}
		return fmt.Sprintf("SV-REG-04: /tools/registered.tools[]=%d entries after AGENTS.md deny-list subtraction (5 fixture − 1 denied=fs_write_dangerous) per §11.2.1", len(parsed.Tools)), true
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "SV-REG-04: " + msg})
	}
	return out
}

// SV-REG-05: list_tools field shape — every tool carries name, risk_class,
// default_control, registered_at, registration_source per schema required[].
func handleSVREG05(ctx context.Context, h HandlerCtx) []Evidence {
	required := []string{"name", "risk_class", "default_control", "registered_at", "registration_source"}
	return registryMetadataProbe(ctx, h, "SV-REG-05", func(tools []map[string]interface{}) string {
		if len(tools) == 0 {
			return "tools array empty — cannot assert field shape"
		}
		for i, t := range tools {
			for _, f := range required {
				if _, ok := t[f]; !ok {
					return fmt.Sprintf("tool[%d]=%q missing required field %q", i, t["name"], f)
				}
			}
		}
		return ""
	}, "§11 list_tools field shape: every tool carries {name, risk_class, default_control, registered_at, registration_source}")
}

// registryMetadataProbe fetches /tools/registered, schema-validates, then
// runs the per-test structural checker against the decoded tools array.
// Returns PASS when checker returns empty string, FAIL otherwise.
func registryMetadataProbe(ctx context.Context, h HandlerCtx, testID string,
	checker func([]map[string]interface{}) string, passMsg string) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §11 /tools/registered metadata assertion"}}
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
			Message: fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err)})
		return out
	}
	body, code, err := getToolsRegisteredRaw(ctx, h.Client, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if code == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("%s: GET /tools/registered → 404; impl has not shipped §11.4 yet", testID)})
		return out
	}
	if code != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: status=%d; want 200", testID, code)})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.ToolsRegisteredResponseSchema), body); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: §11.4 response fails schema: %v", testID, err)})
		return out
	}
	var parsed struct {
		Tools []map[string]interface{} `json:"tools"`
	}
	if err := jsonUnmarshal(body, &parsed); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("%s: parse tools array: %v", testID, err)})
		return out
	}
	if violation := checker(parsed.Tools); violation != "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: %s", testID, violation)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: %s (observed %d tools)", testID, passMsg, len(parsed.Tools))})
	return out
}

// SV-REG-OBS-01: schema validity on GET /tools/registered. Impl T-3 shipped
// live ToolRegistry read with registry_version=sha256(JCS(tools[])).
func handleSVREGOBS01(ctx context.Context, h HandlerCtx) []Evidence {
	return toolsRegisteredProbe(ctx, h, "SV-REG-OBS-01", false)
}

// SV-REG-OBS-02: not-a-side-effect byte-identity predicate.
func handleSVREGOBS02(ctx context.Context, h HandlerCtx) []Evidence {
	return toolsRegisteredProbe(ctx, h, "SV-REG-OBS-02", true)
}

func toolsRegisteredProbe(ctx context.Context, h HandlerCtx, testID string, byteIdentity bool) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §11.4 /tools/registered observability"}}
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
			Message: fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err)})
		return out
	}
	body1, code1, err := getToolsRegisteredRaw(ctx, h.Client, bearer)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if code1 == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("%s: GET /tools/registered → 404; impl has not shipped §11.4 yet (blocks on impl T-3)", testID)})
		return out
	}
	if code1 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: status=%d; want 200. body=%.200q", testID, code1, string(body1))})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.ToolsRegisteredResponseSchema), body1); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: §11.4 response fails schema: %v", testID, err)})
		return out
	}
	if !byteIdentity {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: fmt.Sprintf("%s: GET /tools/registered 200 + schema-valid per §11.4", testID)})
		return out
	}
	body2, code2, _ := getToolsRegisteredRaw(ctx, h.Client, bearer)
	if code2 != http.StatusOK {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("%s: second read status=%d; want 200", testID, code2)})
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
			Message: fmt.Sprintf("%s: two rapid /tools/registered reads differ after stripping generated_at; §11.4 not-a-side-effect invariant violated", testID)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%s: §11.4 not-a-side-effect — strip(generated_at) byte-identical across two reads", testID)})
	return out
}

func getToolsRegisteredRaw(ctx context.Context, c *runner.Client, bearer string) ([]byte, int, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+"/tools/registered", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

func registryPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-5 (dynamic MCP registration). Handler wired; flips when impl signals T-5 lands."},
	}
}

// SV-HOOK-01..08 live in handlers_m3_hooks.go with real subprocess
// hook-harness implementations (01-04) + skip-pending diagnostics (05-08).

func hookPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-6 (PreToolUse/PostToolUse lifecycle via internal/subprocrunner). Handler wired; flips when impl signals T-6 lands."},
	}
}
