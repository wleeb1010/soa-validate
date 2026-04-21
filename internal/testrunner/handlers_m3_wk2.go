package testrunner

// M3 Week-2 handlers (V-6 + V-7) — Budget (§13) + ToolRegistry (§11)
// observability. Impl T-3 shipped /budget/projection + /tools/registered
// ahead of schedule (Week 1 Day 1). Observability scaffolds go live today;
// rule-level tests (SV-BUD-01..07, SV-REG-01..05) skip-pending until impl
// T-4 (real p95-over-W accounting) + T-5 (mcp-dynamic registration) ship.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── V-6 SV-BUD + SV-BUD-PROJ (9 tests) ──────────────────────────────

func handleSVBUD01(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-01", "§13 projection algorithm — needs impl T-4 real p95-over-W accounting.")
}
func handleSVBUD02(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-02", "§13 pre-call halt — projection predicts exhaustion → refuse decision. Needs T-4.")
}
func handleSVBUD03(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-03", "§13 mid-stream cancel on BudgetExhausted. Needs T-4 + T-2 (/events/recent).")
}
func handleSVBUD04(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-04", "§13 cache_accounting fields populated after real turns. Needs T-4.")
}
func handleSVBUD05(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-05", "§13 billing_tag propagation. Needs T-4.")
}
func handleSVBUD06(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-06", "§13 StopReason closed enum — BudgetExhausted emitted. Needs T-4.")
}
func handleSVBUD07(ctx context.Context, h HandlerCtx) []Evidence {
	return budgetPending(h, "SV-BUD-07", "§13 BillingTagMismatch detected via /budget/projection. Needs T-4.")
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
	sid, bearer, status, err := m2Bootstrap(ctx, h.Client, bootstrapBearer)
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

func budgetPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-4 (real p95-over-W accounting). Handler wired; flips when impl signals T-4 lands."},
	}
}

// ─── V-7 SV-REG + SV-REG-OBS (7 tests) ───────────────────────────────

func handleSVREG01(ctx context.Context, h HandlerCtx) []Evidence {
	return registryPending(h, "SV-REG-01", "§11 list_tools metadata-only (no handler state). Needs impl T-5.")
}
func handleSVREG02(ctx context.Context, h HandlerCtx) []Evidence {
	return registryPending(h, "SV-REG-02", "§11 MCP name pattern enforcement. Needs T-5.")
}
func handleSVREG03(ctx context.Context, h HandlerCtx) []Evidence {
	return registryPending(h, "SV-REG-03", "§11.3.1 tool pool pinned per session; SOA_RUNNER_DYNAMIC_TOOL_REGISTRATION hook per L-34. Needs T-5.")
}
func handleSVREG04(ctx context.Context, h HandlerCtx) []Evidence {
	return registryPending(h, "SV-REG-04", "§11 deny-list from AGENTS.md. Needs T-5.")
}
func handleSVREG05(ctx context.Context, h HandlerCtx) []Evidence {
	return registryPending(h, "SV-REG-05", "§11 list_tools field shape (name, description, risk_class, retention). Needs T-5.")
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
	_, bearer, status, err := m2Bootstrap(ctx, h.Client, bootstrapBearer)
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

// ─── V-8 SV-HOOK (8 tests) — PreToolUse / PostToolUse lifecycle ──────

func handleSVHOOK01(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-01", "§11.5 PreToolUse/PostToolUse stdin schema conformance. Needs impl T-6 hook lifecycle.")
}
func handleSVHOOK02(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-02", "§11.5 PreToolUse 5s timeout default — hang → SIGKILL + Deny.")
}
func handleSVHOOK03(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-03", "§11.5 PostToolUse 10s timeout default — hang → SIGKILL + log.")
}
func handleSVHOOK04(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-04", "§11.5 exit-code table: 0,1,2,3 per spec; other codes → HookAbnormalExit.")
}
func handleSVHOOK05(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-05", "§11.5 PreToolUse replace_args modifies tool invocation.")
}
func handleSVHOOK06(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-06", "§11.5 PostToolUse replace_result modifies recorded tool result.")
}
func handleSVHOOK07(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-07", "§11.5 step-5 ordering: Perm → Pre → Tool → Post → Audit/Stream/Persist.")
}
func handleSVHOOK08(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-08", "§11.5 no hook reentrancy: hook invoking a Runner tool → HookReentrancy + session terminate.")
}

func hookPending(h HandlerCtx, testID, diagnostic string) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: testID + " — " + diagnostic},
		{Path: PathLive, Status: StatusSkip, Message: testID + ": blocks on impl T-6 (PreToolUse/PostToolUse lifecycle via internal/subprocrunner). Handler wired; flips when impl signals T-6 lands."},
	}
}
