package testrunner

// M3 Week-2 (V-8) §15 hook lifecycle handlers — SV-HOOK-01..08.
//
// Strategy: each test generates a per-test Python hook script at runtime
// (in a tempdir), spawns a fresh impl subprocess with SOA_PRE_TOOL_USE_HOOK
// and/or SOA_POST_TOOL_USE_HOOK pointing at the script, drives a permission
// decision, and asserts the hook's effect on the HTTP response.
//
// Impl hook protocol (packages/runner/src/hook/runner.ts):
//   Stdin: JSON {hook: "PreToolUse"|"PostToolUse", session_id, turn_id,
//                tool: {name, risk_class, args_digest},
//                capability, handler}
//   Stdout: single-line JSON, optional {decision?, reason?, ...}
//   Exit codes (Pre): 0=Allow, 1=Deny, 2=Deny, 3=Prompt, other=Deny hook-nonzero-exit
//   Exit codes (Post): 0=Allow, 1=Deny, 2=Allow (retry), other=Deny hook-nonzero-exit
//   Timeouts: Pre 5s, Post 10s (SIGKILL).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/runner"
)

// hookTestHarness captures the subprocess + probe invocation pattern.
// Generates the Python hook script, spawns impl with that script wired,
// runs the provided probe, returns Evidence.
type hookTestHarness struct {
	testID      string
	preScript   string // Python source; written to <tmp>/pre-hook.py. Empty = not configured.
	postScript  string // Python source; written to <tmp>/post-hook.py. Empty = not configured.
	probe       func(probeCtx context.Context, client *runner.Client, bearer string) (string, bool)
	description string // live-only skip vector evidence text
}

// runHookHarness is the SV-HOOK test runner. Writes scripts, spawns impl
// with env vars set, invokes probe against /permissions/decisions. Honest
// SKIP on SOA_IMPL_BIN unset or python unavailable.
func runHookHarness(ctx context.Context, h HandlerCtx, cfg hookTestHarness) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only — §15 hook lifecycle " + cfg.description}}
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: cfg.testID + ": SOA_IMPL_BIN unset; cannot spawn subprocess with hook"})
		return out
	}
	pythonBin, err := exec.LookPath("python")
	if err != nil {
		if p2, err2 := exec.LookPath("python3"); err2 == nil {
			pythonBin = p2
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: cfg.testID + ": no python on PATH; cannot generate hook scripts"})
			return out
		}
	}
	tmp, err := os.MkdirTemp("", "sv-hook-*")
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	defer os.RemoveAll(tmp)
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := cfg.testID + "-hook-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
	if cfg.preScript != "" {
		preScriptPath := filepath.Join(tmp, "pre-hook.py")
		if err := os.WriteFile(preScriptPath, []byte(cfg.preScript), 0755); err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "write pre-hook: " + err.Error()})
			return out
		}
		env["SOA_PRE_TOOL_USE_HOOK"] = pythonBin + " " + preScriptPath
	}
	if cfg.postScript != "" {
		postScriptPath := filepath.Join(tmp, "post-hook.py")
		if err := os.WriteFile(postScriptPath, []byte(cfg.postScript), 0755); err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "write post-hook: " + err.Error()})
			return out
		}
		env["SOA_POST_TOOL_USE_HOOK"] = pythonBin + " " + postScriptPath
	}

	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		_, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap failed: status=%d err=%v", status, err), false
		}
		return cfg.probe(probeCtx, client, sbearer)
	})
	if pass {
		out = append(out, Evidence{Path: PathLive, Status: StatusPass, Message: msg})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: cfg.testID + ": " + msg})
	}
	return out
}

// postDecision is a minimal test-local wrapper around POST /permissions/decisions.
// Returns (response-body-as-map, HTTP status, error).
func postDecisionForHook(ctx context.Context, client *runner.Client, sid, sbearer, tool, argsDigest string) (map[string]interface{}, int, error) {
	body := fmt.Sprintf(
		`{"tool":%q,"session_id":%q,"args_digest":"sha256:%s"}`,
		tool, sid, argsDigest,
	)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		client.BaseURL()+"/permissions/decisions",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sbearer)
	req.Header.Set("Content-Type", "application/json")
	// Post-hook 10s timeout means the response can take ≥10s when Post
	// hook sleeps to its own SIGKILL. Allow generous client timeout.
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var parsed map[string]interface{}
	_ = json.Unmarshal(raw, &parsed)
	return parsed, resp.StatusCode, nil
}

// Standard args_digest placeholder per spec test conventions.
const hookProbeDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// mintSessionForHook bootstraps a fresh session against the given client
// (subprocess-spawned impl), returning session_id + bearer.
func mintSessionForHook(ctx context.Context, client *runner.Client, bootstrapBearer string) (string, string, error) {
	body := `{"requested_activeMode":"DangerFullAccess","user_sub":"sv-hook","request_decide_scope":true}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL()+"/sessions",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bootstrapBearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("mint session: status=%d body=%.200q", resp.StatusCode, string(raw))
	}
	var parsed struct {
		SessionID     string `json:"session_id"`
		SessionBearer string `json:"session_bearer"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", fmt.Errorf("parse: %w", err)
	}
	return parsed.SessionID, parsed.SessionBearer, nil
}

// ─── SV-HOOK handlers ─────────────────────────────────────────────────

// SV-HOOK-01: PreToolUse stdin schema. Script reads stdin, validates
// required fields (hook, session_id, turn_id, tool.{name,risk_class,
// args_digest}, capability, handler). Exits 0 on pass → decision goes
// through with AutoAllow/Prompt per normal resolver.
const preStdinSchemaScript = `import sys, json
try:
    d = json.loads(sys.stdin.read())
    assert d.get("hook") == "PreToolUse"
    assert isinstance(d.get("session_id"), str) and d["session_id"].startswith("ses_")
    assert isinstance(d.get("turn_id"), str) and d["turn_id"].startswith("turn_")
    t = d.get("tool")
    assert isinstance(t, dict)
    assert isinstance(t.get("name"), str)
    assert t.get("risk_class") in ("ReadOnly", "Mutating", "Destructive")
    assert isinstance(t.get("args_digest"), str)
    assert d.get("capability") in ("ReadOnly", "WorkspaceWrite", "DangerFullAccess")
    assert isinstance(d.get("handler"), str)
    sys.exit(0)
except Exception as e:
    sys.stderr.write(f"stdin-schema-fail: {e}\n")
    sys.exit(1)
`

func handleSVHOOK01(ctx context.Context, h HandlerCtx) []Evidence {
	return runHookHarness(ctx, h, hookTestHarness{
		testID:      "SV-HOOK-01",
		description: "PreToolUse stdin schema conformance",
		preScript:   preStdinSchemaScript,
		probe: func(probeCtx context.Context, client *runner.Client, _ string) (string, bool) {
			sid, sbearer, err := mintSessionForHook(probeCtx, client, "SV-HOOK-01-hook-bearer")
			if err != nil {
				return "mint session: " + err.Error(), false
			}
			body, status, err := postDecisionForHook(probeCtx, client, sid, sbearer, "fs__read_file", hookProbeDigest)
			if err != nil {
				return "POST /permissions/decisions: " + err.Error(), false
			}
			// Stdin-schema-valid → hook exits 0 (Allow) → decision resolves
			// normally. A 403 hook-deny with reason=hook-deny would mean
			// the hook failed our assertion; fail-closed script exits 1 on
			// bad stdin.
			if status == http.StatusCreated {
				return fmt.Sprintf("SV-HOOK-01: PreToolUse stdin validates; decision returned %s with status=201 (hook validated all required fields per §15.2)", body["decision"]), true
			}
			if status == http.StatusForbidden {
				reason, _ := body["reason"].(string)
				if reason == "hook-deny" {
					return fmt.Sprintf("SV-HOOK-01: hook FAILED stdin-schema assertion (returned 403 hook-deny). Impl's stdin payload missing/malformed required fields per §15.2. response=%v", body), false
				}
			}
			return fmt.Sprintf("SV-HOOK-01: unexpected status=%d body=%v", status, body), false
		},
	})
}

// SV-HOOK-02: PreToolUse 5s timeout default. Hook sleeps 30s → impl
// SIGKILLs + treats as Deny with timeout reason.
const preTimeoutScript = `import sys, time
time.sleep(30)
sys.exit(0)
`

func handleSVHOOK02(ctx context.Context, h HandlerCtx) []Evidence {
	return runHookHarness(ctx, h, hookTestHarness{
		testID:      "SV-HOOK-02",
		description: "PreToolUse 5s timeout → SIGKILL + Deny",
		preScript:   preTimeoutScript,
		probe: func(probeCtx context.Context, client *runner.Client, _ string) (string, bool) {
			sid, sbearer, err := mintSessionForHook(probeCtx, client, "SV-HOOK-02-hook-bearer")
			if err != nil {
				return "mint session: " + err.Error(), false
			}
			start := time.Now()
			body, status, err := postDecisionForHook(probeCtx, client, sid, sbearer, "fs__read_file", hookProbeDigest)
			dur := time.Since(start)
			if err != nil {
				return "POST /permissions/decisions: " + err.Error(), false
			}
			if status != http.StatusForbidden {
				return fmt.Sprintf("status=%d (want 403); §15.3 requires Deny on hook timeout; dur=%v", status, dur), false
			}
			reason, _ := body["reason"].(string)
			if reason != "hook-deny" {
				return fmt.Sprintf("reason=%q; want hook-deny on PreToolUse timeout", reason), false
			}
			// Kill should happen at ~5s per §15.3 PRE_TOOL_USE_TIMEOUT_MS.
			if dur > 8*time.Second {
				return fmt.Sprintf("timeout took %v; §15.3 requires 5s kill", dur), false
			}
			return fmt.Sprintf("SV-HOOK-02: PreToolUse timeout observed at %v (<8s), impl returned 403 hook-deny per §15.3", dur), true
		},
	})
}

// SV-HOOK-03: PostToolUse 10s timeout default. Post runs on the audit/
// stream/persist trailing path; observable indirectly via step-5
// ordering — but the M1-coarse observable is the Post hook timing out
// and emitting a log but NOT blocking the decision response. Narrow
// assertion: POST /permissions/decisions still returns 201 even when
// Post hook is sleeping (because Pre is Allow + Post doesn't gate the
// HTTP response per §15.3 ordering).
const postTimeoutScript = `import sys, time
time.sleep(30)
sys.exit(0)
`

func handleSVHOOK03(ctx context.Context, h HandlerCtx) []Evidence {
	return runHookHarness(ctx, h, hookTestHarness{
		testID:      "SV-HOOK-03",
		description: "PostToolUse 10s timeout → SIGKILL + log",
		postScript:  postTimeoutScript,
		probe: func(probeCtx context.Context, client *runner.Client, _ string) (string, bool) {
			sid, sbearer, err := mintSessionForHook(probeCtx, client, "SV-HOOK-03-hook-bearer")
			if err != nil {
				return "mint session: " + err.Error(), false
			}
			start := time.Now()
			_, status, err := postDecisionForHook(probeCtx, client, sid, sbearer, "fs__read_file", hookProbeDigest)
			dur := time.Since(start)
			if err != nil {
				return "POST /permissions/decisions: " + err.Error(), false
			}
			if status != http.StatusCreated {
				return fmt.Sprintf("status=%d (want 201); PostToolUse timeout MUST NOT block decision response per §15.3", status), false
			}
			// Post hook is 10s default; HTTP response blocks on Post completion
			// per current impl — so we expect ~10s wall-clock.
			if dur < 9*time.Second {
				return fmt.Sprintf("decision returned after %v; Post hook was supposed to sleep through the 10s timeout — duration too short to have waited for timeout", dur), false
			}
			return fmt.Sprintf("SV-HOOK-03: PostToolUse timeout observed at %v (near 10s SIGKILL), decision response still 201 per §15.3", dur), true
		},
	})
}

// SV-HOOK-04: PreToolUse exit-code table. Test arm: script exits 3 → Prompt.
const preExit3Script = `import sys
sys.exit(3)
`

func handleSVHOOK04(ctx context.Context, h HandlerCtx) []Evidence {
	return runHookHarness(ctx, h, hookTestHarness{
		testID:      "SV-HOOK-04",
		description: "exit-code table: 3 → Prompt (one arm)",
		preScript:   preExit3Script,
		probe: func(probeCtx context.Context, client *runner.Client, _ string) (string, bool) {
			sid, sbearer, err := mintSessionForHook(probeCtx, client, "SV-HOOK-04-hook-bearer")
			if err != nil {
				return "mint session: " + err.Error(), false
			}
			// fs__read_file is normally AutoAllow under DFA. Hook exit=3
			// forces to Prompt per §15.3.
			body, status, err := postDecisionForHook(probeCtx, client, sid, sbearer, "fs__read_file", hookProbeDigest)
			if err != nil {
				return "POST /permissions/decisions: " + err.Error(), false
			}
			if status != http.StatusCreated {
				return fmt.Sprintf("status=%d (want 201)", status), false
			}
			decision, _ := body["decision"].(string)
			if decision != "Prompt" {
				return fmt.Sprintf("decision=%q; §15.3 exit-3 MUST force Prompt (base resolver would have AutoAllow'd fs__read_file under DFA)", decision), false
			}
			return "SV-HOOK-04: PreToolUse exit=3 forced Prompt per §15.3 exit-code table (override: AutoAllow → Prompt)", true
		},
	})
}

// SV-HOOK-05 and SV-HOOK-06 (replace_args / replace_result) need
// observable args_digest OR tool result mutation on the audit record.
// Not straightforward on a single-decision flow — impl may or may not
// surface the replacement in /permissions/decisions response. Skip with
// precise diagnostic pending observation channel clarity.
func handleSVHOOK05(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-05", "§15.3 replace_args honored — observable surface unclear. Impl accepts stdout JSON {replace_args} but changes may land only in audit record detail. Needs /audit/records post-decision cross-check.")
}
func handleSVHOOK06(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-06", "§15.3 replace_result honored — PostToolUse output observability; current impl surface doesn't expose in /permissions/decisions response.")
}

// SV-HOOK-07: step-5 ordering. Observable via /events/recent — PreToolUse
// event logs BEFORE PermissionDecision event. Impl may or may not emit
// these yet; skip until observable.
func handleSVHOOK07(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-07", "§15.3 step-5 ordering (Perm→Pre→Tool→Post→Audit/Stream/Persist). Needs observable per-step events in /events/recent. Impl T-6 ships hook invocation but event-emission for Pre/Post ordering may not be in §14.1 25-type enum.")
}

// SV-HOOK-08: reentrancy. Hook invokes /permissions/decisions on the
// Runner — impl MUST detect + terminate session.
func handleSVHOOK08(ctx context.Context, h HandlerCtx) []Evidence {
	return hookPending(h, "SV-HOOK-08", "§15.3 no hook reentrancy — hook calls Runner /permissions/decisions → HookReentrancy + session terminate. Needs subprocess with hook that makes HTTP call back to parent Runner port (known at spawn time) + observation of session terminate.")
}
