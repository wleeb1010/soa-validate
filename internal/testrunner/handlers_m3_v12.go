package testrunner

// V-12 handlers — HR-07/09/10/11.
//
// HR-09 + HR-10 are validator-local pure functions on diff bytes. No SI
// runtime required (§9.3 + §9.1 explicitly say "harness MUST reject
// any diff that..." — the VALIDATOR is the harness). HR-07 + HR-11
// need impl surface extensions (Findings AV + AW).

import (
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

	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/sidiff"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── HR-07 §11.2 + §15.5 — agentType=explore cannot invoke Mutating ──

func handleHR07(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "HR-07: SOA_IMPL_BIN unset"}}
	}
	cardPath, cleanup, err := writeExploreReadOnlyCard(h.Spec)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "writeExploreReadOnlyCard: " + err.Error()}}
	}
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "hr07-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_PATH":            cardPath,
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		// Mint a ReadOnly session (card's activeMode ceiling is ReadOnly, explore-type).
		bootBody := `{"requested_activeMode":"ReadOnly","user_sub":"hr07-driver","request_decide_scope":true}`
		bootReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/sessions", strings.NewReader(bootBody))
		bootReq.Header.Set("Content-Type", "application/json")
		bootReq.Header.Set("Authorization", "Bearer "+bearer)
		bootResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(bootReq)
		if err != nil {
			return "HR-07 bootstrap: " + err.Error(), false
		}
		bootRaw, _ := io.ReadAll(bootResp.Body)
		bootResp.Body.Close()
		if bootResp.StatusCode != http.StatusCreated {
			return fmt.Sprintf("HR-07 bootstrap status=%d body=%.200q", bootResp.StatusCode, string(bootRaw)), false
		}
		var boot struct{ SessionID, SessionBearer string }
		_ = json.Unmarshal(bootRaw, &struct {
			SessionID     *string `json:"session_id"`
			SessionBearer *string `json:"session_bearer"`
		}{&boot.SessionID, &boot.SessionBearer})
		sid := boot.SessionID
		sbearer := boot.SessionBearer
		body := []byte(fmt.Sprintf(`{"tool":"fs__write_file","session_id":%q,"args_digest":"sha256:%064x"}`, sid, time.Now().UnixNano()))
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sbearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "HR-07 POST /permissions/decisions: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("HR-07 status=%d (want 403 agent-type-insufficient); body=%.200q", resp.StatusCode, string(raw)), false
		}
		var dec struct {
			Error, Reason string
		}
		_ = json.Unmarshal(raw, &dec)
		if dec.Reason != "agent-type-insufficient" {
			return fmt.Sprintf("HR-07 reason=%q (want agent-type-insufficient); body=%.200q", dec.Reason, string(raw)), false
		}
		return fmt.Sprintf("§11.2 + §15.5 HR-07 agent-type enforcement: agentType=explore + ReadOnly card → fs__write_file → 403 {reason:agent-type-insufficient}"), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// writeExploreReadOnlyCard builds a temp card with agentType=explore +
// activeMode=ReadOnly (passes AN precedence-guard; allows Mutating-tool
// runtime rejection path under AV).
func writeExploreReadOnlyCard(spec specvec.Locator) (string, func(), error) {
	raw, err := spec.Read(specvec.ConformanceCard)
	if err != nil {
		return "", func() {}, err
	}
	var card map[string]interface{}
	if err := json.Unmarshal(raw, &card); err != nil {
		return "", func() {}, err
	}
	card["agentType"] = "explore"
	if perms, ok := card["permissions"].(map[string]interface{}); ok {
		perms["activeMode"] = "ReadOnly"
	}
	out, _ := json.MarshalIndent(card, "", "  ")
	dir, err := os.MkdirTemp("", "hr07-card-*")
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "agent-card.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}

// ─── HR-09 §9.3 — SI marker escape (validator-local) ─────────────────
//
// Pure function on diff bytes + entrypoint source. Spec §9.3: "harness
// MUST reject any diff that modifies bytes outside the EDITABLE SURFACES
// span." Validator IS the harness for this assertion. No SI runtime.
func handleHR09(ctx context.Context, h HandlerCtx) []Evidence {
	// Synthetic agent.py with markers and a diff touching bytes OUTSIDE the span.
	entrypoint := `#!/usr/bin/env python3
# Immutable boot prelude
import sys

# === EDITABLE SURFACES (meta-agent may modify) ===
def persona():
    return "helpful assistant"

def routing_logic(query):
    return "default"
# === END EDITABLE SURFACES ===

# === IMMUTABLE ADAPTER (do not edit) ===
def mcp_client_bootstrap():
    pass
# === END IMMUTABLE ADAPTER ===

if __name__ == "__main__":
    sys.exit(0)
`
	// Valid diff (inside span): modifies line 7 which is inside [6, 10).
	goodDiff := `--- a/agent.py
+++ b/agent.py
@@ -6,3 +6,3 @@
 def persona():
-    return "helpful assistant"
+    return "very helpful assistant"

`
	// Escape diff: modifies line 3 (import sys), which is OUTSIDE the editable span.
	escapeDiff := `--- a/agent.py
+++ b/agent.py
@@ -3,1 +3,2 @@
-import sys
+import sys
+import os
`
	good := sidiff.ValidateDiff("agent.py", entrypoint, goodDiff)
	if !good.Accepted {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§9.3 diff-validator rejected a legitimate in-span edit: reason=%s detail=%s", good.RejectReason, good.Detail)}}
	}
	escape := sidiff.ValidateDiff("agent.py", entrypoint, escapeDiff)
	if escape.Accepted {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "§9.3 diff-validator ACCEPTED a marker-escape edit (line outside EDITABLE SURFACES span); expected SelfImprovementRejected"}}
	}
	if escape.RejectReason != "SelfImprovementRejected" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§9.3 marker escape rejected with wrong code: got %s, want SelfImprovementRejected", escape.RejectReason)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "§9.3 SI marker escape: validator-local diff-validator accepts in-span edit + rejects out-of-span edit with SelfImprovementRejected"}}
}

// ─── HR-10 §9.1 — SI immutable task (validator-local) ────────────────

func handleHR10(ctx context.Context, h HandlerCtx) []Evidence {
	entrypoint := "# === EDITABLE SURFACES ===\nfoo\n# === END EDITABLE SURFACES ===\n"
	tasksDiff := `--- a/tasks/benchmark-01.harbor
+++ b/tasks/benchmark-01.harbor
@@ -1,1 +1,1 @@
-old content
+new content
`
	result := sidiff.ValidateDiff("agent.py", entrypoint, tasksDiff)
	if result.Accepted {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "§9.1 diff-validator ACCEPTED an edit to tasks/ (immutable target); expected ImmutableTargetEdit"}}
	}
	if result.RejectReason != "ImmutableTargetEdit" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§9.1 tasks/ edit rejected with wrong code: got %s, want ImmutableTargetEdit", result.RejectReason)}}
	}
	// Negative-of-negative: a non-tasks edit that's otherwise valid should NOT trip this check.
	okDiff := `--- a/agent.py
+++ b/agent.py
@@ -2,1 +2,1 @@
-foo
+bar
`
	ok := sidiff.ValidateDiff("agent.py", entrypoint, okDiff)
	if !ok.Accepted {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§9.1 sanity: non-tasks edit rejected: reason=%s detail=%s", ok.RejectReason, ok.Detail)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "§9.1 SI immutable task: validator-local diff-validator rejects tasks/* edits with ImmutableTargetEdit + accepts non-tasks in-span edits"}}
}

// ─── HR-11 §10.3 step 3 — toolRequirements tighten-only ──────────────

func handleHR11(ctx context.Context, h HandlerCtx) []Evidence {
	return awLooseningCardProbe(ctx, h, "HR-11")
}

// awLooseningCardProbe is shared by HR-11 + SV-PERM-02: build a card
// whose toolRequirements maps a tool to a LOOSER control than its
// registry default_control. Spawn impl → /ready=503 + Config log
// record code=ConfigPrecedenceViolation.
func awLooseningCardProbe(ctx context.Context, h HandlerCtx, testID string) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: testID + ": SOA_IMPL_BIN unset"}}
	}
	cardPath, cleanup, err := writeLooseningCard(h.Spec)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "writeLooseningCard: " + err.Error()}}
	}
	defer cleanup()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := strings.ToLower(testID) + "-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_PATH":            cardPath,
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		readyResp, err := client.Do(probeCtx, http.MethodGet, "/ready", nil)
		if err != nil {
			return testID + ": GET /ready: " + err.Error(), false
		}
		readyResp.Body.Close()
		if readyResp.StatusCode != http.StatusServiceUnavailable {
			return fmt.Sprintf("%s: /ready status=%d (want 503 — toolRequirements loosening should raise ConfigPrecedenceViolation)", testID, readyResp.StatusCode), false
		}
		url := fmt.Sprintf("%s/logs/system/recent?session_id=ses_runnerBootLifetime&category=Config&limit=50", client.BaseURL())
		logReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		logReq.Header.Set("Authorization", "Bearer "+bearer)
		logResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(logReq)
		if err != nil {
			return testID + ": GET /logs/system/recent: " + err.Error(), false
		}
		logRaw, _ := io.ReadAll(logResp.Body)
		logResp.Body.Close()
		if logResp.StatusCode != http.StatusOK {
			return fmt.Sprintf("%s: /logs/system/recent status=%d; body=%.200q", testID, logResp.StatusCode, string(logRaw)), false
		}
		var parsed struct {
			Records []struct {
				Category, Level, Code string
			} `json:"records"`
		}
		_ = json.Unmarshal(logRaw, &parsed)
		for _, r := range parsed.Records {
			if r.Category == "Config" && r.Level == "error" && r.Code == "ConfigPrecedenceViolation" {
				return fmt.Sprintf("%s: /ready=503 + /logs/system/recent {Config/error/ConfigPrecedenceViolation} for toolRequirements loosening (§10.3 step 3 tighten-only)", testID), true
			}
		}
		return fmt.Sprintf("%s: no ConfigPrecedenceViolation in %d Config records", testID, len(parsed.Records)), false
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// writeLooseningCard builds a card whose toolRequirements explicitly
// maps a Mutating-class tool to AutoAllow under activeMode=ReadOnly —
// a §10.3 step 3 loosening.
func writeLooseningCard(spec specvec.Locator) (string, func(), error) {
	raw, err := spec.Read(specvec.ConformanceCard)
	if err != nil {
		return "", func() {}, err
	}
	var card map[string]interface{}
	if err := json.Unmarshal(raw, &card); err != nil {
		return "", func() {}, err
	}
	if perms, ok := card["permissions"].(map[string]interface{}); ok {
		perms["activeMode"] = "ReadOnly"
		perms["toolRequirements"] = map[string]interface{}{
			"fs__write_file": "AutoAllow",
		}
	}
	out, _ := json.MarshalIndent(card, "", "  ")
	dir, err := os.MkdirTemp("", "hr11-card-*")
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "agent-card.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}
