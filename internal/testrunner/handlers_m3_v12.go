package testrunner

// V-12 handlers — HR-07/09/10/11.
//
// HR-09 + HR-10 are validator-local pure functions on diff bytes. No SI
// runtime required (§9.3 + §9.1 explicitly say "harness MUST reject
// any diff that..." — the VALIDATOR is the harness). HR-07 + HR-11
// need impl surface extensions (Findings AV + AW).

import (
	"context"
	"fmt"

	"github.com/wleeb1010/soa-validate/internal/sidiff"
)

// ─── HR-07 §15.5 — Agent-type enforcement ────────────────────────────

func handleHR07(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-07 (§11.2 + §15.5 agentType=explore cannot invoke Mutating): precedence-guard catches explore+activeMode>ReadOnly " +
			"at Card layer (SV-CARD-10), but no runtime check at /permissions/decisions rejects a Mutating-class tool request " +
			"from agentType=explore when activeMode=ReadOnly. **Finding AV (impl)**: decisions-route MUST add {error:PermissionDenied, " +
			"reason:agent-type-insufficient} branch when (session.activeMode >= tool.risk_class) holds but session is bound to " +
			"agentType=explore AND tool.risk_class > ReadOnly. Validator probe (post-AV): spawn impl with agentType=explore + " +
			"activeMode=DangerFullAccess card, mint session (note: SV-CARD-10 precedence gate would fire here — need card with " +
			"agentType=explore + activeMode=ReadOnly). Resolved: activeMode=ReadOnly so fs__read_file OK, but the test requires " +
			"a Mutating tool attempt — which is already denied by the ReadOnly ceiling. The §11.2 rule is that agentType is a " +
			"SEPARATE axis — reason must be agent-type-insufficient, not readonly-ceiling. This is an audit-reason-label gap more " +
			"than a blocking behavior gap."}}
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

// ─── HR-11 §10.3 — Permission override tighten-only ──────────────────

func handleHR11(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-11 (§10.3 step 3 toolRequirements tighten-only): impl precedence-guard.ts has axis 1 (agentType × activeMode) + " +
			"axis 2 (AGENTS.md denylist × toolRequirements), but no axis 3 (activeMode × toolRequirements) enforcing tighten-only. " +
			"A Card with activeMode=ReadOnly + toolRequirements={fs__write_file:AutoAllow} loosens — MUST raise ConfigPrecedenceViolation " +
			"at boot. **Finding AW (impl)**: precedence-guard.ts gains axis 3 — for each toolRequirements entry, if the tool's " +
			"risk_class exceeds the Card's activeMode (e.g., Mutating tool under ReadOnly activeMode), emit ConfigPrecedenceViolation " +
			"with axis=\"activemode-tool-requirement\". Validator probe (post-AW): subprocess with crafted Card → /ready=503 + " +
			"{Config/error/ConfigPrecedenceViolation}."}}
}
