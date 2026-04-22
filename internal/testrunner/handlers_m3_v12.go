package testrunner

// V-12 handlers — HR-07/09/10/11. HR-01 already wired (vector pass,
// live skip pending impl cold-start restart hook). HR-02/03/14/17
// are separate M2/M3 tracks; this file covers the 4 V-12 remainder.
//
// Impl surface audit (post-V-10):
//   - agentType precedence check: card-level only (SV-CARD-10 gate via
//     precedence-guard.ts axis 1). Runtime agentType→tool denial at
//     decisions-route is NOT shipped.
//   - toolRequirements × activeMode tighten-only: precedence-guard has
//     axis 1 (agentType × activeMode) + axis 2 (denylist × toolReqs),
//     no axis 3 (activeMode × toolReqs) for the HR-11 path.
//   - Self-improvement edit pipeline (editable_surfaces, /tasks/
//     immutability): SI is M5 territory except for Card-declared shape
//     fields; no runtime edit-enforcement shipped.

import (
	"context"
)

// ─── HR-07 §15.5 — Agent-type enforcement ────────────────────────────

func handleHR07(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-07 (§15.5 agentType=explore cannot invoke Mutating): impl precedence-guard.ts catches explore+activeMode>ReadOnly " +
			"at the Card layer (SV-CARD-10 surface), but there's no runtime check at /permissions/decisions that rejects a " +
			"Mutating-class tool request from an explore-type agent when activeMode=ReadOnly (the ReadOnly-ceiling path rejects " +
			"via resolved_control, not via agent-type reason). **Finding AV (impl)**: decisions-route MUST reject a Mutating-class " +
			"request from agentType=explore with `{error:PermissionDenied, reason:agent-type-insufficient}` + audit row carrying " +
			"the same reason. Validator probe (post-AV): spawn impl with agentType=explore + activeMode=ReadOnly card, mint " +
			"session, attempt fs__write_file decision, assert 403 with reason=agent-type-insufficient."}}
}

// ─── HR-09 §15.5 — SI marker escape ──────────────────────────────────

func handleHR09(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-09 (§15.5 SI marker escape): diff editing bytes outside EDITABLE SURFACES is rejected. Impl has no SI edit " +
			"pipeline — self-improvement is mostly M5 + Card shape fields. **Finding AX (impl)**: full SI edit pipeline " +
			"(editable_surfaces enforcement + diff-validator + rejected-outside-editable outcome) is M5 scope; M3 retag " +
			"to M5 may be correct per user's pre-budget list. Alternative probe if impl ships a subset: stub edit-pipeline " +
			"that only validates a diff against editable_surfaces without running a real SI iteration."}}
}

// ─── HR-10 §15.5 — SI immutable task ─────────────────────────────────

func handleHR10(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-10 (§15.5 SI immutable task): diff touching /tasks/ MUST reject with ImmutableTargetEdit. Same SI-pipeline " +
			"blocker as HR-09 — impl does not ship the edit pipeline in M3. **Finding AX (impl)**: same impl ask as HR-09 " +
			"(diff-validator + immutable-target enforcement). /tasks/ is the canonical immutable-target set per §9.2; the " +
			"validator probe would submit a test diff touching tasks/ and assert `{error:ImmutableTargetEdit}`."}}
}

// ─── HR-11 §15.5 — Permission override tighten-only ──────────────────

func handleHR11(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "HR-11 (§15.5 toolRequirements tighten-only): impl precedence-guard.ts has axis 1 (agentType × activeMode) + axis 2 " +
			"(AGENTS.md denylist × toolRequirements), but no axis 3 (activeMode × toolRequirements) enforcing the tighten-only " +
			"rule. A Card with activeMode=ReadOnly + toolRequirements={fs__write_file:AutoAllow} loosens — MUST raise " +
			"ConfigPrecedenceViolation on boot. **Finding AW (impl)**: extend precedence-guard.ts with axis 3 — any toolRequirements " +
			"entry mapping a tool whose risk_class exceeds the Card's activeMode is a violation. Validator probe (post-AW): " +
			"subprocess with the crafted Card, expect /ready=503 + ConfigPrecedenceViolation log record (same wire as SV-CARD-10)."}}
}
