package testrunner

// V-11 handlers — SV-AGENTS-01..05, 07, 08 (7 tests). SV-AGENTS-06 is
// M5-deferred. All 7 blocked on impl: current `parseAgentsMdDenyList`
// (packages/runner/src/registry/agents-md.ts) handles only the
// `## Agent Type Constraints` → `### Deny` denylist subset used by
// SV-REG-04. The full §7.2/§7.3 parser (7 required H2s ordered + unique,
// @import depth ≤ 8, cycle detection, mid-turn reload semantics,
// entrypoint Card cross-check) is not shipped.
//
// **Finding AT (impl)**: implement the full §7.2 + §7.3 AGENTS.md parser
// with the required failure taxonomy:
//   §7.2 missing/duplicate/out-of-order H2 → AgentsMdInvalid
//   §7.3 @import depth > 8              → AgentsMdImportDepthExceeded
//   §7.3 @import A→B→A cycle             → AgentsMdImportCycle
//   §7.4 mid-turn file change             → ignored until turn end
//   §7.2#4 entrypoint/card mismatch       → AgentsMdInvalid
// Emit each as a System Event Log record on /logs/system/recent
// (category=Config, level=error, code=<enum>) so validator can observe.
//
// Spec-side ask (potential Finding AU): ship fixture set
// test-vectors/agents-md-grammar/{missing-h2, duplicate-h2, out-of-
// order-h2, import-depth-9, import-cycle, mid-turn-reload, entrypoint-
// mismatch}/ covering each failure path. All 7 handlers below wire a
// real subprocess probe once AT lands + fixtures arrive.

import (
	"context"
)

// ─── SV-AGENTS-01 §7.2 — Required H2 present ─────────────────────────

func handleSVAGENTS01(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-01 (§7.2 required H2): impl parseAgentsMdDenyList (registry/agents-md.ts) handles " +
			"only `## Agent Type Constraints` → `### Deny`; full §7.2 grammar check (7 required H2 order + uniqueness) not shipped. " +
			"**Finding AT (impl)**: ship full §7.2 parser; missing required H2 → AgentsMdInvalid system-log record. " +
			"Probe (post-AT): spawn impl with SOA_RUNNER_AGENTS_MD_PATH pointing at a fixture missing `## Memory Policy`; " +
			"assert /logs/system/recent has {category=Config, level=error, code=AgentsMdInvalid, data.reason=missing-h2}."}}
}

// ─── SV-AGENTS-02 §7.2 — H2 ordering ─────────────────────────────────

func handleSVAGENTS02(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-02 (§7.2 H2 ordering): out-of-order H2 → AgentsMdInvalid — blocked by Finding AT (full §7.2 parser). " +
			"Probe (post-AT): fixture with `## Agent Persona` before `## Project Rules`, assert AgentsMdInvalid(data.reason=h2-out-of-order)."}}
}

// ─── SV-AGENTS-03 §7.2 — Duplicate H2 rejected ───────────────────────

func handleSVAGENTS03(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-03 (§7.2 duplicate H2): duplicate required H2 → AgentsMdInvalid — blocked by Finding AT. " +
			"Probe (post-AT): fixture with two `## Project Rules` H2s, assert AgentsMdInvalid(data.reason=h2-duplicate)."}}
}

// ─── SV-AGENTS-04 §7.3 — @import depth ────────────────────────────────

func handleSVAGENTS04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-04 (§7.3 @import depth ≤ 8): depth-9 → AgentsMdImportDepthExceeded — blocked by Finding AT (no @import support). " +
			"Probe (post-AT): 9-deep import chain A→B→…→I, assert AgentsMdImportDepthExceeded system-log record."}}
}

// ─── SV-AGENTS-05 §7.3 — @import cycle ───────────────────────────────

func handleSVAGENTS05(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-05 (§7.3 @import cycle): A→B→A → AgentsMdImportCycle — blocked by Finding AT (no @import support). " +
			"Probe (post-AT): A imports B imports A, assert AgentsMdImportCycle system-log record with data.cycle=[A,B,A]."}}
}

// ─── SV-AGENTS-07 §7.4 — No mid-turn reload ──────────────────────────

func handleSVAGENTS07(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-07 (§7.4 no mid-turn reload): AGENTS.md modified mid-turn ignored until turn end — blocked by Finding AT (no reload machinery). " +
			"Probe (post-AT): spawn impl, start a turn, rewrite AGENTS.md mid-turn, observe no change until turn end; " +
			"verify new-turn-after-end picks up new rules."}}
}

// ─── SV-AGENTS-08 §7.2/§6.2 — entrypoint matches Card ────────────────

func handleSVAGENTS08(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-AGENTS-08 (§7.2/§6.2 entrypoint match): AGENTS.md `## Self-Improvement Policy` → `entrypoint: <path>` MUST equal " +
			"Card `self_improvement.entrypoint_file` (mismatch raises AgentsMdInvalid) — blocked by Finding AT. " +
			"Probe (post-AT): fixture AGENTS.md with entrypoint: agent_wrong.py against conformance-card with entrypoint_file: agent.py, " +
			"assert AgentsMdInvalid(data.reason=entrypoint-mismatch)."}}
}
