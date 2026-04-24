package testrunner

// M9 A2A-surface probes (spec §17; v1.3).
//
// Registration strategy: handler wiring lands now; the live-probe bodies
// promote to real HTTP exercises in M9 W5 (validator-probes milestone).
// Until then each handler returns a skip with a precise rationale pointing
// at the impl-unit-test that carries current coverage.
//
// This file is forward-compatible with must-map entries that exist in the
// spec repo at commit ≥ ff702f4 but have not yet propagated to this
// repo's soa-validate.lock pin (still at c958bf9, v1.2.0 era). When the
// pin bumps at the v1.3.0 ceremony, these handlers become the dispatch
// targets for the newly-reachable test IDs. Until then the handler map
// entries are dormant (runner dispatches by ID presence in the pinned
// must-map, not by handler map membership).

import (
	"context"
	"fmt"
)

// SV-A2A-10 through SV-A2A-16: JWT profile + digest + HandoffStatus + deadlines
// probes. Each returns skip-with-rationale until the SOA_A2A_* env vars that
// enable a real probe run are set. Unit-test-level coverage for these
// assertions lives in soa-harness-impl/packages/runner/test/a2a-{jwt,signer-
// discovery,digest-check}.test.ts.

func handleSVA2A10Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-10: JWT alg allowlist (EdDSA/ES256/RS256≥3072); live probe requires a cooperating Runner with JWT auth configured (SOA_A2A_BEARER + a JWT-capable verifier key). Unit coverage at packages/runner/test/a2a-jwt.test.ts (alg-outside-allowlist test).",
	}}
}

func handleSVA2A11Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-11: JWT signing-key discovery via Agent-Card-kid and mTLS x5t#S256. Live probe requires a full §17.1 step-2 test harness with a caller agent publishing a valid /.well-known/agent-card.jws. Unit coverage at packages/runner/test/a2a-signer-discovery.test.ts (27 assertions covering both paths).",
	}}
}

func handleSVA2A12Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-12: jti replay cache within exp+30s. Live probe requires two JWTs with identical jti crafted by a test caller; unit coverage at packages/runner/test/a2a-jwt.test.ts (replayed-jti test + signature-invalid-does-not-poison-cache test).",
	}}
}

func handleSVA2A13Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-13: agent_card_etag drift → HandoffRejected reason=card-version-drift + CardVersionDrift event. Live probe requires a caller whose card is served at a reachable URL and a post-rotation fetch flow. Unit coverage at packages/runner/test/a2a-signer-discovery.test.ts (checkAgentCardEtagDrift match/drift/unreachable tests).",
	}}
}

func handleSVA2A14Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-14: §17.2.5 per-method digest recompute matrix. Live probe requires an offer→transfer flow with deliberately-tampered messages/workflow; unit coverage at packages/runner/test/a2a-digest-check.test.ts (16 assertions covering the full matrix + JCS canonicalization invariance).",
	}}
}

func handleSVA2A15Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-15: HandoffStatus enum closed-set + transition matrix. Live probe requires a handoff.status polling loop across the full transfer→execute→complete lifecycle. Unit coverage at packages/runner/test/a2a.test.ts (A2aTaskRegistry monotonicity tests).",
	}}
}

func handleSVA2A16Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-A2A-16: §17.2.2 per-method deadlines + env-var overrides. Live probe requires booting a Runner with a specific SOA_A2A_*_DEADLINE_S env override and timing request round-trips; unit coverage at packages/runner/test/a2a.test.ts (resolveA2aDeadlines env-override tests).",
	}}
}

// SV-A2A-17: §17.2.3 A2A capability advertisement and matching.
//
// Scope: exercise the 5 truth-table rows + the byte-exact reason string
// "no-a2a-capabilities-advertised" + error.data.missing_capabilities shape
// + capabilities_needed validation (non-empty strings, dedup, soft cap).
//
// Live-probe promotion (M9 W5) requires:
//   - SOA_A2A_URL  — optional override for a2a endpoint; defaults to
//     h.Client.BaseURL() + "/a2a/v1"
//   - SOA_A2A_BEARER — W1 bearer token accepted by the /a2a/v1 plugin
//     (replaced by JWT profile after §17.1 middleware lands in W3).
//   - An agent.describe round-trip so the probe can introspect the
//     Runner's advertised a2a.capabilities set and construct both
//     subset-accept and non-subset-CapabilityMismatch payloads driven by
//     the Runner's actual surface (not a hard-coded test fixture).
//
// Until those land, this handler skips with a pointer to the impl-side
// unit and integration tests that cover §17.2.3 exhaustively.
func handleSVA2A17Skip(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{
		Path:   PathLive,
		Status: StatusSkip,
		Message: fmt.Sprint(
			"SV-A2A-17: §17.2.3 truth-table + reason-string + error.data.missing_capabilities ",
			"assertions currently covered at the impl-unit layer in soa-harness-impl/packages/runner/",
			"test/a2a.test.ts (40 assertions: 13 pure-function truth-table + dedup + UTF-8 byte- ",
			"comparison + validation, 5 wire integration over POST /a2a/v1). Live probe lands in ",
			"M9 W5 once the JWT profile (W3) stabilizes agent.describe signing-key discovery and ",
			"the Agent Card test harness serves a deterministic a2a.capabilities set the ",
			"validator can introspect before constructing row-4 subset-match / row-5 non-subset ",
			"payloads. Pin-bump to spec commit ≥ ff702f4 activates this handler; until then the ",
			"registration is dormant.",
		),
	}}
}
