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
