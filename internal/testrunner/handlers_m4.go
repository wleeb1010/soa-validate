package testrunner

// M4 adapter-conformance handler skeletons (§18.5). Probe bodies land in
// a follow-up commit once the impl session signals Phase 2.6 green + the
// adapter HTTP endpoint is available for probing.
//
// Skip precedence (all four handlers share the same gate):
//   1. h.Adapter == ""           → adapter-flag-not-set
//   2. !h.Live                   → adapter-endpoint-not-configured
//   3. probe body not implemented → todo (flips to pass/fail post-Phase-2.6)
//
// When --adapter is unset, SV-ADAPTER-* skip via the M4 deferral path in
// runner.go and never reach these handlers. The explicit adapter-flag-not-set
// branch below is belt-and-suspenders for any caller that sets cfg.Adapter to
// "" while also overriding MilestonesInScope to include M4.

import "context"

// adapterGate returns the pre-probe skip evidence shared across
// SV-ADAPTER-01..04. Returns (evidence, shouldProbe). When shouldProbe is
// false, the caller returns the evidence directly.
func adapterGate(testID string, h HandlerCtx) ([]Evidence, bool) {
	if h.Adapter == "" {
		return []Evidence{{
			Path: PathLive, Status: StatusSkip,
			Message: testID + ": adapter-flag-not-set (§18.5.5: --adapter=<langgraph|crewai|autogen|langchain-agents|custom> required to run SV-ADAPTER-*)",
		}}, false
	}
	if !h.Live {
		return []Evidence{{
			Path: PathLive, Status: StatusSkip,
			Message: testID + ": adapter-endpoint-not-configured (--adapter=" + h.Adapter + " set but --impl-url / SOA_IMPL_URL unset; cannot reach adapter HTTP surface)",
		}}, false
	}
	return nil, true
}

// handleSVADAPTER01 — Adapter Card injection (§18.5 + §18.5.1 + §18.5.4 +
// §18.5.5 + §6). Verifies /.well-known/agent-card.json carries
// adapter_notes.host_framework equal to --adapter value; deferred_test_families
// (if present) must name families the validator will subsequently skip.
// Failure reasons: card-vs-invocation-mismatch, missing-adapter-declaration.
func handleSVADAPTER01(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-01", h); !probe {
		return ev
	}
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-ADAPTER-01: probe body TODO — flips when impl Phase 2.6 adapter HTTP endpoint signal lands. Planned: fetch /.well-known/agent-card.json, verify JWS against §5.3 trust anchor, assert adapter_notes.host_framework == " + h.Adapter + ", check deferred_test_families ⊆ {SV-MEM, SV-BUD, SV-SESS}.",
	}}
}

// handleSVADAPTER02 — Pre-dispatch permission interception (§18.5.2 +
// §10.3 + §14.1 + §14.1.1 + §15.4). Drives a Mutating tool invocation,
// denies via PDA, asserts no ToolResult/ToolError for the same tool_call_id
// reaches /events/recent. Failure reasons: post-dispatch-permission,
// advisory-mode-not-core-conformant.
func handleSVADAPTER02(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-02", h); !probe {
		return ev
	}
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-ADAPTER-02: probe body TODO — flips when impl Phase 2.6 adapter HTTP endpoint signal lands. Planned: invoke one Mutating tool via adapter, subscribe to /events/recent, verify ordering ToolInputStart(args_digest=D) → PermissionPrompt(args_digest=D) → PermissionDecision(deny) → NO ToolResult/ToolError for tool_call_id T.",
	}}
}

// handleSVADAPTER03 — LangGraph event mapping (§18.5.3 + §14.6 + §14.6.1
// + §14.6.2 + §14.6.4). Replays test-vectors/langgraph-adapter/
// simple-agent-trace.json against the adapter, compares emitted SOA
// StreamEvent sequence against the fixture's expected_soa_emission (with
// §14.6.4 deviation substitution from Card). Failure reason:
// event-mapping-silent-deviation.
func handleSVADAPTER03(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-03", h); !probe {
		return ev
	}
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-ADAPTER-03: probe body TODO — flips when impl Phase 2.6 adapter HTTP endpoint signal lands. Planned: load test-vectors/langgraph-adapter/simple-agent-trace.json from pinned spec, POST langgraph_events to adapter trace-ingest, subscribe /events/recent, compare emitted type sequence vs expected_soa_emission with §14.6.4 deviation substitution from Card.event_mapping_deviations.",
	}}
}

// handleSVADAPTER04 — Adapter audit forwarding (§18.5.3 + §10.5 + §10.5.2
// + §10.5.3 + §10.5.6). Drives one ReadOnly + one Mutating tool via the
// adapter, fetches /audit/records, verifies hash chain + retention_class
// ∈ {dfa-365d, standard-90d} on tool-invocation rows. Failure reasons:
// audit-chain-broken, retention-class-missing.
func handleSVADAPTER04(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-04", h); !probe {
		return ev
	}
	return []Evidence{{
		Path: PathLive, Status: StatusSkip,
		Message: "SV-ADAPTER-04: probe body TODO — flips when impl Phase 2.6 adapter HTTP endpoint signal lands. Planned: drive 1 ReadOnly + 1 Mutating tool via adapter, GET /audit/records (admin:read), validate against schemas/audit-records-response.schema.json, verify hash chain per §10.5, assert each tool-invocation row carries retention_class ∈ {dfa-365d, standard-90d}.",
	}}
}
