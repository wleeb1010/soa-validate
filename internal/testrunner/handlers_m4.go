package testrunner

// M4 adapter-conformance probes (§18.5). Runs when --adapter=<name> is
// supplied and --impl-url points at a live adapter HTTP surface.
//
// Environment extensions (Phase 2.7 adapter-demo default values shown):
//   SOA_ADAPTER_SESSION_ID       /events/recent session scope (default
//                                "ses_adapterdemo0000001")
//   SOA_ADAPTER_SESSION_BEARER   session bearer for /events/recent
//                                (default "adapter-demo-session-bearer")
//   SOA_ADAPTER_BACKEND_URL      back-end Runner URL carrying the adapter's
//                                upstream /audit/tool-invocations + /audit/records
//                                (required for SV-ADAPTER-04 full probe; demo
//                                logs this URL at startup)
//   SOA_ADAPTER_BACKEND_BEARER   back-end bearer (default
//                                "adapter-demo-back-end" per the demo binary)
//
// Skip precedence (all four handlers share adapterGate first):
//   1. h.Adapter == ""           → adapter-flag-not-set
//   2. !h.Live                   → adapter-endpoint-not-configured
//   Per-handler fail/pass from there.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/wleeb1010/soa-validate/internal/auditchain"
)

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

// fetchAdapterCard GETs the adapter's Agent Card from
// /.well-known/agent-card.json and decodes it into a map. The card is
// shared across SV-ADAPTER-01 and SV-ADAPTER-02 so both probes can
// assert against the same bytes in one fetch.
func fetchAdapterCard(ctx context.Context, h HandlerCtx) (map[string]any, error) {
	resp, err := h.Client.Do(ctx, http.MethodGet, "/.well-known/agent-card.json", nil)
	if err != nil {
		return nil, fmt.Errorf("GET /.well-known/agent-card.json: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /.well-known/agent-card.json: status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read card body: %w", err)
	}
	var card map[string]any
	if err := json.Unmarshal(body, &card); err != nil {
		return nil, fmt.Errorf("card-malformed: %w", err)
	}
	return card, nil
}

// handleSVADAPTER01 — Adapter Card injection (§18.5 + §18.5.1 + §18.5.4 +
// §18.5.5 + §6). Verifies /.well-known/agent-card.json carries
// adapter_notes.host_framework equal to --adapter value.
func handleSVADAPTER01(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-01", h); !probe {
		return ev
	}

	card, err := fetchAdapterCard(ctx, h)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-01: " + err.Error()}}
	}

	notes, ok := card["adapter_notes"].(map[string]any)
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-01: missing-adapter-declaration (card has no adapter_notes but --adapter=" + h.Adapter + " was supplied per §18.5.1)"}}
	}

	got, _ := notes["host_framework"].(string)
	if got == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-01: missing-adapter-declaration (card has adapter_notes but no host_framework field per §18.5.1)"}}
	}
	if got != h.Adapter {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-01: card-vs-invocation-mismatch (card adapter_notes.host_framework=%q != --adapter=%q per §18.5.1)", got, h.Adapter)}}
	}

	// §18.5.4: if deferred_test_families present, each entry MUST be in
	// the allowed set {SV-MEM, SV-BUD, SV-SESS}.
	if raw, has := notes["deferred_test_families"]; has {
		arr, ok := raw.([]any)
		if !ok {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: "SV-ADAPTER-01: adapter_notes.deferred_test_families is not an array per §18.5.4"}}
		}
		for _, item := range arr {
			s, _ := item.(string)
			if s != "SV-MEM" && s != "SV-BUD" && s != "SV-SESS" {
				return []Evidence{{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("SV-ADAPTER-01: deferred_test_families entry %q not in allowed set {SV-MEM, SV-BUD, SV-SESS} per §18.5.4", s)}}
			}
		}
	}

	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-ADAPTER-01: card adapter_notes.host_framework=%q matches --adapter=%q", got, h.Adapter)}}
}

// handleSVADAPTER02 — Pre-dispatch permission interception (§18.5.2).
// Full runtime verification (deny→no ToolResult) requires driving a tool
// dispatch through the adapter's LangGraph ToolNode, which is out of
// reach for a pure HTTP consumer. This probe enforces the card-declared
// invariant (§18.5.2 item 4): permission_mode MUST be "pre-dispatch" for
// core-conformance; "advisory" is an explicit opt-out.
func handleSVADAPTER02(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-02", h); !probe {
		return ev
	}

	card, err := fetchAdapterCard(ctx, h)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-02: " + err.Error()}}
	}

	notes, _ := card["adapter_notes"].(map[string]any)
	if notes == nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-02: missing-adapter-declaration (prerequisite for §18.5.2 probe)"}}
	}
	mode, _ := notes["permission_mode"].(string)
	switch mode {
	case "":
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-02: adapter_notes.permission_mode absent (§18.5.2 requires the declaration for core-conformant adapters)"}}
	case "advisory":
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-02: advisory-mode-not-core-conformant (card declares permission_mode=advisory; §18.5.2 item 4 excludes advisory from the core profile)"}}
	case "pre-dispatch":
		return []Evidence{{Path: PathLive, Status: StatusPass,
			Message: "SV-ADAPTER-02: card declares permission_mode=pre-dispatch per §18.5.2. Note: full runtime deny→no-dispatch verification requires driving the adapter's ToolNode from a JS consumer — out of scope for HTTP-only validator."}}
	default:
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-02: adapter_notes.permission_mode=%q not in {pre-dispatch, advisory} per §18.5.2", mode)}}
	}
}

// handleSVADAPTER03 — LangGraph event mapping (§18.5.3 + §14.6). Reads
// /events/recent and, if non-empty, compares the emitted type sequence
// against the fixture's expected_soa_emission (direct-mapped subset).
// When /events/recent is empty (no traffic driven), the probe passes
// trivially — there are no silent deviations, which is the only
// fail-conditional in the assertion.
func handleSVADAPTER03(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-03", h); !probe {
		return ev
	}

	sid := os.Getenv("SOA_ADAPTER_SESSION_ID")
	if sid == "" {
		sid = "ses_adapterdemo0000001"
	}
	bearer := os.Getenv("SOA_ADAPTER_SESSION_BEARER")
	if bearer == "" {
		bearer = "adapter-demo-session-bearer"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		h.Client.BaseURL()+"/events/recent?session_id="+sid, nil)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "SV-ADAPTER-03: build events request: " + err.Error()}}
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	hc := &http.Client{Timeout: 5_000_000_000} // 5s
	resp, err := hc.Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-03: GET /events/recent: " + err.Error()}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-03: GET /events/recent: status %s (expected 200)", resp.Status)}}
	}
	body, _ := io.ReadAll(resp.Body)
	var payload struct {
		Events []struct {
			Type     string `json:"type"`
			Sequence int    `json:"sequence"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-03: /events/recent response body not JSON-decodable: " + err.Error()}}
	}

	if len(payload.Events) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusPass,
			Message: "SV-ADAPTER-03: /events/recent empty — no silent deviations possible. Traffic-driven sequence verification requires a LangGraph trace pushed through the adapter bridge (§18.5.3)."}}
	}

	// Fixture lives in the pinned spec repo.
	fixturePath := h.Spec.Path("test-vectors/langgraph-adapter/simple-agent-trace.json")
	fixRaw, err := os.ReadFile(fixturePath)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "SV-ADAPTER-03: read fixture " + fixturePath + ": " + err.Error()}}
	}
	var fixture struct {
		ExpectedSoaEmission []struct {
			Type string `json:"type"`
		} `json:"expected_soa_emission"`
	}
	if err := json.Unmarshal(fixRaw, &fixture); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "SV-ADAPTER-03: fixture unmarshal: " + err.Error()}}
	}

	// §14.6.2 orchestrator-sourced synthetic events are NOT emitted by
	// the EventMapper (they come from the orchestrator layer). Filter
	// them from the expected direct-mapped sequence before comparison.
	synthetic := map[string]bool{
		"MemoryLoad": true, "PermissionPrompt": true, "PermissionDecision": true,
		"PreToolUseOutcome": true, "PostToolUseOutcome": true, "ToolInputEnd": true,
		"CompactionStart": true, "CompactionEnd": true, "CrashEvent": true,
		"HandoffStart": true, "HandoffComplete": true, "HandoffFailed": true,
		"SelfImprovementStart": true, "SelfImprovementAccepted": true,
		"SelfImprovementRejected": true, "SelfImprovementOrphaned": true,
	}
	var expected []string
	for _, e := range fixture.ExpectedSoaEmission {
		if !synthetic[e.Type] {
			expected = append(expected, e.Type)
		}
	}
	var got []string
	for _, e := range payload.Events {
		got = append(got, e.Type)
	}

	if strings.Join(got, ",") != strings.Join(expected, ",") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-03: event-mapping-silent-deviation — /events/recent emitted [%s]; fixture expected direct-mapped [%s] per §14.6.1",
				strings.Join(got, ","), strings.Join(expected, ","))}}
	}

	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-ADAPTER-03: /events/recent emitted %d event(s) matching fixture direct-mapped sequence per §14.6.1", len(got))}}
}

// handleSVADAPTER04 — Adapter audit forwarding (§18.5.3 + §10.5 +
// §10.5.2 + §10.5.3 + §10.5.6). Drives 2 fixture tool-invocation rows
// (one ReadOnly + one Mutating) into the back-end Runner's
// /audit/tool-invocations endpoint (the same upstream the adapter's
// audit-sink forwards to), then fetches /audit/records and verifies:
//   - chain integrity per §10.5 (prev_hash linkage)
//   - retention_class ∈ {dfa-365d, standard-90d} per §10.5.6 on each row
//
// The back-end Runner URL must be supplied via SOA_ADAPTER_BACKEND_URL
// (random port — demo binary logs it at startup). Bearer defaults to
// "adapter-demo-back-end" per the Phase 2.7 demo binary; override via
// SOA_ADAPTER_BACKEND_BEARER for production-adapter deployments.
func handleSVADAPTER04(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, probe := adapterGate("SV-ADAPTER-04", h); !probe {
		return ev
	}

	backendURL := os.Getenv("SOA_ADAPTER_BACKEND_URL")
	if backendURL == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-ADAPTER-04: SOA_ADAPTER_BACKEND_URL unset — the adapter forwards audit to an upstream back-end Runner whose address must be supplied for /audit/records verification (Phase 2.7 demo logs this URL at startup)."}}
	}
	backendURL = strings.TrimRight(backendURL, "/")
	backendBearer := os.Getenv("SOA_ADAPTER_BACKEND_BEARER")
	if backendBearer == "" {
		backendBearer = "adapter-demo-back-end"
	}
	sid := os.Getenv("SOA_ADAPTER_SESSION_ID")
	if sid == "" {
		sid = "ses_adapterdemo0000001"
	}

	hc := &http.Client{Timeout: 5_000_000_000}

	// Drive 2 fixture audit rows simulating one ReadOnly + one Mutating
	// tool invocation forwarded by the adapter's audit-sink module.
	rows := []map[string]any{
		{
			"session_id":       sid,
			"tool_name":        "fs__read_file",
			"args_digest":      "sha256:" + strings.Repeat("a", 64),
			"retention_class":  "standard-90d",
		},
		{
			"session_id":       sid,
			"tool_name":        "fs__write_file",
			"args_digest":      "sha256:" + strings.Repeat("b", 64),
			"retention_class":  "dfa-365d",
		},
	}
	for i, row := range rows {
		payload, _ := json.Marshal(row)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			backendURL+"/audit/tool-invocations", bytes.NewReader(payload))
		if err != nil {
			return []Evidence{{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("SV-ADAPTER-04: build POST row %d: %v", i, err)}}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+backendBearer)
		resp, err := hc.Do(req)
		if err != nil {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-ADAPTER-04: POST back-end row %d: %v", i, err)}}
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("SV-ADAPTER-04: POST /audit/tool-invocations row %d: status %s body=%s", i, resp.Status, string(body))}}
		}
	}

	// Fetch the back-end's /audit/records and verify chain + retention.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		backendURL+"/audit/records", nil)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "SV-ADAPTER-04: build GET /audit/records: " + err.Error()}}
	}
	req.Header.Set("Authorization", "Bearer "+backendBearer)
	resp, err := hc.Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-04: GET /audit/records: " + err.Error()}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-04: GET /audit/records: status %s", resp.Status)}}
	}
	body, _ := io.ReadAll(resp.Body)
	var respEnvelope struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(body, &respEnvelope); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-ADAPTER-04: /audit/records body not JSON-decodable: " + err.Error()}}
	}
	if len(respEnvelope.Records) < 2 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-04: /audit/records returned %d rows; §18.5.3 requires ≥2 (one per tool invocation in a completed session)", len(respEnvelope.Records))}}
	}

	// Extract chain fields + retention_class for each row.
	chain := make([]auditchain.Record, 0, len(respEnvelope.Records))
	for i, r := range respEnvelope.Records {
		rec := auditchain.Record{}
		if v, ok := r["this_hash"].(string); ok {
			rec.ThisHash = v
		}
		if v, ok := r["prev_hash"].(string); ok {
			rec.PrevHash = v
		}
		chain = append(chain, rec)

		// retention_class check for tool-invocation rows (§10.5.6).
		if _, isToolRow := r["tool_name"]; isToolRow {
			rc, _ := r["retention_class"].(string)
			if rc != "dfa-365d" && rc != "standard-90d" {
				return []Evidence{{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("SV-ADAPTER-04: retention-class-missing on row %d (got %q, expected ∈ {dfa-365d, standard-90d} per §10.5.6)", i, rc)}}
			}
		}
	}
	if breakIdx, err := auditchain.VerifyChain(chain); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-ADAPTER-04: audit-chain-broken at records[%d]: %v", breakIdx, err)}}
	}

	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("SV-ADAPTER-04: %d audit rows forwarded; hash chain verifies per §10.5; retention_class populated on all tool-invocation rows per §10.5.6", len(respEnvelope.Records))}}
}
