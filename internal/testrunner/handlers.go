package testrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/crlstate"
	"github.com/wleeb1010/soa-validate/internal/digest"
	"github.com/wleeb1010/soa-validate/internal/inittrust"
	"github.com/wleeb1010/soa-validate/internal/jcs"
	"github.com/wleeb1010/soa-validate/internal/permprompt"
	"github.com/wleeb1010/soa-validate/internal/permresolve"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/toolregistry"
)

// T_ref for CRL state-machine clock injection per test-vectors/crl/README.md.
var crlRefClock = time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)

// Handler receives the shared execution context (runner client, spec locator,
// live-path gate) and returns a list of Evidence. The runner aggregates.
type Handler func(ctx context.Context, h HandlerCtx) []Evidence

type HandlerCtx struct {
	Client *runner.Client
	Spec   specvec.Locator
	Live   bool // attempt live path when true
}

// Handlers maps test IDs to their implementation.
var Handlers = map[string]Handler{
	"SV-CARD-01": handleSVCARD01,
	"SV-SIGN-01": handleSVSIGN01,
	"SV-PERM-01": handleSVPERM01,
	"HR-01":      handleHR01,
	"HR-02":      handleHR02,
	"SV-BOOT-01": handleSVBOOT01,
	"HR-12":      stub("assertions land in M1 week 5"),
	"HR-14":      stub("assertions land in M1 week 5"),
}

func stub(reason string) Handler {
	return func(ctx context.Context, h HandlerCtx) []Evidence {
		return []Evidence{{Path: PathVector, Status: StatusSkip, Message: reason}}
	}
}

// ─── SV-CARD-01 ──────────────────────────────────────────────────────────
// Agent Card shape: schema validity (vector), HTTP headers + schema (live).

func handleSVCARD01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{cardVectorCheck(h.Spec)}
	if h.Live {
		out = append(out, cardLiveCheck(ctx, h.Client, h.Spec))
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset / runner unreachable"})
	}
	return out
}

func cardVectorCheck(sv specvec.Locator) Evidence {
	card, err := sv.Read(specvec.AgentCardJSON)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	if err := agentcard.ValidateJSON(sv.Path(specvec.AgentCardSchema), card); err != nil {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: "pinned card vector fails its schema: " + err.Error()}
	}
	// JCS round-trip stability: canonicalize twice, confirm identical bytes.
	var v interface{}
	if err := json.Unmarshal(card, &v); err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: "parse card: " + err.Error()}
	}
	c1, err := jcs.Canonicalize(v)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: "canonicalize: " + err.Error()}
	}
	var v2 interface{}
	_ = json.Unmarshal(c1, &v2)
	c2, _ := jcs.Canonicalize(v2)
	if !bytes.Equal(c1, c2) {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "JCS canonical form is not idempotent"}
	}
	return Evidence{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("schema OK + JCS idempotent (%d canonical bytes)", len(c1))}
}

func cardLiveCheck(ctx context.Context, c *runner.Client, sv specvec.Locator) Evidence {
	resp, err := c.Do(ctx, http.MethodGet, "/.well-known/agent-card.json", nil)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "GET agent-card.json: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Evidence{Path: PathLive, Status: StatusFail, Message: "status " + resp.Status}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "read body: " + err.Error()}
	}
	// Schema validity.
	if err := agentcard.ValidateJSON(sv.Path(specvec.AgentCardSchema), body); err != nil {
		return Evidence{Path: PathLive, Status: StatusFail, Message: "schema: " + err.Error()}
	}
	// Cache-Control: max-age ≤ 300 (§ spec says freshness cap).
	if cc := resp.Header.Get("Cache-Control"); cc != "" {
		if max, ok := parseMaxAge(cc); ok && max > 300 {
			return Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("Cache-Control max-age=%d exceeds 300s", max)}
		}
	}
	// ETag must be present and non-empty.
	if etag := resp.Header.Get("ETag"); etag == "" {
		return Evidence{Path: PathLive, Status: StatusFail, Message: "ETag header missing"}
	}
	return Evidence{Path: PathLive, Status: StatusPass, Message: "live card validates"}
}

// parseMaxAge returns the max-age value if present in a Cache-Control header.
func parseMaxAge(cc string) (int, bool) {
	for _, part := range splitCommaTrim(cc) {
		if len(part) >= 8 && part[:8] == "max-age=" {
			if n, err := strconv.Atoi(part[8:]); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func splitCommaTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			v := trim(s[start:i])
			if v != "" {
				out = append(out, v)
			}
			start = i + 1
		}
	}
	return out
}

func trim(s string) string {
	a, b := 0, len(s)
	for a < b && (s[a] == ' ' || s[a] == '\t') {
		a++
	}
	for b > a && (s[b-1] == ' ' || s[b-1] == '\t') {
		b--
	}
	return s[a:b]
}

// ─── SV-SIGN-01 ──────────────────────────────────────────────────────────
// Agent Card JWS: structural header + detached payload, JCS-canonical
// signing input; full crypto verification deferred if placeholder sig.

func handleSVSIGN01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{signVectorCheck(h.Spec)}
	if h.Live {
		out = append(out, signLiveCheck(ctx, h.Client))
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset / runner unreachable"})
	}
	return out
}

func signVectorCheck(sv specvec.Locator) Evidence {
	jwsBytes, err := sv.Read(specvec.AgentCardJWS)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	parsed, err := agentcard.ParseJWS(jwsBytes)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "parse: " + err.Error()}
	}
	if parsed.Header.Alg != "EdDSA" {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: "alg = " + parsed.Header.Alg + ", want EdDSA"}
	}
	if parsed.Header.Typ != "soa-agent-card+jws" {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: "typ = " + parsed.Header.Typ + ", want soa-agent-card+jws"}
	}
	if parsed.Header.Kid == "" {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "kid missing"}
	}
	if !parsed.Detached {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: "expected detached JWS (empty payload segment)"}
	}
	// JCS re-canonicalize the pinned card to confirm the signing input would
	// be stable. (Full signature crypto is deferred — vector ships a
	// placeholder repeating-'0' signature.)
	card, err := sv.Read(specvec.AgentCardJSON)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	var v interface{}
	if err := json.Unmarshal(card, &v); err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: "parse card: " + err.Error()}
	}
	canonical, err := jcs.Canonicalize(v)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: "canonicalize: " + err.Error()}
	}
	msg := fmt.Sprintf("header OK (alg=EdDSA, kid=%s), detached, canonical card=%d bytes",
		parsed.Header.Kid, len(canonical))
	if agentcard.IsPlaceholderSignature(parsed.SignatureEncoded) {
		msg += "; signature is pinned placeholder (crypto verify deferred)"
	}
	return Evidence{Path: PathVector, Status: StatusPass, Message: msg}
}

func signLiveCheck(ctx context.Context, c *runner.Client) Evidence {
	resp, err := c.Do(ctx, http.MethodGet, "/.well-known/agent-card.jws", nil)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "GET agent-card.jws: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Evidence{Path: PathLive, Status: StatusFail, Message: "status " + resp.Status}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "read body: " + err.Error()}
	}
	parsed, err := agentcard.ParseJWS(body)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusFail, Message: "parse: " + err.Error()}
	}
	if parsed.Header.Alg != "EdDSA" || parsed.Header.Typ != "soa-agent-card+jws" {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("header shape: alg=%s typ=%s", parsed.Header.Alg, parsed.Header.Typ)}
	}
	return Evidence{Path: PathLive, Status: StatusPass, Message: "live jws structural check OK"}
}

// ─── SV-PERM-01 ──────────────────────────────────────────────────────────
// Permission resolver: PermissionPrompt + canonical_decision + PDA-JWS
// vector set + nonce equality + JCS-canonical decision digest.

// Spec README for the pinned vector asserts this SHA-256 of JCS(canonical-decision.json).
const pinnedDecisionDigest = "7bc890692f68b7d3b842380fcf9739f9987bf77c6cdf4c7992aac31c66fe4a8a"

func handleSVPERM01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{permVectorCheck(h.Spec)}
	if ev := permResolveOracleCheck(h.Spec); ev.Status != StatusPass {
		return append(out, ev)
	} else {
		out = append(out, ev)
	}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	out = append(out, permResolveLiveCheck(ctx, h))
	return out
}

// ─── SV-PERM-01 live path (§12.6 + §10.3.1 + §10.5.2) ─────────────────
// The test-as-spec'd requires all 24 cells (3 activeModes × 8 tools) to be
// exercisable against the running deployment. Pass criteria:
//  - All three sessions provision (requires a card with activeMode=DangerFullAccess)
//  - Every decision matches the §10.3 oracle
//  - /audit/tail this_hash is byte-identical before and after the sweep
// Any session that cannot provision → SKIP with deployment-gap diagnostic.
// Any decision mismatch → FAIL. Any audit drift → FAIL.
// Partial coverage is never reported as pass.

type sessionBootstrapResponse struct {
	SessionID        string `json:"session_id"`
	SessionBearer    string `json:"session_bearer"`
	GrantedActiveMode string `json:"granted_activeMode"`
	ExpiresAt        string `json:"expires_at"`
	RunnerVersion    string `json:"runner_version"`
}

type auditTailResponse struct {
	ThisHash            string `json:"this_hash"`
	RecordCount         int    `json:"record_count"`
	LastRecordTimestamp string `json:"last_record_timestamp,omitempty"`
	RunnerVersion       string `json:"runner_version"`
	GeneratedAt         string `json:"generated_at"`
}

type resolveResponse struct {
	Decision           string `json:"decision"`
	ResolvedControl    string `json:"resolved_control"`
	ResolvedCapability string `json:"resolved_capability"`
	Reason             string `json:"reason"`
	RunnerVersion      string `json:"runner_version"`
	ResolvedAt         string `json:"resolved_at"`
}

func permResolveLiveCheck(ctx context.Context, h HandlerCtx) Evidence {
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path needs SOA_RUNNER_BOOTSTRAP_BEARER env var set (same value the Runner was started with)"}
	}

	// 1) Load the pinned Tool Registry fixture.
	regBytes, err := h.Spec.Read(specvec.ToolRegistryJSON)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: err.Error()}
	}
	reg, err := toolregistry.Parse(regBytes)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: err.Error()}
	}

	// 2) Provision a session per capability. §10.3.1 conformance requires
	//    all three to succeed; a deployment whose Agent Card caps activeMode
	//    below DangerFullAccess cannot run the test-as-spec'd — SKIP with
	//    diagnostic, never a partial-coverage pass.
	type provisioned struct {
		cap  permresolve.Capability
		resp sessionBootstrapResponse
	}
	capsToTry := []permresolve.Capability{
		permresolve.CapReadOnly, permresolve.CapWorkspaceWrite, permresolve.CapDangerFullAccess,
	}
	var grants []provisioned
	var capDenied []permresolve.Capability
	for _, cap := range capsToTry {
		resp, status, err := postSession(ctx, h.Client, bootstrapBearer, cap)
		if err != nil {
			return Evidence{Path: PathLive, Status: StatusError, Message: fmt.Sprintf("POST /sessions (%s): %v", cap, err)}
		}
		switch status {
		case http.StatusCreated:
			if resp.GrantedActiveMode != string(cap) {
				return Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("granted_activeMode=%s, requested=%s", resp.GrantedActiveMode, cap)}
			}
			body, _ := json.Marshal(resp)
			if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SessionBootstrapResponseSchema), body); err != nil {
				return Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("session-bootstrap response schema violation (%s): %v", cap, err)}
			}
			grants = append(grants, provisioned{cap: cap, resp: resp})
		case http.StatusForbidden:
			capDenied = append(capDenied, cap)
		default:
			return Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("POST /sessions (%s) returned %d; expected 201 or 403", cap, status)}
		}
	}
	if len(grants) != 3 {
		return Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("test-as-spec'd (§10.3.1: 24 cells = 3 activeModes × 8 tools) not runnable on this deployment: %d/3 sessions provisioned; %v 403'd via §12.6 tighten-only gate (deployment's Agent Card activeMode caps below DangerFullAccess). Root-cause fix: deploy a Runner loading the DFA conformance card (test-vectors/conformance-card/) via RUNNER_CARD_FIXTURE. Refuses partial-coverage pass.", len(grants), capDenied)}
	}

	// 3) Baseline audit tail (use first grant's bearer).
	firstBearer := grants[0].resp.SessionBearer
	baseline, err := getAuditTail(ctx, h.Client, firstBearer, h.Spec)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "baseline /audit/tail: " + err.Error()}
	}

	// 4) Sweep every (tool, granted-capability) cell; assert response.decision
	//    matches the §10.3 oracle.
	sweptCells := 0
	for _, g := range grants {
		for _, tool := range reg.Tools {
			resolved, raw, status, err := getResolve(ctx, h.Client, g.resp.SessionBearer, tool.Name, g.resp.SessionID)
			if err != nil {
				return Evidence{Path: PathLive, Status: StatusError,
					Message: fmt.Sprintf("/permissions/resolve(%s,%s): %v", tool.Name, g.cap, err)}
			}
			if status != http.StatusOK {
				return Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("/permissions/resolve(%s,%s) status=%d", tool.Name, g.cap, status)}
			}
			if err := agentcard.ValidateJSON(h.Spec.Path(specvec.PermissionsResolveResponseSchema), raw); err != nil {
				return Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("/permissions/resolve response schema (%s,%s): %v", tool.Name, g.cap, err)}
			}
			want := permresolve.Resolve(
				permresolve.RiskClass(tool.RiskClass),
				permresolve.Control(tool.DefaultControl),
				g.cap, "",
			)
			if resolved.Decision != string(want) {
				return Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("%s×%s: impl=%s, oracle=%s", tool.Name, g.cap, resolved.Decision, want)}
			}
			sweptCells++
		}
	}

	// 5) Not-a-side-effect MUST — audit tail this_hash unchanged.
	after, err := getAuditTail(ctx, h.Client, firstBearer, h.Spec)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "post-sweep /audit/tail: " + err.Error()}
	}
	if after.ThisHash != baseline.ThisHash {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§10.3.1 not-a-side-effect violated: audit this_hash changed %s → %s across %d resolve queries",
				baseline.ThisHash, after.ThisHash, sweptCells)}
	}

	if sweptCells != len(reg.Tools)*len(grants) {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("cell-count mismatch: swept %d, expected %d", sweptCells, len(reg.Tools)*len(grants))}
	}
	return Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("%d cells swept (all 3 activeModes × %d tools); every decision matches §10.3 oracle; §10.5.2 not-a-side-effect MUST satisfied — audit this_hash=%s unchanged across %d queries",
			sweptCells, len(reg.Tools), baseline.ThisHash, sweptCells)}
}

func postSession(ctx context.Context, c *runner.Client, bootstrapBearer string, cap permresolve.Capability) (sessionBootstrapResponse, int, error) {
	body := map[string]string{
		"requested_activeMode": string(cap),
		"user_sub":             "soa-validate",
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", strings.NewReader(string(b)))
	if err != nil {
		return sessionBootstrapResponse{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bootstrapBearer)
	resp, err := runnerHTTP(c).Do(req)
	if err != nil {
		return sessionBootstrapResponse{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return sessionBootstrapResponse{}, resp.StatusCode, nil
	}
	var out sessionBootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return sessionBootstrapResponse{}, resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return out, resp.StatusCode, nil
}

func getAuditTail(ctx context.Context, c *runner.Client, sessionBearer string, sv specvec.Locator) (auditTailResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+"/audit/tail", nil)
	if err != nil {
		return auditTailResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+sessionBearer)
	resp, err := runnerHTTP(c).Do(req)
	if err != nil {
		return auditTailResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return auditTailResponse{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if err := agentcard.ValidateJSON(sv.Path(specvec.AuditTailResponseSchema), body); err != nil {
		return auditTailResponse{}, fmt.Errorf("schema: %w", err)
	}
	var out auditTailResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return auditTailResponse{}, fmt.Errorf("decode: %w", err)
	}
	return out, nil
}

// getResolve returns both the parsed response AND the raw bytes. Caller
// schema-validates the RAW bytes against permissions-resolve-response.schema.json
// — our struct only covers fields the handler inspects (decision, reason, etc.)
// and would lose required fields like `trace` on round-trip, producing
// spurious schema failures on the re-encoded form.
func getResolve(ctx context.Context, c *runner.Client, sessionBearer, tool, sessionID string) (resolveResponse, []byte, int, error) {
	url := fmt.Sprintf("%s/permissions/resolve?tool=%s&session_id=%s", c.BaseURL(), tool, sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return resolveResponse{}, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+sessionBearer)
	resp, err := runnerHTTP(c).Do(req)
	if err != nil {
		return resolveResponse{}, nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resolveResponse{}, raw, resp.StatusCode, nil
	}
	var out resolveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return resolveResponse{}, raw, resp.StatusCode, err
	}
	return out, raw, resp.StatusCode, nil
}

// runnerHTTP extracts the underlying http.Client for manual request building.
// We need this because runner.Client.Do always injects the client's bearer; the
// Week-3 live path needs different bearer values per endpoint (bootstrap vs session).
func runnerHTTP(c *runner.Client) *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// permResolveOracleCheck loads the pinned Tool Registry fixture, walks every
// (tool, activeMode) cell through the §10.3 oracle, and verifies the fixture
// is consistent — every tool's risk_class / default_control is one the oracle
// recognizes, the 24-cell matrix produces deterministic decisions, and the
// spec-authored expected matrix in the README matches oracle output
// (enforced separately in internal/permresolve/*_test.go). This establishes
// the validator-side decision source-of-truth the live path will assert against.
func permResolveOracleCheck(sv specvec.Locator) Evidence {
	regBytes, err := sv.Read(specvec.ToolRegistryJSON)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	reg, err := toolregistry.Parse(regBytes)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "parse tool-registry: " + err.Error()}
	}
	if len(reg.Tools) != 8 {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("pinned tool-registry has %d tools; expected 8 per §10.3.1 README matrix", len(reg.Tools))}
	}
	caps := []permresolve.Capability{
		permresolve.CapReadOnly, permresolve.CapWorkspaceWrite, permresolve.CapDangerFullAccess,
	}
	cells := 0
	for _, t := range reg.Tools {
		for _, cap := range caps {
			d := permresolve.Resolve(
				permresolve.RiskClass(t.RiskClass),
				permresolve.Control(t.DefaultControl),
				cap,
				"", // no toolRequirements overrides in the pinned fixture
			)
			// Any unexpected token (e.g., new risk_class added to fixture without
			// oracle support) surfaces as a fail — don't silently mis-classify.
			switch d {
			case permresolve.DecAutoAllow, permresolve.DecPrompt, permresolve.DecDeny,
				permresolve.DecCapabilityDenied, permresolve.DecConfigPrecedenceViolation:
				cells++
			default:
				return Evidence{Path: PathVector, Status: StatusFail,
					Message: fmt.Sprintf("oracle produced non-enum decision %q for %s×%s (fixture may have drifted beyond oracle support)", d, t.Name, cap)}
			}
		}
	}
	return Evidence{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("pinned Tool Registry fixture (8 tools) + §10.3 oracle yield %d enum-valid decision cells; oracle matches spec 24-cell matrix (asserted in permresolve unit tests)", cells)}
}

func permVectorCheck(sv specvec.Locator) Evidence {
	pb, err := sv.Read(specvec.PermissionPromptJSON)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	db, err := sv.Read(specvec.CanonicalDecisionJSON)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	jwsBytes, err := sv.Read(specvec.PDAJWS)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: err.Error()}
	}
	prompt, err := permprompt.ParsePrompt(pb)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "prompt: " + err.Error()}
	}
	decision, err := permprompt.ParseDecision(db)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "decision: " + err.Error()}
	}
	if err := permprompt.ValidateDecisionSchema(sv.Path(specvec.CanonicalDecisionSchema), db); err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "decision schema: " + err.Error()}
	}
	if err := permprompt.CheckNonceEquality(prompt, decision); err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "UV-P-18 " + err.Error()}
	}
	if err := permprompt.CheckPromptIDEquality(prompt, decision); err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: err.Error()}
	}
	// JCS-canonicalize the decision and confirm byte length + SHA-256 match
	// the spec README's published values (385 bytes / 7bc89…4a8a).
	var dv interface{}
	_ = json.Unmarshal(db, &dv)
	canon, err := jcs.Canonicalize(dv)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusError, Message: "canonicalize decision: " + err.Error()}
	}
	if len(canon) != 385 {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("JCS(decision) = %d bytes; spec README publishes 385", len(canon))}
	}
	gotDigest := digest.SHA256Hex(canon)
	if gotDigest != pinnedDecisionDigest {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("digest mismatch: got %s, spec README publishes %s", gotDigest, pinnedDecisionDigest)}
	}
	// Parse PDA-JWS structure; placeholder signature tolerated.
	pda, err := agentcard.ParseJWS(jwsBytes)
	if err != nil {
		return Evidence{Path: PathVector, Status: StatusFail, Message: "pda jws: " + err.Error()}
	}
	if pda.Header.Typ != "soa-pda+jws" {
		return Evidence{Path: PathVector, Status: StatusFail,
			Message: "PDA typ = " + pda.Header.Typ + ", want soa-pda+jws"}
	}
	msg := fmt.Sprintf("nonce eq, prompt_id eq, schema OK, JCS=%d bytes, digest matches spec (%s…), PDA typ=%s",
		len(canon), gotDigest[:8], pda.Header.Typ)
	if agentcard.IsPlaceholderSignature(pda.SignatureEncoded) {
		msg += "; PDA sig is placeholder (crypto verify deferred)"
	}
	return Evidence{Path: PathVector, Status: StatusPass, Message: msg}
}

// ─── HR-01 ──────────────────────────────────────────────────────────────
// Trust bootstrap: spec ships the initial-trust schema but no pinned trust
// bundle vectors. Negative-path assertions (malformed/missing-required/
// extra-field inputs rejected) run against inline fixtures; positive-path
// (happy bundle loaded successfully) requires a pinned vector the spec
// does not yet publish.

func handleHR01(ctx context.Context, h HandlerCtx) []Evidence {
	schemaPath := h.Spec.Path(specvec.InitialTrustSchema)

	// Inline negatives — still useful for fuzzy coverage of schema edges.
	inlineNegs := []struct{ name, body string }{
		{"empty bundle", `{}`},
		{"wrong soaHarnessVersion", `{"soaHarnessVersion":"0.9","publisher_kid":"k","spki_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issuer":"CN=x"}`},
		{"extra field", `{"soaHarnessVersion":"1.0","publisher_kid":"k","spki_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issuer":"CN=x","rogue":true}`},
		{"short spki_sha256", `{"soaHarnessVersion":"1.0","publisher_kid":"k","spki_sha256":"abc","issuer":"CN=x"}`},
	}
	for _, c := range inlineNegs {
		if err := agentcard.ValidateJSON(schemaPath, []byte(c.body)); err == nil {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("inline negative %q should have been rejected by schema", c.name)}}
		}
	}

	// Pinned positive: valid.json — must schema-validate AND semantically accept.
	validBytes, err := h.Spec.Read(specvec.InitialTrustValid)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if err := agentcard.ValidateJSON(schemaPath, validBytes); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "valid.json should validate against schema: " + err.Error()}}
	}
	validBundle, err := inittrust.Parse(validBytes)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if r := inittrust.SemanticValidate(validBundle, time.Now()); r != inittrust.ReasonAccept {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("valid.json semantic check: got reason %q, want accept", r)}}
	}

	// Pinned semantic-rejection: expired.json — MUST pass schema but MUST be
	// rejected by the post-parse clock gate with reason bootstrap-expired.
	expiredBytes, err := h.Spec.Read(specvec.InitialTrustExpired)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if err := agentcard.ValidateJSON(schemaPath, expiredBytes); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "expired.json must be schema-valid (rejection must come from semantic layer, not schema): " + err.Error()}}
	}
	expiredBundle, err := inittrust.Parse(expiredBytes)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if r := inittrust.SemanticValidate(expiredBundle, time.Now()); r != inittrust.ReasonBootstrapExpired {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("expired.json: got reason %q, want bootstrap-expired", r)}}
	}

	// Pinned schema-layer negative: channel-mismatch.json — MUST be rejected
	// by schema (closed enum on channel), NOT reach the semantic layer.
	cmBytes, err := h.Spec.Read(specvec.InitialTrustChannelMismatch)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if err := agentcard.ValidateJSON(schemaPath, cmBytes); err == nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "channel-mismatch.json should have been rejected by schema (closed enum)"}}
	}

	out := []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "positive (valid.json accepted), semantic-reject (expired.json → bootstrap-expired), schema-reject (channel-mismatch.json rejected), plus 4 inline schema negatives"}}

	if h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "HR-01 live path needs impl cold-start restart hook"})
	}
	return out
}

// ─── HR-02 ──────────────────────────────────────────────────────────────
// CRL cache state machine: same gap situation. Negative-path schema reject
// runs; fresh/stale/expired state-machine vectors require pinned CRL bundles.

func handleHR02(ctx context.Context, h HandlerCtx) []Evidence {
	schemaPath := h.Spec.Path(specvec.CRLSchema)

	// Inline schema negatives.
	inlineNegs := []struct{ name, body string }{
		{"empty CRL", `{}`},
		{"missing revoked_kids", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z"}`},
		{"extra field", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z","revoked_kids":[],"rogue":true}`},
		{"revoked_kid missing required", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z","revoked_kids":[{"kid":"k1"}]}`},
	}
	for _, c := range inlineNegs {
		if err := agentcard.ValidateJSON(schemaPath, []byte(c.body)); err == nil {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("inline negative %q should have been rejected", c.name)}}
		}
	}

	// State-machine coverage at T_ref = 2026-04-20T12:00:00Z.
	type caseSpec struct {
		name               string
		vecPath            string
		useTRef            bool
		expectState        crlstate.State
		expectAccept       bool
		expectRefresh      bool
		expectFailureCode  crlstate.Reason
	}
	cases := []caseSpec{
		{"fresh.json @ T_ref", specvec.CRLFresh, true, crlstate.StateFresh, true, false, crlstate.ReasonAccept},
		{"stale.json @ T_ref", specvec.CRLStale, true, crlstate.StateStaleButValid, true, true, crlstate.ReasonAccept},
		{"expired.json (any clock)", specvec.CRLExpired, false, crlstate.StateExpired, false, false, crlstate.ReasonCRLExpired},
	}
	for _, c := range cases {
		body, err := h.Spec.Read(c.vecPath)
		if err != nil {
			return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
		}
		if err := agentcard.ValidateJSON(schemaPath, body); err != nil {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("%s must be schema-valid: %v", c.name, err)}}
		}
		crl, err := crlstate.Parse(body)
		if err != nil {
			return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
		}
		now := crlRefClock
		if !c.useTRef {
			now = time.Now()
		}
		got := crlstate.Classify(crl, now)
		if got.State != c.expectState {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("%s: state = %s, want %s", c.name, got.State, c.expectState)}}
		}
		if got.Accept != c.expectAccept {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("%s: accept = %v, want %v", c.name, got.Accept, c.expectAccept)}}
		}
		if got.RefreshNeeded != c.expectRefresh {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("%s: refresh-queued = %v, want %v", c.name, got.RefreshNeeded, c.expectRefresh)}}
		}
		if got.FailureReason != c.expectFailureCode {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("%s: failure_reason = %q, want %q", c.name, got.FailureReason, c.expectFailureCode)}}
		}
	}

	out := []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "3 state-machine cases @ T_ref=2026-04-20T12:00:00Z (fresh=accept+no-refresh, stale=accept+refresh-queued, expired=fail-closed/crl-expired) + 4 inline schema negatives"}}

	if h.Live {
		out = append(out, hr02LiveCheck(ctx, h.Client))
	}
	return out
}

// hr02LiveCheck observes the Runner's CRL cache through /ready: per impl's
// Week 2 wiring, /ready=200 means the boot orchestrator has a CRL in one of
// the accept states (fresh or stale-but-valid); /ready=503 with closed-enum
// reason `crl-expired` means expired. Exercising the full three-state
// transition live requires orchestrating Runner restarts with RUNNER_TEST_CLOCK
// set to a controlled instant — that's CI-level orchestration, not a single
// validator invocation.
func hr02LiveCheck(ctx context.Context, c *runner.Client) Evidence {
	resp, err := c.Do(ctx, http.MethodGet, "/ready", nil)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: "GET /ready: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return Evidence{Path: PathLive, Status: StatusPass,
			Message: "/ready=200 — CRL cache in accept state (fresh or stale-but-valid); stale/expired transitions require orchestrated Runner restart with RUNNER_TEST_CLOCK"}
	case http.StatusServiceUnavailable:
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/ready=503 — Runner degraded; body=%s", string(body))}
	default:
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/ready returned unexpected %s", resp.Status)}
	}
}

// ─── SV-BOOT-01 ─────────────────────────────────────────────────────────
// Boot-time verification. Live-only per plan: needs impl's /health + /ready
// probes plus a cold-start simulation. Reports whatever is actually present.

func handleSVBOOT01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only test per plan; no vector work"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_URL unset"})
		return out
	}
	hErr := h.Client.Health(ctx)
	rErr := h.Client.Ready(ctx)
	switch {
	case hErr == nil && rErr == nil:
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "/health + /ready both respond; cold-start simulation deferred until impl exposes restart hook"})
	case hErr != nil && rErr != nil:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "neither /health nor /ready respond (impl has not shipped §5.4 probes)"})
	default:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§5.4 probe partial: health=%v ready=%v", errOrOK(hErr), errOrOK(rErr))})
	}
	return out
}

func errOrOK(e error) string {
	if e == nil {
		return "ok"
	}
	return e.Error()
}
