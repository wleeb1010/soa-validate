package testrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/auditchain"
	"github.com/wleeb1010/soa-validate/internal/crlstate"
	"github.com/wleeb1010/soa-validate/internal/digest"
	"github.com/wleeb1010/soa-validate/internal/inittrust"
	"github.com/wleeb1010/soa-validate/internal/jcs"
	"github.com/wleeb1010/soa-validate/internal/permprompt"
	"github.com/wleeb1010/soa-validate/internal/permresolve"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/subprocrunner"
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
	"SV-CARD-01":       handleSVCARD01,
	"SV-SIGN-01":       handleSVSIGN01,
	"SV-PERM-01":       handleSVPERM01,
	"HR-01":            handleHR01,
	"HR-02":            handleHR02, // bypassed — must-map marks M3-deferred
	"SV-BOOT-01":       handleSVBOOT01,
	"HR-12":            handleHR12,
	"SV-SESS-BOOT-01":  handleSVSESSBOOT01,
	"SV-SESS-BOOT-02":  handleSVSESSBOOT02,
	"SV-AUDIT-TAIL-01": handleSVAUDITTAIL01,
	"SV-PERM-20":          handleSVPERM20,
	"SV-PERM-21":          handleSVPERM21,
	"SV-PERM-22":          handleSVPERM22,
	"HR-14":               handleHR14,
	"SV-AUDIT-RECORDS-01": handleSVAUDITRECORDS01,
	"SV-AUDIT-RECORDS-02": handleSVAUDITRECORDS02,
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

// ─── SV-SESS-BOOT-01 ─────────────────────────────────────────────────────
// POST /sessions under each of three activeMode values against a DFA-capable
// deployment; 201 body schema-validates; granted_activeMode == requested;
// session_id + session_bearer shapes meet schema patterns.

func handleSVSESSBOOT01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "no pinned vector for this test — POST /sessions is an endpoint-behavior assertion"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set in shell"})
		return out
	}
	caps := []permresolve.Capability{
		permresolve.CapReadOnly, permresolve.CapWorkspaceWrite, permresolve.CapDangerFullAccess,
	}
	for _, cap := range caps {
		resp, status, err := postSession(ctx, h.Client, bearer, cap)
		if err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("POST /sessions(%s): %v", cap, err)})
			return out
		}
		if status != http.StatusCreated {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("POST /sessions(%s) status=%d; expected 201 against DFA card", cap, status)})
			return out
		}
		body, _ := json.Marshal(resp)
		if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SessionBootstrapResponseSchema), body); err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("session-bootstrap response schema (%s): %v", cap, err)})
			return out
		}
		if resp.GrantedActiveMode != string(cap) {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("requested %s, granted %s", cap, resp.GrantedActiveMode)})
			return out
		}
		if !strings.HasPrefix(resp.SessionID, "ses_") || len(resp.SessionID) < 20 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("session_id %q fails schema pattern ^ses_[A-Za-z0-9]{16,}$", resp.SessionID)})
			return out
		}
		if len(resp.SessionBearer) < 32 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("session_bearer length %d < minLength 32", len(resp.SessionBearer))})
			return out
		}
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "3 sessions provisioned (RO, WW, DFA) against DFA card; all 201 bodies schema-valid; granted == requested; ids + bearers meet shape constraints"})
	return out
}

// ─── SV-SESS-BOOT-02 ─────────────────────────────────────────────────────
// Tighten-only 403: against a Runner loaded with the DEFAULT ReadOnly card,
// POST /sessions with requested_activeMode=DangerFullAccess MUST 403 with
// reason=ConfigPrecedenceViolation.

func handleSVSESSBOOT02(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "pure impl-behavior assertion; no vector evidence"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	// Probe the running Runner's card; only execute if it's a ReadOnly card.
	// The current deployment serves the DFA conformance card, so this skips
	// with a precise diagnostic rather than firing against the wrong card.
	resp, err := h.Client.Do(ctx, http.MethodGet, "/.well-known/agent-card.json", nil)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var card struct {
		Permissions struct {
			ActiveMode string `json:"activeMode"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(body, &card); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "parse card: " + err.Error()})
		return out
	}
	if card.Permissions.ActiveMode != "ReadOnly" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("running Runner serves card with activeMode=%s; this test requires a Runner configured with the default test-vectors/agent-card.json (activeMode=ReadOnly). Needs either a second Runner instance or subprocess-invocation harness.", card.Permissions.ActiveMode)})
		return out
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}
	_, status, err := postSession(ctx, h.Client, bearer, permresolve.CapDangerFullAccess)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if status != http.StatusForbidden {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("POST /sessions(DFA) against ReadOnly card returned %d; expected 403 per §12.6", status)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "ReadOnly card + requested DFA → 403 per §12.6 tighten-only gate"})
	return out
}

// ─── SV-AUDIT-TAIL-01 ────────────────────────────────────────────────────
// Spec §10.5.2 MUST:
//   - Empty log: this_hash == "GENESIS", last_record_timestamp OMITTED
//   - Non-empty log: this_hash is 64-char lowercase hex
//   - Read MUST NOT append a meta-record (not-a-side-effect): two
//     back-to-back reads report identical hash + record_count
// Handler asserts whichever branch applies to the Runner's current state.

var hex64Re = regexp.MustCompile(`^[a-f0-9]{64}$`)

func handleSVAUDITTAIL01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only test per spec §10.5.2 (endpoint-behavior assertion)"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}
	sess, status, err := postSession(ctx, h.Client, bearer, permresolve.CapReadOnly)
	if err != nil || status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("provisioning session for audit-tail read: status=%d err=%v", status, err)})
		return out
	}

	raw1, err := getAuditTailRaw(ctx, h.Client, sess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "GET /audit/tail (1): " + err.Error()})
		return out
	}
	var tail1 auditTailResponse
	if err := json.Unmarshal(raw1, &tail1); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}

	hasLastTs := bytes.Contains(raw1, []byte(`"last_record_timestamp"`))

	switch {
	case tail1.ThisHash == "GENESIS":
		if tail1.RecordCount != 0 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("this_hash=GENESIS but record_count=%d; expected 0", tail1.RecordCount)})
			return out
		}
		if hasLastTs {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: "empty log but last_record_timestamp present; spec §10.5.2 requires OMITTED on empty log"})
			return out
		}
	case hex64Re.MatchString(tail1.ThisHash):
		if tail1.RecordCount < 1 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("non-GENESIS this_hash but record_count=%d; expected ≥1", tail1.RecordCount)})
			return out
		}
		if !hasLastTs {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: "non-empty log but last_record_timestamp omitted; spec §10.5.2 requires it present"})
			return out
		}
	default:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("this_hash=%q does not match 'GENESIS' or ^[a-f0-9]{64}$", tail1.ThisHash)})
		return out
	}

	// Not-a-side-effect: two back-to-back reads must agree on hash+count.
	raw2, err := getAuditTailRaw(ctx, h.Client, sess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "GET /audit/tail (2): " + err.Error()})
		return out
	}
	var tail2 auditTailResponse
	_ = json.Unmarshal(raw2, &tail2)
	if tail2.ThisHash != tail1.ThisHash || tail2.RecordCount != tail1.RecordCount {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("two-read regression: hash/count drifted (hash %s→%s, count %d→%d)",
				tail1.ThisHash, tail2.ThisHash, tail1.RecordCount, tail2.RecordCount)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("state-adaptive: this_hash=%s, record_count=%d, last_record_timestamp %s; two-read idempotence holds",
			summarizeHash(tail1.ThisHash), tail1.RecordCount,
			func() string { if hasLastTs { return "present" }; return "omitted" }())})
	return out
}

func summarizeHash(h string) string {
	if h == "GENESIS" {
		return "GENESIS"
	}
	if len(h) >= 8 {
		return h[:8] + "…"
	}
	return h
}

func getAuditTailRaw(ctx context.Context, c *runner.Client, sessionBearer string, sv specvec.Locator) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+"/audit/tail", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+sessionBearer)
	resp, err := runnerHTTP(c).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := agentcard.ValidateJSON(sv.Path(specvec.AuditTailResponseSchema), raw); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return raw, nil
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

// ─── SV-BOOT-01 (with V-12 negative-arm scaffold) ─────────────────────
// Spec §5.3: SDK-pinned bootstrap channel. When declared, Runner refuses
// any Agent Card whose security.trustAnchors[].publisher_kid does not
// match the SDK-pinned value, emitting HostHardeningInsufficient
// (reason=bootstrap-missing).
//
// Current /health + /ready check (positive live evidence) carries the
// happy-path assertion. Negative-arm subprocess scaffold (V-12) — three
// fixture invocations of impl with controlled RUNNER_INITIAL_TRUST env
// var — gates on impl T-07 (RUNNER_INITIAL_TRUST shipping) plus the
// validator harness having SOA_IMPL_BIN set.

func handleSVBOOT01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only test per plan"}}
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
			Message: "/health + /ready both respond; positive happy-path live arm satisfied. V-12 negative-arm scaffold (subprocess-launched impl with broken trust fixtures: expired.json, channel-mismatch.json, mismatched-pub-kid.json → HostHardeningInsufficient) waits on impl T-07 (RUNNER_INITIAL_TRUST env-var support) + SOA_IMPL_BIN; subprocrunner package ready."})
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

// ─── SV-PERM-20 / SV-PERM-21 / SV-PERM-22 ─────────────────────────────
// POST /permissions/decisions (§10.3.2). Requires a pre-enrolled demo
// session with canDecide=true until T-03 (request_decide_scope) ships;
// shared via SOA_IMPL_DEMO_SESSION env var as "<session_id>:<bearer>".

type permissionDecisionRequest struct {
	Tool       string  `json:"tool"`
	SessionID  string  `json:"session_id"`
	ArgsDigest string  `json:"args_digest"`
	PDA        *string `json:"pda,omitempty"`
}

type permissionDecisionResponse struct {
	Decision           string `json:"decision"`
	ResolvedCapability string `json:"resolved_capability"`
	ResolvedControl    string `json:"resolved_control"`
	Reason             string `json:"reason"`
	AuditRecordID      string `json:"audit_record_id"`
	AuditThisHash      string `json:"audit_this_hash"`
	HandlerAccepted    bool   `json:"handler_accepted"`
	RunnerVersion      string `json:"runner_version"`
	RecordedAt         string `json:"recorded_at"`
}

func parseDemoSession() (sid, bearer string, ok bool) {
	raw := os.Getenv("SOA_IMPL_DEMO_SESSION")
	if raw == "" {
		return "", "", false
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func postDecision(ctx context.Context, c *runner.Client, bearer string, req permissionDecisionRequest) (permissionDecisionResponse, []byte, int, error) {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/permissions/decisions", bytes.NewReader(body))
	if err != nil {
		return permissionDecisionResponse{}, nil, 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+bearer)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := runnerHTTP(c).Do(httpReq)
	if err != nil {
		return permissionDecisionResponse{}, nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return permissionDecisionResponse{}, raw, resp.StatusCode, nil
	}
	var out permissionDecisionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return permissionDecisionResponse{}, raw, resp.StatusCode, err
	}
	return out, raw, resp.StatusCode, nil
}

func handleSVPERM20(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.3.2"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrap := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrap == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}
	demoSid, demoBearer, ok := parseDemoSession()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_DEMO_SESSION (<sid>:<bearer>) not set; needed for the pre-enrolled canDecide session until T-03 ships"})
		return out
	}

	before, err := getAuditTail(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "pre-decision GET /audit/tail: " + err.Error()})
		return out
	}
	req := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  demoSid,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	dec, rawResp, status, err := postDecision(ctx, h.Client, demoBearer, req)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "POST /permissions/decisions: " + err.Error()})
		return out
	}
	if status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("positive POST /permissions/decisions status=%d; expected 201; body=%s", status, string(rawResp))})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path("schemas/permission-decision-response.schema.json"), rawResp); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "decision response schema: " + err.Error()})
		return out
	}
	want := permresolve.Resolve(permresolve.RiskReadOnly, permresolve.CtrlAutoAllow, permresolve.CapDangerFullAccess, "")
	if dec.Decision != string(want) {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("forgery-resistance: impl decision=%s, oracle=%s", dec.Decision, want)})
		return out
	}
	after, err := getAuditTail(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "post-decision GET /audit/tail: " + err.Error()})
		return out
	}
	if after.RecordCount != before.RecordCount+1 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("record_count delta=%d; expected exactly 1 (%d -> %d)", after.RecordCount-before.RecordCount, before.RecordCount, after.RecordCount)})
		return out
	}
	if after.ThisHash != dec.AuditThisHash {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("audit_this_hash mismatch: decision response=%s, tail after=%s", dec.AuditThisHash, after.ThisHash)})
		return out
	}

	// Auth-negative #1: fresh session without decide scope → insufficient-scope.
	sess, sStatus, err := postSession(ctx, h.Client, bootstrap, permresolve.CapReadOnly)
	if err != nil || sStatus != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "auth-neg provision session: " + fmt.Sprintf("status=%d err=%v", sStatus, err)})
		return out
	}
	negReq1 := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  sess.SessionID,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	_, raw1, st1, err := postDecision(ctx, h.Client, sess.SessionBearer, negReq1)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "neg-1 POST: " + err.Error()})
		return out
	}
	if r := extractReason(raw1); st1 != http.StatusForbidden || r != "insufficient-scope" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("auth-neg insufficient-scope: status=%d reason=%q (want 403+insufficient-scope; body=%s)", st1, r, string(raw1))})
		return out
	}

	// Auth-negative #2: demo bearer (valid for demoSid) with a body
	// session_id that DOES NOT match → 403 reason=session-bearer-mismatch.
	// Use sess.SessionID (the fresh RO session) as the mismatched id.
	negReq2 := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  sess.SessionID, // different from demoSid → mismatch
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	_ = demoSid
	_, raw2, st2, err := postDecision(ctx, h.Client, demoBearer, negReq2)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "neg-2 POST: " + err.Error()})
		return out
	}
	if r := extractReason(raw2); st2 != http.StatusForbidden || r != "session-bearer-mismatch" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("auth-neg session-bearer-mismatch: status=%d reason=%q (want 403+session-bearer-mismatch; body=%s)", st2, r, string(raw2))})
		return out
	}

	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("positive: decision=%s matches §10.3 oracle, schema-valid, +1 audit record (%d→%d), audit_this_hash=%s matches tail; negatives: fresh-session-without-decide-scope → 403 insufficient-scope; demo-bearer-with-wrong-session-id → 403 session-bearer-mismatch (both L-22 enum). pda-decision-mismatch variant skipped on this deployment (reaches 503 pda-verify-unavailable before mismatch logic — PDA verify unwired; see SV-PERM-22).",
			dec.Decision, before.RecordCount, after.RecordCount, summarizeHash(dec.AuditThisHash))})
	return out
}

// ─── HR-12 (V-09) ─────────────────────────────────────────────────────
// Tampered Card bytes → CardInvalid; Runner fails closed at boot.
// Live exercise via subprocess: spawn impl with RUNNER_CARD_JWS pointing
// at a tampered fixture and assert non-zero exit OR /ready never flips.
//
// Two prerequisites stack:
//   - SOA_IMPL_BIN env var: command line to launch impl (e.g.
//     "node ../soa-harness-impl/packages/runner/dist/bin/start-runner.js")
//   - Impl must accept RUNNER_CARD_JWS env var (T-06; not yet shipped)
//
// When SOA_IMPL_BIN is set but T-06 isn't shipped, the harness runs a
// "happy regression" only — spawns the impl with normal env, confirms
// it boots clean. Doesn't assert the tampered branch (would need T-06).
//
// When neither is available, honest skip with the precise diagnostic.

func handleHR12(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only test per spec §15.5 (subprocess-driven boot-time tamper detection)"}}
	bin := os.Getenv("SOA_IMPL_BIN")
	if bin == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_BIN not set; HR-12 needs to subprocess-launch impl with controlled env. Set SOA_IMPL_BIN='node <path-to-start-runner.js>' (and SOA_IMPL_TEST_PORT to avoid clashing with the running impl). Full tamper assertion additionally requires impl T-06 (RUNNER_CARD_JWS env-var support)."})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
		Message: "impl T-06 not yet shipped (RUNNER_CARD_JWS env-var). Subprocess harness ready (internal/subprocrunner); will switch from skip to PASS the moment T-06 lands. Happy-path regression run available — set SOA_IMPL_HR12_REGRESSION=1 to confirm impl still boots clean under default env (no tamper)."})
	return out
}

// runHappyRegression is exposed for V-09's "expected to succeed" boot
// regression check. Not wired into the test runner by default — the
// scoreboard stays honest about HR-12 being a tamper-detect test that
// can't fire its full assertion without T-06. Callers invoke this
// helper to smoke the subprocess-spawn machinery against current impl.
func runHappyRegression(ctx context.Context, bin string, args []string, env map[string]string, port int) subprocrunner.Result {
	return subprocrunner.Spawn(ctx, subprocrunner.Config{
		Bin:     bin,
		Args:    args,
		Env:     env,
		Timeout: 15 * time.Second,
		ReadinessProbe: func(probeCtx context.Context) error {
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet,
				fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
			resp, err := (&http.Client{Timeout: 1 * time.Second}).Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return nil
		},
		PollInterval: 250 * time.Millisecond,
	})
}

// extractReason returns the canonical reason string from a decisions-endpoint
// error body. Falls back to the "error" field when "reason" is absent.
func extractReason(raw []byte) string {
	var b struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(raw, &b)
	if b.Reason != "" {
		return b.Reason
	}
	return b.Error
}

func handleSVPERM21(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{
		{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.3.2+§6.1.1"},
		{Path: PathLive, Status: StatusSkip,
			Message: "requires a valid PDA-JWS signed by a handler key chained to the Runners security.trustAnchors. Validator has no PDA-signing fixture yet; needs either (a) spec to ship a signed PDA vector whose trust anchor the Runner can be configured to accept, or (b) validator to gain a signing identity the Runner is configured to trust. Honest skip until the fixture/design decision is made."},
	}
}

func handleSVPERM22(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.3.2+§6.1.1"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	demoSid, demoBearer, ok := parseDemoSession()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_DEMO_SESSION not set; positive path needs the pre-enrolled canDecide session"})
		return out
	}

	before, err := getAuditTail(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "pre GET /audit/tail: " + err.Error()})
		return out
	}
	bogus := "not.a.real.jws"
	req := permissionDecisionRequest{
		Tool:       "net__http_get",
		SessionID:  demoSid,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		PDA:        &bogus,
	}
	dec, raw, status, err := postDecision(ctx, h.Client, demoBearer, req)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "POST /permissions/decisions: " + err.Error()})
		return out
	}
	// Spec §10.3.2 L-23 branch: Runner deployed without resolvePdaVerifyKey
	// MUST return 503 + {error,reason}=pda-verify-unavailable. This is an
	// ASSERTABLE spec conformance check — the endpoint's behavior under
	// "verify unavailable" state is pinned.
	if status == http.StatusServiceUnavailable {
		var body struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &body)
		if body.Error == "pda-verify-unavailable" && body.Reason == "pda-verify-unavailable" {
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "Runner without PDA verify config correctly returns 503 error=pda-verify-unavailable reason=pda-verify-unavailable per §10.3.2 L-23. crypto-invalid-PDA + structural-mismatch branches of SV-PERM-22 not exercised on this deployment (would require Runner with resolvePdaVerifyKey injection); deployment-misconfig branch asserted."})
			return out
		}
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("503 body error=%q reason=%q; §10.3.2 L-23 requires both to equal 'pda-verify-unavailable'", body.Error, body.Reason)})
		return out
	}
	// Legacy non-conformant path — flag it rather than silently accept.
	if status == http.StatusBadRequest {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("400 %s; §10.3.2 L-23 (pin 1971e87) requires 503 pda-verify-unavailable, not 400. Impl has not adopted the rename on this Runner.", string(raw))})
		return out
	}
	// Two spec-permitted paths depending on impl ordering:
	// - 201 decision=Deny handler_accepted=false reason=pda-verify-failed (crypto-first) + audited
	// - 403 reason=pda-malformed (structural-first; also in L-22 enum)
	switch status {
	case http.StatusCreated:
		if err := agentcard.ValidateJSON(h.Spec.Path("schemas/permission-decision-response.schema.json"), raw); err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "response schema: " + err.Error()})
			return out
		}
		if dec.Decision != "Deny" || dec.HandlerAccepted || dec.Reason != "pda-verify-failed" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("crypto-invalid PDA: decision=%s handler_accepted=%v reason=%q; spec requires Deny/false/pda-verify-failed", dec.Decision, dec.HandlerAccepted, dec.Reason)})
			return out
		}
		after, _ := getAuditTail(ctx, h.Client, demoBearer, h.Spec)
		if after.RecordCount != before.RecordCount+1 {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("crypto-invalid PDA attempt MUST audit per §10.3.2; record_count delta=%d, expected 1", after.RecordCount-before.RecordCount)})
			return out
		}
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "crypto-invalid PDA -> 201 decision=Deny handler_accepted=false reason=pda-verify-failed; attempt audited (+1 record). decision-mismatch variant skipped (requires valid PDA construction; see SV-PERM-21 skip)."})
	case http.StatusForbidden:
		var body struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &body)
		reason := body.Reason
		if reason == "" {
			reason = body.Error
		}
		if reason != "pda-malformed" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("structural-first 403 reason=%q; L-22 enum requires pda-malformed", reason)})
			return out
		}
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "malformed PDA rejected structurally: 403 reason=pda-malformed (L-22 enum). Impl chose structural-first over crypto-first; both are spec-permitted. Well-formed-JWS-with-bad-signature variant skipped (requires signing-fixture setup)."})
	default:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("unexpected status %d; expected 201(pda-verify-failed) or 403(pda-malformed); body=%s", status, string(raw))})
	}
	return out
}

// ─── SV-AUDIT-RECORDS-01 / SV-AUDIT-RECORDS-02 ───────────────────────────
// GET /audit/records (§10.5.3). Paginated; each page schema-validates;
// records in chain order (earliest first). Handlers SKIP honestly when
// the endpoint is 404 (T-01 not shipped) with a precise diagnostic.

type auditRecordsResponse struct {
	Records       []auditchain.Record `json:"records"`
	HasMore       bool                `json:"has_more"`
	NextAfter     string              `json:"next_after,omitempty"`
	RunnerVersion string              `json:"runner_version"`
	GeneratedAt   string              `json:"generated_at"`
}

func getAuditRecordsPage(ctx context.Context, c *runner.Client, bearer, after string, limit int) (auditRecordsResponse, []byte, int, error) {
	u := c.BaseURL() + "/audit/records"
	first := true
	addQ := func(k, v string) {
		if first {
			u += "?"
			first = false
		} else {
			u += "&"
		}
		u += k + "=" + v
	}
	if after != "" {
		addQ("after", after)
	}
	if limit > 0 {
		addQ("limit", strconv.Itoa(limit))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return auditRecordsResponse{}, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := runnerHTTP(c).Do(req)
	if err != nil {
		return auditRecordsResponse{}, nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return auditRecordsResponse{}, raw, resp.StatusCode, nil
	}
	var out auditRecordsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return auditRecordsResponse{}, raw, resp.StatusCode, err
	}
	return out, raw, resp.StatusCode, nil
}

// collectAllRecords walks /audit/records pagination to completion.
// Returns the full ordered slice plus a trace of each page size.
func collectAllRecords(ctx context.Context, c *runner.Client, bearer string, sv specvec.Locator) ([]auditchain.Record, []int, int, error) {
	var all []auditchain.Record
	var pageSizes []int
	after := ""
	for i := 0; i < 100; i++ { // safety cap: absurd ceiling
		page, raw, status, err := getAuditRecordsPage(ctx, c, bearer, after, 0)
		if err != nil {
			return nil, nil, status, err
		}
		if status != http.StatusOK {
			return nil, nil, status, fmt.Errorf("page %d: status %d body=%s", i, status, string(raw))
		}
		if err := agentcard.ValidateJSON(sv.Path(specvec.AuditRecordsResponseSchema), raw); err != nil {
			return nil, nil, status, fmt.Errorf("page %d schema: %w", i, err)
		}
		pageSizes = append(pageSizes, len(page.Records))
		all = append(all, page.Records...)
		if !page.HasMore {
			return all, pageSizes, http.StatusOK, nil
		}
		if page.NextAfter == "" {
			return nil, nil, status, fmt.Errorf("page %d has_more=true but next_after empty", i)
		}
		after = page.NextAfter
	}
	return nil, nil, 0, fmt.Errorf("pagination did not terminate after 100 pages")
}

func handleSVAUDITRECORDS01(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.5.3"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	_, demoBearer, ok := parseDemoSession()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_DEMO_SESSION not set"})
		return out
	}
	// Probe endpoint existence first.
	_, _, status, _ := getAuditRecordsPage(ctx, h.Client, demoBearer, "", 0)
	if status == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /audit/records → 404; impl has not shipped T-01 yet (§10.5.3 endpoint pending). Handler code ready; auto-flips to full assertion when T-01 lands."})
		return out
	}
	all, pageSizes, _, err := collectAllRecords(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "collect pages: " + err.Error()})
		return out
	}
	// Chain ordering: timestamps non-decreasing (earliest first is the spec
	// requirement; pagination follows the same order).
	for i := 1; i < len(all); i++ {
		if all[i-1].Timestamp > all[i].Timestamp {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("chain-order violation at records[%d]: timestamp %s < %s", i, all[i].Timestamp, all[i-1].Timestamp)})
			return out
		}
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("walked %d pages (sizes=%v); %d records total; schema-valid on every page; chain order (earliest→latest) holds", len(pageSizes), pageSizes, len(all))})
	return out
}

func handleSVAUDITRECORDS02(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.5.3+§10.5"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	_, demoBearer, ok := parseDemoSession()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_DEMO_SESSION not set"})
		return out
	}
	_, _, status, _ := getAuditRecordsPage(ctx, h.Client, demoBearer, "", 0)
	if status == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /audit/records → 404; impl has not shipped T-01. Chain-integrity assertion ready; fires when T-01 lands."})
		return out
	}
	all, _, _, err := collectAllRecords(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if len(all) == 0 {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "chain is empty (no records on this Runner yet); SV-AUDIT-RECORDS-02 needs ≥1 record to assert. Drive records via SOA_DRIVE_AUDIT_RECORDS=N."})
		return out
	}
	if brk, err := auditchain.VerifyChain(all); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("chain break at index %d: %v", brk, err)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§10.5 chain integrity holds across %d records: records[0].prev_hash=GENESIS; for all i>0 records[i].prev_hash==records[i-1].this_hash", len(all))})
	return out
}

// ─── HR-14 ────────────────────────────────────────────────────────────────
// Audit hash chain — any prev_hash tamper MUST fail chain verification.
// Live: read chain, verify, tamper locally, re-verify, assert failure at
// exact break index. Pure validator-side mutation — no state written to
// the Runner.

func handleHR14(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §15.5"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	_, demoBearer, ok := parseDemoSession()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_DEMO_SESSION not set"})
		return out
	}
	_, _, status, _ := getAuditRecordsPage(ctx, h.Client, demoBearer, "", 0)
	if status == http.StatusNotFound {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "GET /audit/records → 404; impl has not shipped T-01. Chain-tamper assertion ready; fires when T-01 lands."})
		return out
	}
	all, _, _, err := collectAllRecords(ctx, h.Client, demoBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if len(all) < 3 {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("chain has %d records; HR-14 needs ≥3 so the tamper index is mid-chain. Drive more via SOA_DRIVE_AUDIT_RECORDS=N.", len(all))})
		return out
	}
	// Baseline: chain must verify first.
	if brk, err := auditchain.VerifyChain(all); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("pre-tamper chain invalid at index %d: %v", brk, err)})
		return out
	}
	// Tamper at mid-chain.
	target := len(all) / 2
	tampered := auditchain.Tamper(all, target)
	brk, err := auditchain.VerifyChain(tampered)
	if err == nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "tamper at mid-chain did not trigger chain-verify failure; §15.5 violated"})
		return out
	}
	if brk != target {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("tamper at index %d detected at %d instead; break index must match exactly", target, brk)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("live chain of %d records verifies; tampered records[%d].prev_hash → VerifyChain flags break at exactly index %d per §15.5", len(all), target, target)})
	return out
}
