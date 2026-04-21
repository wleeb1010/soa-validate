package testrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

	// M2 Week 1 — tool-pool classification + audit-sink state machine + state observability.
	"SV-SESS-05":              handleSVSESS05,
	"SV-SESS-11":              handleSVSESS11,
	"SV-PERM-19":              handleSVPERM19,
	"SV-AUDIT-SINK-EVENTS-01": handleSVAUDITSINKEVENTS01,
	"SV-SESS-STATE-01":        handleSVSESSSTATE01,

	// M2 Week 3 (V2-09b/c) — atomic-write + resume-algorithm crash conformance.
	"SV-SESS-06": handleSVSESS06,
	"SV-SESS-07": handleSVSESS07,
	"SV-SESS-08": handleSVSESS08,
	"SV-SESS-09": handleSVSESS09,
	"SV-SESS-10": handleSVSESS10,

	// M2 Week 2 (V2-06 + V2-07 + V2-08) — crash-recovery via /state +
	// bracket-persist + idempotency key continuity. Scaffolded against
	// M2-T2 (resume algorithm) — flip as impl ships T-2.
	"HR-04":      handleHR04,
	"HR-05":      handleHR05,
	"SV-SESS-03": handleSVSESS03,
	"SV-SESS-04": handleSVSESS04,

	// M2 Week 3 baseline (V2-09a) — /state schema + session-file refusal.
	"SV-SESS-01": handleSVSESS01,
	"SV-SESS-02": handleSVSESS02,
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
	return postSessionWithScope(ctx, c, bootstrapBearer, cap, false)
}

// postSessionWithScope adds the T-03 request_decide_scope flag. When true,
// the returned bearer carries permissions:decide:<sid> in addition to the
// always-granted scopes.
//
// Bootstrap-bearer rate limit handling: impl rate-limits POST /sessions at
// 30/min per bootstrap bearer. The test suite cumulatively mints ~17+
// sessions across handlers; bursts can saturate. On 429, this helper
// reads Retry-After, sleeps secs+1, and retries (single retry — if it
// hits 429 again the caller sees it).
func postSessionWithScope(ctx context.Context, c *runner.Client, bootstrapBearer string, cap permresolve.Capability, requestDecideScope bool) (sessionBootstrapResponse, int, error) {
	body := map[string]interface{}{
		"requested_activeMode": string(cap),
		"user_sub":             "soa-validate",
	}
	if requestDecideScope {
		body["request_decide_scope"] = true
	}
	b, _ := json.Marshal(body)
	doOnce := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", strings.NewReader(string(b)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bootstrapBearer)
		return runnerHTTP(c).Do(req)
	}
	resp, err := doOnce()
	if err != nil {
		return sessionBootstrapResponse{}, 0, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		secs, _ := strconv.Atoi(retryAfter)
		if secs <= 0 {
			secs = 5
		}
		time.Sleep(time.Duration(secs+1) * time.Second)
		resp, err = doOnce()
		if err != nil {
			return sessionBootstrapResponse{}, 0, err
		}
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
	// For each capability, run a request_decide_scope round-trip:
	//   - mint session with decide=true → bearer MUST authorize
	//     POST /permissions/decisions (observable: 201)
	//   - mint session with decide omitted/false → bearer MUST NOT
	//     authorize (observable: 403 reason=insufficient-scope)
	// Confirms the scope grant is independent of capability.
	for _, cap := range caps {
		for _, decide := range []bool{true, false} {
			resp, status, err := postSessionWithScope(ctx, h.Client, bearer, cap, decide)
			if err != nil || status != http.StatusCreated {
				out = append(out, Evidence{Path: PathLive, Status: StatusError,
					Message: fmt.Sprintf("POST /sessions(%s, decide=%v): status=%d err=%v", cap, decide, status, err)})
				return out
			}
			body, _ := json.Marshal(resp)
			if err := agentcard.ValidateJSON(h.Spec.Path(specvec.SessionBootstrapResponseSchema), body); err != nil {
				out = append(out, Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("session-bootstrap response schema (%s, decide=%v): %v", cap, decide, err)})
				return out
			}
			if resp.GrantedActiveMode != string(cap) {
				out = append(out, Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("requested %s, granted %s", cap, resp.GrantedActiveMode)})
				return out
			}
			if !strings.HasPrefix(resp.SessionID, "ses_") || len(resp.SessionID) < 20 {
				out = append(out, Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("session_id %q fails schema pattern", resp.SessionID)})
				return out
			}
			if len(resp.SessionBearer) < 32 {
				out = append(out, Evidence{Path: PathLive, Status: StatusFail,
					Message: fmt.Sprintf("session_bearer length %d < 32", len(resp.SessionBearer))})
				return out
			}
			// Round-trip: probe POST /permissions/decisions with the minted bearer.
			req := permissionDecisionRequest{
				Tool:       "fs__read_file",
				SessionID:  resp.SessionID,
				ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			}
			_, rawProbe, sProbe, err := postDecision(ctx, h.Client, resp.SessionBearer, req)
			if err != nil {
				out = append(out, Evidence{Path: PathLive, Status: StatusError,
					Message: fmt.Sprintf("round-trip POST decision(%s, decide=%v): %v", cap, decide, err)})
				return out
			}
			if decide {
				if sProbe != http.StatusCreated {
					out = append(out, Evidence{Path: PathLive, Status: StatusFail,
						Message: fmt.Sprintf("decide=true bearer (%s) MUST authorize /permissions/decisions but got %d; body=%s", cap, sProbe, string(rawProbe))})
					return out
				}
			} else {
				if r := extractReason(rawProbe); sProbe != http.StatusForbidden || r != "insufficient-scope" {
					out = append(out, Evidence{Path: PathLive, Status: StatusFail,
						Message: fmt.Sprintf("decide=false bearer (%s) MUST 403 insufficient-scope; got status=%d reason=%q", cap, sProbe, r)})
					return out
				}
			}
		}
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: "6 sessions minted (3 caps × 2 decide-scope variants); all 201 bodies schema-valid; granted == requested; ids+bearers shape OK; round-trip: decide=true bearers authorize /permissions/decisions (201), decide=false bearers refused (403 insufficient-scope) — scope grant independent of capability"})
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
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}

	// Path 1 (cheap): if the running Runner already serves a ReadOnly card,
	// run the assertion against it.
	cardCap := probeRunningCardActiveMode(ctx, h.Client)
	if cardCap == "ReadOnly" {
		ev := assertSessBoot02(ctx, h.Client, bearer)
		ev.Message = "running Runner serves ReadOnly card. " + ev.Message
		out = append(out, ev)
		return out
	}

	// Path 2 (path-a per coordination plan): spawn a second impl with
	// RUNNER_CARD_PATH pointed at the spec's pinned ReadOnly agent-card.json,
	// wait for /health, fire the assertion, kill the subprocess.
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: fmt.Sprintf("running Runner serves card with activeMode=%s (not ReadOnly). Path (a) needs SOA_IMPL_BIN set to spawn a second impl on a test port with RUNNER_CARD_PATH=<spec>/test-vectors/agent-card.json. Path (b) waits for Week 5b create-soa-agent ReadOnly deployment.", cardCap)})
		return out
	}
	ev := svSessBoot02ViaSubprocess(ctx, h.Spec, bearer, bin, args)
	out = append(out, ev)
	return out
}

// liveCardHasL24Anchor returns true when the running Runner's Agent Card
// includes a trust anchor whose spki_sha256 prefix matches the L-24
// pinned handler key. Used by SV-PERM-21 to differentiate "L-24 not
// adopted yet" from "L-24 anchor present but resolvePdaVerifyKey unwired".
func liveCardHasL24Anchor(ctx context.Context, c *runner.Client) bool {
	resp, err := c.Do(ctx, http.MethodGet, "/.well-known/agent-card.json", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var card struct {
		Security struct {
			TrustAnchors []struct {
				PublisherKid string `json:"publisher_kid"`
				SpkiSha256   string `json:"spki_sha256"`
			} `json:"trustAnchors"`
		} `json:"security"`
	}
	if err := json.Unmarshal(body, &card); err != nil {
		return false
	}
	for _, a := range card.Security.TrustAnchors {
		if a.PublisherKid == specvec.HandlerKeyKID {
			return true
		}
		// Also accept SPKI prefix match in case kid varies in deployments.
		if strings.HasPrefix(a.SpkiSha256, "749f3fd468e5a7e7") {
			return true
		}
	}
	return false
}

func probeRunningCardActiveMode(ctx context.Context, c *runner.Client) string {
	resp, err := c.Do(ctx, http.MethodGet, "/.well-known/agent-card.json", nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var card struct {
		Permissions struct {
			ActiveMode string `json:"activeMode"`
		} `json:"permissions"`
	}
	_ = json.Unmarshal(body, &card)
	return card.Permissions.ActiveMode
}

// assertSessBoot02 runs the §12.6 tighten-only assertion against any
// already-running ReadOnly-card Runner: POST /sessions with DFA must 403.
func assertSessBoot02(ctx context.Context, c *runner.Client, bootstrap string) Evidence {
	_, status, err := postSession(ctx, c, bootstrap, permresolve.CapDangerFullAccess)
	if err != nil {
		return Evidence{Path: PathLive, Status: StatusError, Message: err.Error()}
	}
	if status != http.StatusForbidden {
		return Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("POST /sessions(DFA) against ReadOnly card returned %d; expected 403 per §12.6", status)}
	}
	return Evidence{Path: PathLive, Status: StatusPass,
		Message: "ReadOnly card + requested DFA → 403 per §12.6 tighten-only gate"}
}

// svSessBoot02ViaSubprocess spawns a fresh impl with the spec's pinned
// ReadOnly agent-card.json, waits for /health, runs the assertion, kills
// the subprocess. Single end-to-end exercise of the SV-SESS-BOOT-02
// invariant on its own controlled deployment.
func svSessBoot02ViaSubprocess(ctx context.Context, sv specvec.Locator, bootstrap, bin string, args []string) Evidence {
	specRoot, _ := filepath.Abs(sv.Root)
	port := implTestPort() + 1 // +1 so it doesn't clash with V-09/V-12 spawns at the default test port
	subBootstrap := bootstrap + "-svboot02"
	env := envWithSystemBasics(map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_PATH":            filepath.Join(specRoot, "test-vectors", "agent-card.json"), // ReadOnly default card
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": subBootstrap,
	})

	// Use a probe-client to detect /health=200 readiness.
	probeClient := runner.New(runner.Config{
		BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Timeout: 1 * time.Second,
	})

	type result struct {
		err     error
		spawned bool
	}
	done := make(chan result, 1)
	var spawnedRes subprocrunner.Result
	go func() {
		spawnedRes = subprocrunner.Spawn(ctx, subprocrunner.Config{
			Bin: bin, Args: args, Env: env, InheritEnv: false,
			Timeout:      20 * time.Second,
			ReadinessProbe: probeClient.Health,
			PollInterval:   300 * time.Millisecond,
		})
		done <- result{}
	}()

	// Wait until /health responds OR subprocess exits early.
	deadline := time.Now().Add(15 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		select {
		case <-done:
			// Subprocess exited before we could fire the assertion —
			// it's spawnedRes.Stderr that tells us why.
			return Evidence{Path: PathLive, Status: StatusError,
				Message: fmt.Sprintf("path-a subprocess exited before /health came up: ExitCode=%d Stderr=%s",
					spawnedRes.ExitCode, spawnedRes.Stderr[:min(200, len(spawnedRes.Stderr))])}
		default:
		}
		if probeClient.Health(ctx) == nil {
			ready = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !ready {
		// Trigger the goroutine to clean up via timeout.
		<-done
		return Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("path-a subprocess never reached /health=200 within 15s; ExitCode=%d Stderr=%s",
				spawnedRes.ExitCode, spawnedRes.Stderr[:min(200, len(spawnedRes.Stderr))])}
	}

	// Subprocess is up. Fire the assertion against ITS bootstrap bearer.
	ev := assertSessBoot02(ctx, probeClient, subBootstrap)
	// Stop waiting on the subprocess; the readiness probe inside Spawn
	// already returned nil so Spawn will kill+return shortly.
	<-done
	if ev.Status == StatusPass {
		ev.Message = fmt.Sprintf("path-a (subprocess on port %d, ReadOnly card via RUNNER_CARD_PATH=test-vectors/agent-card.json): %s", port, ev.Message)
	}
	return ev
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
	_, sessBearer, src := auditBearer(ctx, h.Client)
	if sessBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "no session bearer available; set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION"})
		return out
	}
	_ = src
	raw1, err := getAuditTailRaw(ctx, h.Client, sessBearer, h.Spec)
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
	raw2, err := getAuditTailRaw(ctx, h.Client, sessBearer, h.Spec)
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
		// Positive happy-path arm satisfied. Now V-12 negatives — propagate
		// PASS/FAIL honestly: any negative-arm failure → aggregate FAIL,
		// not "pass + caveat in the message".
		msg, ok, allPass := svBootNegativesEvidence(ctx, h)
		switch {
		case !ok:
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "/health + /ready respond (positive arm). V-12 negative arms (expired / channel-mismatch / mismatched-publisher-kid → HostHardeningInsufficient) skipped: SOA_IMPL_BIN unset. Set SOA_IMPL_BIN='node /abs/path/to/start-runner.js' to fire them."})
		case allPass:
			out = append(out, Evidence{Path: PathLive, Status: StatusPass,
				Message: "/health + /ready respond (positive arm); " + msg})
		default:
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: "/health + /ready respond, BUT V-12 negative arms failed: " + msg})
		}
	case hErr != nil && rErr != nil:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "neither /health nor /ready respond (impl has not shipped §5.4 probes)"})
	default:
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§5.4 probe partial: health=%v ready=%v", errOrOK(hErr), errOrOK(rErr))})
	}
	return out
}

// svBootNegativesEvidence runs the three pinned broken-trust fixtures
// against subprocess-spawned impl. Returns (summary, ranTests, allPass).
// ranTests=false when SOA_IMPL_BIN unset (skip outer-handler decides).
func svBootNegativesEvidence(ctx context.Context, h HandlerCtx) (string, bool, bool) {
	bin, args, ok := parseImplBin()
	if !ok {
		return "", false, false
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	cards := map[string]string{
		"expired":                  filepath.Join(specRoot, "test-vectors", "initial-trust", "expired.json"),
		"channel-mismatch":         filepath.Join(specRoot, "test-vectors", "initial-trust", "channel-mismatch.json"),
		"mismatched-publisher-kid": filepath.Join(specRoot, "test-vectors", "initial-trust", "mismatched-publisher-kid.json"),
	}
	expectedReason := map[string]string{
		"expired":                  "bootstrap-expired",
		"channel-mismatch":         "bootstrap-invalid-schema",
		"mismatched-publisher-kid": "bootstrap-missing",
	}
	var results []string
	allPass := true
	for name, fixturePath := range cards {
		env := map[string]string{
			"RUNNER_PORT":                 strconv.Itoa(port),
			"RUNNER_HOST":                 "127.0.0.1",
			"RUNNER_INITIAL_TRUST":        fixturePath,
			"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
			"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
			"RUNNER_DEMO_MODE":            "1",
			"SOA_RUNNER_BOOTSTRAP_BEARER": "svboot01-test-bearer",
		}
		if name == "mismatched-publisher-kid" {
			env["RUNNER_EXPECTED_PUBLISHER_KID"] = "soa-validator-different-from-fixture-kid"
		}
		res := subprocrunner.Spawn(ctx, subprocrunner.Config{
			Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
			Timeout: 12 * time.Second,
		})
		if !res.Exited || res.ExitCode == 0 {
			results = append(results, fmt.Sprintf("%s: FAIL (Exited=%v ExitCode=%d)", name, res.Exited, res.ExitCode))
			allPass = false
			continue
		}
		combined := res.Stderr + "\n" + res.Stdout
		// Write captured stderr to a debug file when SOA_VALIDATE_DEBUG_DIR is set.
		if dbgDir := os.Getenv("SOA_VALIDATE_DEBUG_DIR"); dbgDir != "" {
			_ = os.WriteFile(filepath.Join(dbgDir, "svboot-"+name+".stderr"), []byte(res.Stderr), 0644)
		}
		got := extractFailureReason(combined)
		if got != expectedReason[name] {
			results = append(results, fmt.Sprintf("%s: FAIL (exit=%d, stderrLen=%d, stdoutLen=%d, got reason=%s, want %s)",
				name, res.ExitCode, len(res.Stderr), len(res.Stdout), got, expectedReason[name]))
			allPass = false
			continue
		}
		results = append(results, fmt.Sprintf("%s→%s", name, got))
	}
	if allPass {
		return fmt.Sprintf("V-12 negatives passed (3 fixtures, subprocess fail-closed boots): %s", strings.Join(results, ", ")), true, true
	}
	return strings.Join(results, "; "), true, false
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

// audiBearer returns a session bearer suitable for /audit/tail and
// /audit/records reads (any session bearer carries audit:read per §12.6).
// Tries SOA_IMPL_DEMO_SESSION first, then mints a fresh session via
// SOA_RUNNER_BOOTSTRAP_BEARER (T-03 spec-normative path). Returns
// ("", "", "") if neither source works — caller skips with diagnostic.
func auditBearer(ctx context.Context, c *runner.Client) (sid, bearer, source string) {
	if s, b, ok := parseDemoSession(); ok {
		return s, b, "demo-session"
	}
	if bs := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER"); bs != "" {
		resp, status, err := postSessionWithScope(ctx, c, bs, permresolve.CapReadOnly, false)
		if err == nil && status == http.StatusCreated {
			return resp.SessionID, resp.SessionBearer, "bootstrap-minted"
		}
	}
	return "", "", ""
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

	// Positive path: mint a fresh session with request_decide_scope:true (T-03).
	// Resolver uses the session's activeMode for capability — RO + AutoAllow
	// tool → AutoAllow decision regardless of card cap.
	posSess, st, err := postSessionWithScope(ctx, h.Client, bootstrap, permresolve.CapReadOnly, true)
	if err != nil || st != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("provision positive session: status=%d err=%v", st, err)})
		return out
	}
	before, err := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "pre-decision GET /audit/tail: " + err.Error()})
		return out
	}
	posReq := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  posSess.SessionID,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	dec, rawResp, status, err := postDecision(ctx, h.Client, posSess.SessionBearer, posReq)
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
	want := permresolve.Resolve(permresolve.RiskReadOnly, permresolve.CtrlAutoAllow, permresolve.CapReadOnly, "")
	if dec.Decision != string(want) {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("forgery-resistance: impl decision=%s, oracle=%s", dec.Decision, want)})
		return out
	}
	after, err := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
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

	// Auth-negative #1: mint session WITHOUT decide scope → insufficient-scope.
	// MUST not write an audit record.
	noScopeSess, st1, err := postSessionWithScope(ctx, h.Client, bootstrap, permresolve.CapReadOnly, false)
	if err != nil || st1 != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "provision no-scope session"})
		return out
	}
	beforeNeg, err := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	negReq1 := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  noScopeSess.SessionID,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	_, rawN1, sN1, err := postDecision(ctx, h.Client, noScopeSess.SessionBearer, negReq1)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "neg-1 POST: " + err.Error()})
		return out
	}
	if r := extractReason(rawN1); sN1 != http.StatusForbidden || r != "insufficient-scope" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("insufficient-scope: status=%d reason=%q (want 403+insufficient-scope; body=%s)", sN1, r, string(rawN1))})
		return out
	}
	tailN1, err := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	if tailN1.RecordCount != beforeNeg.RecordCount {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("insufficient-scope MUST not audit; tail count %d → %d (Δ=%d)", beforeNeg.RecordCount, tailN1.RecordCount, tailN1.RecordCount-beforeNeg.RecordCount)})
		return out
	}

	// Auth-negative #2: bearer-A on session-B (both with decide scope) →
	// session-bearer-mismatch. MUST not write an audit record.
	mismB, stm, err := postSessionWithScope(ctx, h.Client, bootstrap, permresolve.CapReadOnly, true)
	if err != nil || stm != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "provision mismatch session B"})
		return out
	}
	beforeN2, _ := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
	negReq2 := permissionDecisionRequest{
		Tool:       "fs__read_file",
		SessionID:  mismB.SessionID, // body says B
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	_, rawN2, sN2, err := postDecision(ctx, h.Client, posSess.SessionBearer, negReq2) // bearer for posSess (≠B)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "neg-2 POST: " + err.Error()})
		return out
	}
	if r := extractReason(rawN2); sN2 != http.StatusForbidden || r != "session-bearer-mismatch" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("session-bearer-mismatch: status=%d reason=%q (want 403+session-bearer-mismatch; body=%s)", sN2, r, string(rawN2))})
		return out
	}
	tailN2, _ := getAuditTail(ctx, h.Client, posSess.SessionBearer, h.Spec)
	if tailN2.RecordCount != beforeN2.RecordCount {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("session-bearer-mismatch MUST not audit; tail count %d → %d", beforeN2.RecordCount, tailN2.RecordCount)})
		return out
	}

	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("positive (T-03 minted bearer): decision=%s matches §10.3 oracle, schema-valid, +1 audit (%d→%d), audit_this_hash=%s matches tail; negatives: insufficient-scope (no decide on bearer) → 403 + audit unchanged; session-bearer-mismatch (bearer-A, body-session-B) → 403 + audit unchanged. RUNNER_DEMO_SESSION dependency retired. pda-decision-mismatch variant still skipped (deployment lacks PDA verify wiring; see SV-PERM-22).",
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
	bin, args, ok := parseImplBin()
	if !ok {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_IMPL_BIN not set. To exercise HR-12 set SOA_IMPL_BIN='node /abs/path/to/start-runner.js' (and optionally SOA_IMPL_TEST_PORT to override default 7701)."})
		return out
	}
	port := implTestPort()
	specRoot, _ := filepath.Abs(h.Spec.Root)
	env := map[string]string{
		"RUNNER_PORT":                  strconv.Itoa(port),
		"RUNNER_HOST":                  "127.0.0.1",
		"RUNNER_INITIAL_TRUST":         filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":          filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":         filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":             "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":  "hr12-test-bearer",
		"RUNNER_CARD_JWS":              filepath.Join(specRoot, "test-vectors", "tampered-card", "agent-card.json.tampered.jws"),
	}
	res := subprocrunner.Spawn(ctx, subprocrunner.Config{
		Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
		Timeout: 12 * time.Second,
		// No readiness probe — we EXPECT non-readiness. Process should
		// exit non-zero before /health binds.
	})
	if res.StartErr != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "spawn impl: " + res.StartErr.Error()})
		return out
	}
	if !res.Exited {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("HR-12: subprocess did NOT exit with tampered card JWS; spec §15.5 requires fail-closed boot. TimedOut=%v Stderr=%s",
				res.TimedOut, res.Stderr[:min(300, len(res.Stderr))])})
		return out
	}
	if res.ExitCode == 0 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("HR-12: subprocess exited 0 with tampered card JWS; spec §15.5 requires non-zero exit. Stderr=%.200q", res.Stderr)})
		return out
	}
	// Pass — impl detected the tampered JWS and refused to boot. Surface
	// the reason from stderr+stdout if it cited one (CardSignatureFailed,
	// x5c-missing, etc.) so the evidence is grounded.
	reason := extractFailureReason(res.Stderr + "\n" + res.Stdout)
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("subprocess refused to boot with tampered card JWS: ExitCode=%d, reason=%s. Spec §15.5 fail-closed satisfied.",
			res.ExitCode, reason)})
	return out
}

// parseImplBin splits SOA_IMPL_BIN on whitespace into (executable, args).
// On Windows, MSYS-style paths (/c/Users/...) are translated to Windows-
// native (C:/Users/...) so the spawned process receives a path its OS
// interprets correctly. Returns ("", nil, false) when SOA_IMPL_BIN is unset.
func parseImplBin() (string, []string, bool) {
	raw := strings.TrimSpace(os.Getenv("SOA_IMPL_BIN"))
	if raw == "" {
		return "", nil, false
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", nil, false
	}
	bin := fields[0]
	args := fields[1:]
	if runtime.GOOS == "windows" {
		bin = msysToWindows(bin)
		for i, a := range args {
			args[i] = msysToWindows(a)
		}
	}
	return bin, args, true
}

// msysToWindows translates "/c/Users/..." → "C:/Users/...". No-op for
// strings that don't match the MSYS pattern.
func msysToWindows(s string) string {
	if len(s) >= 3 && s[0] == '/' && s[2] == '/' {
		c := s[1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return strings.ToUpper(string(c)) + ":" + s[2:]
		}
	}
	return s
}

// seedAuditChain POSTs `n` permission decisions against the :7700 impl
// using the supplied session bearer. Each decision adds one audit row.
// Returns (seededCount, firstError). Used by HR-14 (tamper assertion
// needs ≥3 records) and can be reused by SV-AUDIT-RECORDS-02 if desired.
//
// This is deliberately conservative: it uses fs__read_file (ReadOnly
// tool) so decisions are AutoAllow — no PDA required, no Prompt-scope
// rejection path. Each decision uses a unique args_digest so impl's
// idempotent-replay dedup doesn't collapse them into one audit row.
func seedAuditChain(ctx context.Context, c *runner.Client, sessionBearer string, n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	// Derive session_id from bearer — auditBearer returns (sid, bearer, source).
	// For inline seeding we don't have sid handy; grab it via a bootstrap.
	// Actually simpler: extract from the bearer-source flow by minting a
	// fresh session of our own.
	bootstrapBearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrapBearer == "" {
		return 0, fmt.Errorf("SOA_RUNNER_BOOTSTRAP_BEARER unset; cannot mint seed session")
	}
	body := `{"requested_activeMode":"DangerFullAccess","user_sub":"hr14-seed","request_decide_scope":true}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bootstrapBearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("mint seed session: %w", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("mint seed session status=%d body=%.200q", resp.StatusCode, string(raw))
	}
	var parsed struct {
		SessionID     string `json:"session_id"`
		SessionBearer string `json:"session_bearer"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, fmt.Errorf("parse bootstrap response: %w", err)
	}
	_ = sessionBearer // parameter preserved for clarity; seed uses its own session to avoid scope collisions
	seeded := 0
	for i := 0; i < n; i++ {
		// Distinct args_digest per decision defeats impl's idempotent-replay
		// cache (which collapses identical (session, tool, args) into one row).
		digestHex := fmt.Sprintf("%064x", uint64(time.Now().UnixNano())+uint64(i))
		decBody := fmt.Sprintf(
			`{"tool":"fs__read_file","session_id":%q,"args_digest":"sha256:%s"}`,
			parsed.SessionID, digestHex,
		)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
			c.BaseURL()+"/permissions/decisions",
			strings.NewReader(decBody))
		req.Header.Set("Authorization", "Bearer "+parsed.SessionBearer)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			return seeded, fmt.Errorf("seed decision %d: %w", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return seeded, fmt.Errorf("seed decision %d status=%d", i+1, resp.StatusCode)
		}
		seeded++
	}
	return seeded, nil
}

// implTestPort returns a port for subprocess spawns. Precedence:
//  1. SOA_IMPL_TEST_PORT env override (back-compat; pinned port for reproducibility)
//  2. Dynamic-free port via OS ephemeral allocation
//
// Default was a fixed 7701 which caused flakes when sequential subprocess
// tests collided (e.g. SV-SESS-BOOT-02 "read tcp ... wsarecv" on re-run).
// Dynamic allocation eliminates the contention surface per test.
func implTestPort() int {
	if raw := os.Getenv("SOA_IMPL_TEST_PORT"); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil && p > 0 {
			return p
		}
	}
	if p, err := subprocrunner.PickFreePort(); err == nil {
		return p
	}
	return 7701 // fall back if the OS can't hand out a free port — preserves old behavior
}

// extractFailureReason scans stderr for spec-defined failure reason
// strings and returns the first hit. Falls back to a short tail of stderr
// when no known reason is recognized.
func extractFailureReason(stderr string) string {
	// Specific reasons first; general categories (CardSignatureFailed,
	// HostHardeningInsufficient) only matched if no specific reason hit.
	known := []string{
		"bootstrap-expired",
		"bootstrap-invalid-schema",
		"bootstrap-missing",
		"x5c-missing",
		"signature-invalid",
		"detached-jws-malformed",
		"CardSignatureFailed",
		"HostHardeningInsufficient",
	}
	for _, k := range known {
		if strings.Contains(stderr, k) {
			return k
		}
	}
	// Return the last line as a hint.
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if len(lines) > 0 {
		last := lines[len(lines)-1]
		if len(last) > 120 {
			last = last[:120] + "…"
		}
		return "(no enum match; last stderr line: " + last + ")"
	}
	return "(no stderr)"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// envWithSystemBasics passes through PATH/SystemRoot/etc. from the
// validator's env so the spawned Node binary can find its runtime,
// without inheriting validator-specific env vars (SOA_*, RUNNER_*) that
// might interfere with the spawned impl's controlled boot.
func envWithSystemBasics(overrides map[string]string) map[string]string {
	out := make(map[string]string, len(overrides)+8)
	for _, k := range []string{
		"PATH", "Path", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
		"USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "ProgramFiles",
		"COMSPEC", "OS", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
		"NODE_PATH",
	} {
		if v := os.Getenv(k); v != "" {
			out[k] = v
		}
	}
	for k, v := range overrides {
		out[k] = v
	}
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

// SV-PERM-21 — PDA happy path. Spec L-24 pinned a handler keypair
// (test-vectors/handler-keypair/) plus a pre-signed PDA-JWS fixture
// (test-vectors/permission-prompt-signed/pda.jws) over a Prompt-resolving
// canonical decision for fs__write_file under WorkspaceWrite/Prompt.
//
// Validator path:
//   1. Mint a session at WorkspaceWrite (or DangerFullAccess) with
//      request_decide_scope:true.
//   2. POST /permissions/decisions {tool=fs__write_file, session_id,
//      args_digest, pda=<pda.jws>}.
//   3. Assert: 201, decision=Prompt, handler_accepted=true, audit_this_hash
//      is hex64, audit_record_id present.
//   4. GET /audit/records and assert newest record's signer_key_id ==
//      "soa-conformance-test-handler-v1.0".
//
// If the deployment has no PDA verify wired (current state pre-L-24 impl
// adoption), the endpoint returns 503 pda-verify-unavailable per L-23 →
// honest skip with diagnostic.
func handleSVPERM21(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "live-only test per spec §10.3.2+§6.1.1"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	bootstrap := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bootstrap == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "SOA_RUNNER_BOOTSTRAP_BEARER not set"})
		return out
	}
	// Read the L-24 pre-signed PDA fixture.
	pdaBytes, err := h.Spec.Read(specvec.SignedPDAJWS)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: err.Error()})
		return out
	}
	pdaStr := strings.TrimSpace(string(pdaBytes))
	// Mint a WW session with decide-scope.
	sess, st, err := postSessionWithScope(ctx, h.Client, bootstrap, permresolve.CapWorkspaceWrite, true)
	if err != nil || st != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("provision WW session: status=%d err=%v", st, err)})
		return out
	}
	req := permissionDecisionRequest{
		Tool:       "fs__write_file",
		SessionID:  sess.SessionID,
		ArgsDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		PDA:        &pdaStr,
	}
	dec, raw, status, err := postDecision(ctx, h.Client, sess.SessionBearer, req)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: "POST /permissions/decisions: " + err.Error()})
		return out
	}
	// Honest skip: deployment lacks PDA verify wiring. Differentiate two
	// sub-states of the L-24 adoption based on what's actually on the wire.
	if status == http.StatusServiceUnavailable && bytes.Contains(raw, []byte("pda-verify-unavailable")) {
		anchorPresent := liveCardHasL24Anchor(ctx, h.Client)
		if anchorPresent {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: "deployment returns 503 pda-verify-unavailable BUT L-24 handler SPKI (749f3fd4…91e3, kid=soa-conformance-test-handler-v1.0) IS already in security.trustAnchors[1] on the live card. The remaining gap is the Runner's resolvePdaVerifyKey injection — PDA verification cannot run until the Runner is wired with a key resolver that maps the handler kid to its verify key. Impl-side fix: inject a resolvePdaVerifyKey at startup whose lookup includes the L-24 anchor's kid → public.pem mapping (test-vectors/handler-keypair/public.pem)."})
		} else {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: "deployment returns 503 pda-verify-unavailable; impl has not yet adopted L-24 (handler SPKI 749f3fd4…91e3 not in trustAnchors). When impl ships L-24, this auto-flips to PASS."})
		}
		return out
	}
	if status != http.StatusCreated {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("expected 201, got %d; body=%s", status, string(raw))})
		return out
	}
	if err := agentcard.ValidateJSON(h.Spec.Path(specvec.PermissionDecisionResponseSchema), raw); err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "decision response schema: " + err.Error()})
		return out
	}
	if dec.Decision != "Prompt" {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("decision=%s, want Prompt (resolver should output Prompt for fs__write_file under WW)", dec.Decision)})
		return out
	}
	if !dec.HandlerAccepted {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("handler_accepted=false reason=%s; want true with valid signed PDA", dec.Reason)})
		return out
	}
	if !hex64Re.MatchString(dec.AuditThisHash) {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "audit_this_hash not 64-char hex: " + dec.AuditThisHash})
		return out
	}
	if dec.AuditRecordID == "" || !strings.HasPrefix(dec.AuditRecordID, "aud_") {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: "audit_record_id missing or wrong shape: " + dec.AuditRecordID})
		return out
	}
	// Verify newest /audit/records entry carries the L-24 handler kid.
	all, _, _, err := collectAllRecords(ctx, h.Client, sess.SessionBearer, h.Spec)
	if err != nil {
		out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "GET /audit/records: " + err.Error()})
		return out
	}
	if len(all) == 0 {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail, Message: "audit chain empty after PDA-signed decision"})
		return out
	}
	newest := all[len(all)-1]
	if newest.SignerKeyID != specvec.HandlerKeyKID {
		out = append(out, Evidence{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("newest record signer_key_id=%q, want %q (L-24 handler kid)", newest.SignerKeyID, specvec.HandlerKeyKID)})
		return out
	}
	out = append(out, Evidence{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("PDA happy-path: 201, decision=Prompt, handler_accepted=true, audit_record_id=%s, audit_this_hash=%s, newest /audit/records signer_key_id=%s (L-24 fixture)",
			dec.AuditRecordID, summarizeHash(dec.AuditThisHash), newest.SignerKeyID)})
	return out
}

func handleSVPERM22(ctx context.Context, h HandlerCtx) []Evidence {
	out := []Evidence{{Path: PathVector, Status: StatusSkip, Message: "live-only test per spec §10.3.2+§6.1.1"}}
	if !h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "live path skipped: SOA_IMPL_URL unset"})
		return out
	}
	// SV-PERM-22 needs a session that can POST /permissions/decisions.
	// Mint one with decide=true via bootstrap; fall back to demo session.
	var demoSid, demoBearer string
	if bs := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER"); bs != "" {
		s, st, err := postSessionWithScope(ctx, h.Client, bs, permresolve.CapDangerFullAccess, true)
		if err == nil && st == http.StatusCreated {
			demoSid = s.SessionID
			demoBearer = s.SessionBearer
		}
	}
	if demoBearer == "" {
		s, b, ok := parseDemoSession()
		if !ok {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: "no decide-scope session available; set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION"})
			return out
		}
		demoSid, demoBearer = s, b
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
	// L-26: §10.3.2 moved pda-malformed from 403 enum to 400 enum.
	// Wire-level malformed PDA → 400 + error/reason == "pda-malformed";
	// no audit record written (auth/structural failure, never touches
	// resolver).
	if status == http.StatusBadRequest {
		r := extractReason(raw)
		if r != "pda-malformed" {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("400 reason=%q; L-26 §10.3.2 400 enum requires 'pda-malformed'; body=%s", r, string(raw))})
			return out
		}
		after, _ := getAuditTail(ctx, h.Client, demoBearer, h.Spec)
		if after.RecordCount != before.RecordCount {
			out = append(out, Evidence{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("400 pda-malformed MUST not audit; record_count %d → %d", before.RecordCount, after.RecordCount)})
			return out
		}
		out = append(out, Evidence{Path: PathLive, Status: StatusPass,
			Message: "malformed-wire PDA → 400 reason=pda-malformed (L-26 enum); no audit record written. crypto-invalid-but-well-formed and decision-mismatch branches require constructing a well-formed-but-wrong-signed PDA — deferred (fixture/design TBD)."})
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
	_, demoBearer, _ := auditBearer(ctx, h.Client)
	if demoBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "no session bearer available; set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION"})
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
	_, demoBearer, _ := auditBearer(ctx, h.Client)
	if demoBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "no session bearer available; set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION"})
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
	_, demoBearer, _ := auditBearer(ctx, h.Client)
	if demoBearer == "" {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "no session bearer available; set SOA_RUNNER_BOOTSTRAP_BEARER (preferred) or SOA_IMPL_DEMO_SESSION"})
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
		// Self-seed: the tamper assertion needs ≥3 records for a mid-chain
		// index to be meaningful. Drive decisions inline to fill the gap.
		needed := 3 - len(all)
		if seeded, seedErr := seedAuditChain(ctx, h.Client, demoBearer, needed); seedErr != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: fmt.Sprintf("chain has %d records; HR-14 needs ≥3 and inline-seed failed after %d posts: %v. Drive externally via SOA_DRIVE_AUDIT_RECORDS=N.", len(all), seeded, seedErr)})
			return out
		}
		// Re-fetch after seeding.
		all, _, _, err = collectAllRecords(ctx, h.Client, demoBearer, h.Spec)
		if err != nil {
			out = append(out, Evidence{Path: PathLive, Status: StatusError, Message: "post-seed refetch: " + err.Error()})
			return out
		}
		if len(all) < 3 {
			out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
				Message: fmt.Sprintf("inline-seed posted but chain still has %d records; HR-14 needs ≥3. Impl may be in degraded-buffering.", len(all))})
			return out
		}
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
