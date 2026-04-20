package testrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/digest"
	"github.com/wleeb1010/soa-validate/internal/jcs"
	"github.com/wleeb1010/soa-validate/internal/permprompt"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

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
	if h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path waiting on impl's permission endpoint (impl Week 2 is StreamEvent SSE; permission flow lands later)"})
	} else {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "live path skipped: SOA_IMPL_URL unset"})
	}
	return out
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
	var out []Evidence

	// Negative path: schema must reject these three crafted inputs.
	cases := []struct {
		name, body string
	}{
		{"empty bundle", `{}`},
		{"wrong soaHarnessVersion", `{"soaHarnessVersion":"0.9","publisher_kid":"k","spki_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issuer":"CN=x"}`},
		{"extra field (additionalProperties false)", `{"soaHarnessVersion":"1.0","publisher_kid":"k","spki_sha256":"0000000000000000000000000000000000000000000000000000000000000000","issuer":"CN=x","rogue":true}`},
		{"short spki_sha256", `{"soaHarnessVersion":"1.0","publisher_kid":"k","spki_sha256":"abc","issuer":"CN=x"}`},
	}
	schemaPath := h.Spec.Path(specvec.InitialTrustSchema)
	for _, c := range cases {
		if err := agentcard.ValidateJSON(schemaPath, []byte(c.body)); err == nil {
			out = append(out, Evidence{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("negative: %s should have been rejected by schema", c.name)})
			return out
		}
	}
	out = append(out, Evidence{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("%d negative fixtures correctly rejected by initial-trust schema (empty, wrong version, extra field, short spki)", len(cases))})

	// Positive path: spec-repo gap.
	out = append(out, Evidence{Path: PathVector, Status: StatusSkip,
		Message: "HR-01 happy-path vector missing in spec repo (no test-vectors/initial-trust/ present); positive path deferred per plan, do not author locally"})

	if h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "HR-01 live path needs impl cold-start restart hook; impl has not exposed one"})
	}
	return out
}

// ─── HR-02 ──────────────────────────────────────────────────────────────
// CRL cache state machine: same gap situation. Negative-path schema reject
// runs; fresh/stale/expired state-machine vectors require pinned CRL bundles.

func handleHR02(ctx context.Context, h HandlerCtx) []Evidence {
	var out []Evidence
	cases := []struct {
		name, body string
	}{
		{"empty CRL", `{}`},
		{"missing revoked_kids", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z"}`},
		{"extra field", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z","revoked_kids":[],"rogue":true}`},
		{"revoked_kid missing required", `{"issuer":"CN=x","issued_at":"2026-04-20T00:00:00Z","not_after":"2026-05-20T00:00:00Z","revoked_kids":[{"kid":"k1"}]}`},
	}
	schemaPath := h.Spec.Path(specvec.CRLSchema)
	for _, c := range cases {
		if err := agentcard.ValidateJSON(schemaPath, []byte(c.body)); err == nil {
			out = append(out, Evidence{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("negative: %s should have been rejected", c.name)})
			return out
		}
	}
	out = append(out, Evidence{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("%d negative CRL fixtures correctly rejected (empty, missing-required, extra-field, incomplete-revoked-kid)", len(cases))})

	out = append(out, Evidence{Path: PathVector, Status: StatusSkip,
		Message: "HR-02 fresh/stale/expired state-machine vectors missing in spec repo (no test-vectors/crl/ present); state-machine coverage deferred per plan"})

	if h.Live {
		out = append(out, Evidence{Path: PathLive, Status: StatusSkip,
			Message: "HR-02 live path needs impl CRL-cache introspection endpoint; none defined yet"})
	}
	return out
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
