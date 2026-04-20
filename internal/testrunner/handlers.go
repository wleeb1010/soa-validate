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
	"github.com/wleeb1010/soa-validate/internal/jcs"
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
	"HR-01":      stub("assertions land in M1 week 6"),
	"HR-02":      stub("assertions land in M1 week 6"),
	"HR-12":      stub("assertions land in M1 week 5"),
	"HR-14":      stub("assertions land in M1 week 5"),
	"SV-BOOT-01": stub("assertions land in M1 week 5"),
	"SV-PERM-01": stub("assertions land in M1 week 3"),
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
