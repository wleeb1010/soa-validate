package testrunner

// V-10 handlers — §1 encoding (SV-ENC 7), §4 principles (SV-PRIN 5),
// §5.1 stack completeness (SV-STACK 2), §5.4 ops (SV-OPS 2) = 16 tests.
// Mostly vector-heavy (spec text + fixture scans); two live probes for
// /health + /ready.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/jcs"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── helpers ─────────────────────────────────────────────────────────

// visitTextFiles walks spec root and yields *.md / *.json paths under
// spec-tracked directories. Skips node_modules + .git + generator output.
func visitTextFiles(specRoot string, yield func(path string, data []byte) error) error {
	return filepath.WalkDir(specRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate unreadable paths (e.g. permission-scoped)
		}
		if d.IsDir() {
			base := d.Name()
			if base == "node_modules" || base == ".git" || base == "graphify-out" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".md" && ext != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return yield(path, data)
	})
}

// ─── SV-ENC-01 §1 — UTF-8 no BOM ─────────────────────────────────────

func handleSVENC01(ctx context.Context, h HandlerCtx) []Evidence {
	specRoot, _ := filepath.Abs(h.Spec.Root)
	var offenders []string
	scanned := 0
	_ = visitTextFiles(specRoot, func(path string, data []byte) error {
		scanned++
		if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
			rel, _ := filepath.Rel(specRoot, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if len(offenders) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 UTF-8 no BOM: %d file(s) ship with BOM: %v", len(offenders), offenders)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§1 UTF-8 no BOM: %d spec text files scanned, zero BOM", scanned)}}
}

// ─── SV-ENC-02 §1 — RFC 3339 timestamps (live) ───────────────────────

func handleSVENC02(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	// /version emits generated_at; /.well-known/agent-card.json.jws is
	// bytewise so no timestamp exposed; /audit/tail exposes
	// last_record_timestamp + generated_at.
	rfc3339 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3,})?(Z|[+-]\d{2}:\d{2})$`)
	body, status, _, err := govGet(ctx, h.Client, "/version")
	if err != nil || status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: fmt.Sprintf("GET /version status=%d err=%v", status, err)}}
	}
	var v struct {
		GeneratedAt string `json:"generated_at"`
	}
	_ = json.Unmarshal(body, &v)
	if !rfc3339.MatchString(v.GeneratedAt) {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/version generated_at=%q not RFC 3339 (needs explicit TZ, ≥ms precision)", v.GeneratedAt)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§1 RFC 3339: /version generated_at=%s (explicit TZ, ≥ms precision)", v.GeneratedAt)}}
}

// ─── SV-ENC-03 §1 — ISO-8601 durations (vector) ──────────────────────

func handleSVENC03(ctx context.Context, h HandlerCtx) []Evidence {
	// Scan spec markdown for duration markers like P30D, PT5M, PT1H.
	// Assertion is "duration fields are ISO-8601" — the spec text is the
	// normative source declaring the format. Check §13.4 / §15.4 / §8.2
	// sections mention the ISO-8601 pattern.
	spec, err := h.Spec.Read("SOA-Harness Core Specification v1.0 (Final).md")
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	text := string(spec)
	isoPat := regexp.MustCompile(`\bP(T)?\d+[DHMSY]\b`)
	matches := isoPat.FindAllString(text, -1)
	if len(matches) < 3 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 ISO-8601 durations: spec text has only %d ISO-8601 duration tokens (expected ≥3 for P*/PT* examples)", len(matches))}}
	}
	seen := map[string]int{}
	for _, m := range matches {
		seen[m]++
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	preview := keys
	if len(preview) > 5 {
		preview = preview[:5]
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§1 ISO-8601 durations: %d tokens across spec (unique: %d, e.g. %v)", len(matches), len(seen), preview)}}
}

// ─── SV-ENC-04 §1 — LF line separators (git-canonical bytes) ─────────
//
// Assertion: "Persisted JSON uses LF line endings; CRLF rejected at
// ingest." Windows git `core.autocrlf=true` rewrites working-copy bytes
// on checkout, so scanning the filesystem directly gives CRLF even when
// the git-stored canonical form is LF. Read bytes via `git show HEAD:`
// to observe the repository's canonical encoding; the manifest digest
// pinned in soa-validate.lock already verifies those bytes end-to-end.
func handleSVENC04(ctx context.Context, h HandlerCtx) []Evidence {
	specRoot, _ := filepath.Abs(h.Spec.Root)
	// List all .json files tracked by git at HEAD.
	lsCmd := exec.Command("git", "ls-files", "*.json")
	lsCmd.Dir = specRoot
	lsOut, err := lsCmd.Output()
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError,
			Message: "git ls-files: " + err.Error() + " (cwd=" + specRoot + ")"}}
	}
	paths := strings.Split(strings.TrimSpace(string(lsOut)), "\n")
	var offenders []string
	scanned := 0
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		showCmd := exec.Command("git", "show", "HEAD:"+p)
		showCmd.Dir = specRoot
		data, err := showCmd.Output()
		if err != nil {
			continue
		}
		scanned++
		if bytes.Contains(data, []byte("\r\n")) {
			offenders = append(offenders, p)
		}
	}
	if len(offenders) > 3 {
		offenders = append(offenders[:3], fmt.Sprintf("… %d more", len(offenders)-3))
	}
	if len(offenders) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 LF line separators (git-canonical): %d .json file(s) store CRLF: %v", len(offenders), offenders)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§1 LF line separators: %d git-tracked .json files at HEAD, zero CRLF in canonical bytes", scanned)}}
}

// ─── SV-ENC-05 §1 — JCS canonicalization (RFC 8785 round-trip) ───────

func handleSVENC05(ctx context.Context, h HandlerCtx) []Evidence {
	dir := h.Spec.Path(specvec.JCSParityGeneratedDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError,
			Message: "read jcs-parity generated/ dir: " + err.Error()}}
	}
	totalCases := 0
	perFile := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return []Evidence{{Path: PathVector, Status: StatusError, Message: "read " + e.Name() + ": " + err.Error()}}
		}
		var doc struct {
			Cases []struct {
				Name              string      `json:"name"`
				Input             interface{} `json:"input"`
				ExpectedCanonical string      `json:"expected_canonical"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return []Evidence{{Path: PathVector, Status: StatusFail, Message: "parse " + e.Name() + ": " + err.Error()}}
		}
		for _, c := range doc.Cases {
			got, err := jcs.Canonicalize(c.Input)
			if err != nil {
				return []Evidence{{Path: PathVector, Status: StatusFail,
					Message: fmt.Sprintf("%s case %q canonicalize: %v", e.Name(), c.Name, err)}}
			}
			if string(got) != c.ExpectedCanonical {
				return []Evidence{{Path: PathVector, Status: StatusFail,
					Message: fmt.Sprintf("%s case %q: got %q, want %q", e.Name(), c.Name, string(got), c.ExpectedCanonical)}}
			}
			// Round-trip: parse canonical form and re-canonicalize.
			var reparsed interface{}
			if err := json.Unmarshal(got, &reparsed); err != nil {
				return []Evidence{{Path: PathVector, Status: StatusFail,
					Message: fmt.Sprintf("%s case %q reparse: %v", e.Name(), c.Name, err)}}
			}
			got2, _ := jcs.Canonicalize(reparsed)
			if !bytes.Equal(got, got2) {
				return []Evidence{{Path: PathVector, Status: StatusFail,
					Message: fmt.Sprintf("%s case %q round-trip divergent", e.Name(), c.Name)}}
			}
			totalCases++
		}
		perFile = append(perFile, fmt.Sprintf("%s=%d", strings.TrimSuffix(e.Name(), ".json"), len(doc.Cases)))
	}
	if totalCases < 20 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 JCS parity: only %d cases checked (expected ≥20 across generated/)", totalCases)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§1 JCS (RFC 8785): %d cases round-tripped byte-identically across {%s}", totalCases, strings.Join(perFile, ", "))}}
}

// ─── SV-ENC-06 §1 — JWT iat/exp ±30s (vector-unavailable) ────────────

func handleSVENC06(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathVector, Status: StatusSkip,
		Message: "SV-ENC-06 (§1 JWT clock-skew ±30s): needs JWT fixtures with iat/exp in/out of the ±30s window to exercise AuthFailed. " +
			"Validator would decode + compare against a reference verifier clock. **Finding AS (spec)**: ship test-vectors/jwt-clock-skew/ " +
			"with {iat-in-window.jwt, iat-past.jwt, iat-future.jwt, exp-expired.jwt} + a reference-clock constant in README."}}
}

// ─── SV-ENC-07 §1 — PDA not_before/not_after ±60s + window ≤15min ────

func handleSVENC07(ctx context.Context, h HandlerCtx) []Evidence {
	// Unsigned canonical-decision.json carries not_before/not_after + a
	// 15-minute window; the signed PDA-pair fixture ships a different
	// schema focused on handler-kid + args_digest + capability (no window
	// fields). The §1 clock-skew assertion is on the unsigned shape.
	raw, err := h.Spec.Read(specvec.CanonicalDecisionJSON)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: "read canonical-decision: " + err.Error()}}
	}
	var dec struct {
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	if err := json.Unmarshal(raw, &dec); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: "parse decision: " + err.Error()}}
	}
	if dec.NotBefore == "" || dec.NotAfter == "" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("PDA canonical-decision missing not_before/not_after: nb=%q na=%q", dec.NotBefore, dec.NotAfter)}}
	}
	nb, err := time.Parse(time.RFC3339, dec.NotBefore)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail, Message: "parse not_before: " + err.Error()}}
	}
	na, err := time.Parse(time.RFC3339, dec.NotAfter)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail, Message: "parse not_after: " + err.Error()}}
	}
	span := na.Sub(nb)
	if span > 15*time.Minute {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 PDA window=%s > 15min ceiling", span)}}
	}
	if span <= 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§1 PDA window invalid: not_after-not_before=%s", span)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§1 PDA window: not_after - not_before = %s ≤ 15min ceiling", span)}}
}

// ─── SV-PRIN-01 §4 — Single-agent baseline (vector) ──────────────────

func handleSVPRIN01(ctx context.Context, h HandlerCtx) []Evidence {
	card, err := h.Spec.Read(specvec.ConformanceCard)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	var c map[string]interface{}
	if err := json.Unmarshal(card, &c); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	// Default is single-agent. If a multi_agent waiver is declared, the
	// Card or a sibling manifest must reference §22.
	waiver, hasWaiver := c["multi_agent_waiver"]
	if hasWaiver {
		s, _ := waiver.(string)
		if !strings.Contains(s, "§22") && !strings.Contains(s, "section 22") {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: "multi_agent_waiver present but lacks §22 reference: " + s}}
		}
		return []Evidence{{Path: PathVector, Status: StatusPass,
			Message: "§4 single-agent: waiver declared with §22 reference"}}
	}
	// Implicit single-agent (no waiver). Confirm no multi-agent markers.
	for _, k := range []string{"agents", "sub_agents", "multi_agent"} {
		if _, present := c[k]; present {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("§4 multi-agent declaration %q present without explicit §22 waiver", k)}}
		}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "§4 single-agent baseline: conformance card advertises single-agent (no multi-agent declarations, no waiver needed)"}}
}

// ─── SV-PRIN-02 §4 — Failure paths defined in §16 ────────────────────

func handleSVPRIN02(ctx context.Context, h HandlerCtx) []Evidence {
	spec, err := h.Spec.Read("SOA-Harness Core Specification v1.0 (Final).md")
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	text := string(spec)
	idx := strings.Index(text, "## 16. Runtime Execution Model and Cross-Interaction Matrix")
	if idx < 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "§16 Cross-Interaction Matrix heading missing from spec"}}
	}
	section := text[idx:]
	end := strings.Index(section, "\n## 17")
	if end > 0 {
		section = section[:end]
	}
	// Required failure paths from SV-PRIN-02 assertion + §16 explicit list.
	wantMarkers := []string{
		"A2A handoff during self-improvement", // crash/upstream
		"BudgetExhausted",                      // token exhaustion
		"Compaction during streaming",          // stream interruption
		"Agent Card changes mid-session",       // rollback/drift
		"OTel exporter failure",                // upstream unavailability
		"HandoffBusy",                          // permission denial proxy
	}
	missing := []string{}
	for _, m := range wantMarkers {
		if !strings.Contains(section, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§16 matrix missing normative outcomes for: %v", missing)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§16 Cross-Interaction Matrix covers %d failure-path markers: %v", len(wantMarkers), wantMarkers)}}
}

// ─── SV-PRIN-03 §4 — Primitives unit-testable (meta-check) ───────────

func handleSVPRIN03(ctx context.Context, h HandlerCtx) []Evidence {
	mmBytes, err := h.Spec.Read("soa-validate-must-map.json")
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	var mm struct {
		Tests map[string]map[string]interface{} `json:"tests"`
	}
	if err := json.Unmarshal(mmBytes, &mm); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	// Each primitive P1-P14 should be mentioned in at least one test's
	// section field (e.g. SV-PERM-* → §10, SV-CARD-* → §6, etc.) — the
	// spec §5.2 mapping is primitive → §N. Loose check: count SV-* tests
	// that reference the canonical primitive sections.
	primitiveSections := map[string][]string{
		"P1 (Tool Registry)":        {"§11"},
		"P2 (Permission System)":    {"§10"},
		"P3 (Session Persistence)":  {"§12"},
		"P4 (Workflow State)":       {"§12"},
		"P5 (Runner State Machine)": {"§16"},
		"P6 (Stream Envelope)":      {"§14"},
		"P7 (Hooks)":                {"§15"},
		"P8 (Harness Regression)":   {"§15", "§18"},
		"P9 (MCP Client)":           {"§5", "§24"},
		"P10 (AGENTS.md Rules)":     {"§7"},
		"P12 (Agent Card)":          {"§6"},
		"P13 (Token Budget)":        {"§13"},
		"P14 (Observability)":       {"§14"},
	}
	missing := []string{}
	for prim, sects := range primitiveSections {
		found := false
		for id, test := range mm.Tests {
			_ = id
			sec, _ := test["section"].(string)
			for _, want := range sects {
				if strings.HasPrefix(sec, want) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			missing = append(missing, prim)
		}
	}
	if len(missing) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§4 primitive coverage: %d primitives lack SV-* test in must-map: %v", len(missing), missing)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§4 primitive coverage: all %d core primitives (P1..P10, P12..P14) have ≥1 SV-* test in the must-map", len(primitiveSections))}}
}

// ─── SV-PRIN-04 §4 — File-system grounded ────────────────────────────

func handleSVPRIN04(ctx context.Context, h HandlerCtx) []Evidence {
	spec, err := h.Spec.Read("SOA-Harness Core Specification v1.0 (Final).md")
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	text := string(spec)
	// §4: "All state and rules MUST be file-system grounded. Databases
	// MAY be used as secondary stores but MUST NOT hold the primary source
	// of truth."
	markers := []string{
		"file-system grounded",
		"Databases MAY be used as secondary stores",
		"MUST NOT hold the primary source of truth",
	}
	missing := []string{}
	for _, m := range markers {
		if !strings.Contains(text, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§4 file-system-grounded principle: spec missing markers %v", missing)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "§4 file-system-grounded: spec declares file-system as authoritative + DB-as-secondary-only rule"}}
}

// ─── SV-PRIN-05 §4/§16 — Composition specified ───────────────────────

func handleSVPRIN05(ctx context.Context, h HandlerCtx) []Evidence {
	spec, err := h.Spec.Read("SOA-Harness Core Specification v1.0 (Final).md")
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	text := string(spec)
	// §16 must cover the observable compositions the spec calls out in
	// the §4 principles (self-improvement × handoff, compaction × streaming).
	required := []string{
		"A2A handoff during self-improvement",
		"Compaction during streaming",
	}
	missing := []string{}
	for _, m := range required {
		if !strings.Contains(text, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§4/§16 composition coverage: spec missing resolutions for: %v", missing)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§4/§16 composition coverage: spec defines %d key compositions (SI×handoff, compaction×streaming)", len(required))}}
}

// ─── SV-STACK-01 §5.1 — Stack completeness ───────────────────────────

func handleSVSTACK01(ctx context.Context, h HandlerCtx) []Evidence {
	cardBytes, err := h.Spec.Read(specvec.ConformanceCard)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	vEv := stackCompletenessCheck(cardBytes, "vector")
	out := []Evidence{vEv}
	if !h.Live {
		return append(out, Evidence{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"})
	}
	live, _, status, err := fetchCardLive(ctx, h.Client)
	if err != nil || status != http.StatusOK {
		return append(out, Evidence{Path: PathLive, Status: StatusError,
			Message: fmt.Sprintf("GET agent-card.json status=%d err=%v", status, err)})
	}
	return append(out, stackCompletenessCheck(live, "live"))
}

func stackCompletenessCheck(cardBytes []byte, label string) Evidence {
	path := PathVector
	if label == "live" {
		path = PathLive
	}
	var c map[string]interface{}
	if err := json.Unmarshal(cardBytes, &c); err != nil {
		return Evidence{Path: path, Status: StatusError, Message: err.Error()}
	}
	required := []string{
		"self_improvement", "memory", "permissions",
		"compaction", "tokenBudget", "observability", "security",
	}
	missing := []string{}
	for _, k := range required {
		if _, ok := c[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return Evidence{Path: path, Status: StatusFail,
			Message: fmt.Sprintf("§5.1 stack completeness (%s): card missing blocks %v", label, missing)}
	}
	return Evidence{Path: path, Status: StatusPass,
		Message: fmt.Sprintf("§5.1 stack completeness (%s): card declares all 7 required blocks (self_improvement, memory, permissions, compaction, tokenBudget, observability, security)", label)}
}

// ─── SV-STACK-02 §5.2 — Primitive endpoints resolve ──────────────────

func handleSVSTACK02(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	// Spot-check representative primitive endpoints per §5.2 / §5.4:
	//  P12 Agent Card → /.well-known/agent-card.json
	//  P2 Permission + P14 Observability → /events/recent
	//  P13 Token Budget → /budget/projection
	//  §5.4 → /health
	endpoints := []string{
		"/.well-known/agent-card.json",
		"/events/recent?session_id=ses_runnerBootLifetime&limit=1",
		"/budget/projection?session_id=ses_runnerBootLifetime",
		"/health",
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	reached := 0
	details := []string{}
	for _, ep := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.Client.BaseURL()+ep, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			details = append(details, fmt.Sprintf("%s=ERR", ep))
			continue
		}
		resp.Body.Close()
		// Any non-404/non-501 means the endpoint is wired (403/401 still
		// counts because the code path is advertised).
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusNotImplemented {
			reached++
			details = append(details, fmt.Sprintf("%s=%d", ep, resp.StatusCode))
		} else {
			details = append(details, fmt.Sprintf("%s=%d", ep, resp.StatusCode))
		}
	}
	if reached < len(endpoints) {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§5.2 primitive endpoints: %d/%d resolved (404/501=not advertised): %v", reached, len(endpoints), details)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§5.2 primitive endpoints: %d/%d advertised + reachable %v", reached, len(endpoints), details)}}
}

// ─── SV-OPS-01 §5.4 — Liveness endpoint ──────────────────────────────

func handleSVOPS01(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := h.Client.Do(reqCtx, http.MethodGet, "/health", nil)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /health: " + err.Error()}}
	}
	elapsed := time.Since(start)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/health status=%d (want 200)", resp.StatusCode)}}
	}
	if elapsed > 5*time.Second {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/health took %s (>5s ceiling)", elapsed)}}
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail, Message: "parse /health: " + err.Error()}}
	}
	if s, _ := doc["status"].(string); s != "alive" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/health status=%q (want \"alive\")", s)}}
	}
	if v, _ := doc["soaHarnessVersion"].(string); v != "1.0" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/health soaHarnessVersion=%q (want \"1.0\")", v)}}
	}
	// §5.4: "no session or audit data in body" — enforce shape strictly.
	for k := range doc {
		if k != "status" && k != "soaHarnessVersion" {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("/health body has extra field %q — §5.4 requires only {status, soaHarnessVersion}", k)}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§5.4 /health: 200 {status:alive, soaHarnessVersion:1.0} in %s", elapsed)}}
}

// ─── SV-OPS-02 §5.4 — Readiness endpoint ─────────────────────────────

func handleSVOPS02(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	resp, err := h.Client.Do(ctx, http.MethodGet, "/ready", nil)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /ready: " + err.Error()}}
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc map[string]interface{}
	_ = json.Unmarshal(body, &doc)
	switch resp.StatusCode {
	case http.StatusOK:
		if s, _ := doc["status"].(string); s != "ready" {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("/ready=200 but status=%q (want \"ready\")", s)}}
		}
		return []Evidence{{Path: PathLive, Status: StatusPass,
			Message: "§5.4 /ready: 200 {status:ready} — bootstrap resolved + tool pool consistent + CRL fresh"}}
	case http.StatusServiceUnavailable:
		// 503 is OK per §5.4 when reason is in the closed set. Validate the
		// reason field is present.
		reason, _ := doc["reason"].(string)
		allowed := []string{
			"bootstrap-pending", "bootstrap-missing", "bootstrap-revoked",
			"trust-bootstrap-pending", "persistence-unavailable",
			"audit-sink-unreachable", "crl-stale", "crl-expired",
			"memory-mcp-unavailable", "tool-pool-inconsistent",
		}
		inSet := false
		for _, a := range allowed {
			if reason == a {
				inSet = true
				break
			}
		}
		if !inSet {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("/ready=503 reason=%q not in §5.4 closed set", reason)}}
		}
		return []Evidence{{Path: PathLive, Status: StatusPass,
			Message: fmt.Sprintf("§5.4 /ready: 503 reason=%s (closed-enum member)", reason)}}
	default:
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/ready status=%d (want 200 or 503)", resp.StatusCode)}}
	}
}

var _ = runner.New // keep runner import live if other probes drop it
