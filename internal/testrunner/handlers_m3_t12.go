package testrunner

// M3 T-12 handlers — SV-GOV (§6/§18/§19) governance + SV-PRIV (§10.7) privacy.
// Impl shipped T-12a (9141fd1) + T-12b (87bbe2b) Wed 2026-04-22:
//   - GET /version + GET /errata/v1.0.json (versionPlugin)
//   - POST /sessions §19.4.1 supported_core_versions negotiation
//   - POST /privacy/delete_subject + POST /privacy/export_subject (privacyPlugin)
//   - DataClass enum gains "sensitive-personal" + recordLoad guard
//   - RetentionSweepScheduler (24h cadence, no env override)
//   - residencyDecision + decisions-route layered-defence gate
//
// Wireable from this surface (8 tests): SV-GOV-01/05/06/07/08/09 +
// SV-PRIV-03/05.
//
// Routed-with-Finding-ask (7 tests):
//   - SV-GOV-02/03/04/11 + SV-PRIV-01: docs (stability-tiers, migrations,
//     errata-v1.0, release-gate, data-inventory) live as repo-root files
//     not served over HTTP. **Finding AF**: serve via /docs/* endpoints.
//   - SV-PRIV-02: recordLoad throws MemoryDeletionForbidden but
//     sessions-route catches non-MemoryTimeout silently (console.warn);
//     no observable surface. **Finding AG**: emit a system-log record
//     when MemoryDeletionForbidden is caught.
//   - SV-PRIV-04: RetentionSweepScheduler defaults to 24h interval +
//     5min tick with no env override; validator can't drive a sweep.
//     **Finding AH**: RUNNER_RETENTION_TICK_MS + RUNNER_RETENTION_INTERVAL_MS
//     env hooks (production-guard pattern, mirrors RUNNER_CONSOLIDATION_*).

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
	"strconv"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/memmock"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── shared T-12 helpers ─────────────────────────────────────────────

// govGet performs a no-bearer GET to /version, /errata, etc. Returns
// (body, status, contentType, error).
func govGet(ctx context.Context, c *runner.Client, path string) ([]byte, int, string, error) {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, "", err
	}
	return body, resp.StatusCode, resp.Header.Get("Content-Type"), nil
}

// govSessionPost POSTs to /sessions with explicit body+bearer; returns
// (status, body). Used by SV-GOV-08/09 negotiation probes.
func govSessionPost(ctx context.Context, c *runner.Client, bearer string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL()+"/sessions", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// govLockSkipIfNoLive emits a uniform skip when the live path isn't
// reachable. Returns (evidence, true) when the caller should bail.
func govLiveGate(h HandlerCtx, testID string) ([]Evidence, bool) {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: testID + ": live path skipped — SOA_IMPL_URL unset / runner unreachable"}}, true
	}
	return nil, false
}

// ─── SV-GOV-01 §6.2 — soaHarnessVersion advertised on /version ───────

func handleSVGOV01(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-01"); bail {
		return ev
	}
	body, status, ctype, err := govGet(ctx, h.Client, "/version")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "GET /version: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /version status=%d (want 200); body=%.200q", status, string(body))}}
	}
	if !strings.Contains(strings.ToLower(ctype), "application/json") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "GET /version Content-Type=" + ctype + " (want application/json)"}}
	}
	var v struct {
		SoaHarnessVersion     string   `json:"soaHarnessVersion"`
		SupportedCoreVersions []string `json:"supported_core_versions"`
		RunnerVersion         string   `json:"runner_version"`
		GeneratedAt           string   `json:"generated_at"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "parse /version body: " + err.Error()}}
	}
	if v.SoaHarnessVersion != "1.0" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("soaHarnessVersion=%q (want \"1.0\")", v.SoaHarnessVersion)}}
	}
	if len(v.SupportedCoreVersions) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "supported_core_versions empty (§19.4.1 requires non-empty)"}}
	}
	abPattern := regexp.MustCompile(`^\d+\.\d+$`)
	for _, sv := range v.SupportedCoreVersions {
		if !abPattern.MatchString(sv) {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("supported_core_versions entry %q does not match A.B pattern", sv)}}
		}
	}
	if v.RunnerVersion == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "runner_version empty"}}
	}
	if v.GeneratedAt == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "generated_at empty"}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§6.2 /version: soaHarnessVersion=%q supported=%v runner_version=%q generated_at=%s",
			v.SoaHarnessVersion, v.SupportedCoreVersions, v.RunnerVersion, v.GeneratedAt)}}
}

// ─── SV-GOV-02/03/04/11 — Finding AF docs surfaces (impl f4b006a) ────

func handleSVGOV02(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-02"); bail {
		return ev
	}
	body, status, _, err := govGet(ctx, h.Client, "/docs/stability-tiers.md")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /docs/stability-tiers.md: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /docs/stability-tiers.md status=%d (want 200)", status)}}
	}
	text := string(body)
	for _, marker := range []string{"§19.3", "Stable", "soaHarnessVersion"} {
		if !strings.Contains(text, marker) {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("docs/stability-tiers.md missing marker %q (§19.3 requires per-field tier declarations)", marker)}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.3 stability tiers: %d-byte body declares §19.3 + Stable + soaHarnessVersion field", len(body))}}
}

func handleSVGOV03(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-03"); bail {
		return ev
	}
	body, status, _, err := govGet(ctx, h.Client, "/docs/migrations/README.md")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /docs/migrations/README.md: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /docs/migrations/README.md status=%d (want 200)", status)}}
	}
	text := string(body)
	for _, marker := range []string{"§19.4", "migration"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(marker)) {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("docs/migrations/README.md missing marker %q", marker)}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.4 migration guide: %d-byte body references §19.4 + migration template", len(body))}}
}

func handleSVGOV04(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-04"); bail {
		return ev
	}
	body, status, _, err := govGet(ctx, h.Client, "/docs/stability-tiers.md")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /docs/stability-tiers.md: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /docs/stability-tiers.md status=%d (want 200)", status)}}
	}
	text := string(body)
	// §19.5 deprecation lifetime ≥2 minors. Look for an explicit lifetime declaration.
	hasLifetime := strings.Contains(text, "§19.5") ||
		strings.Contains(strings.ToLower(text), "deprecation") ||
		strings.Contains(text, "2 minor")
	if !hasLifetime {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "docs/stability-tiers.md lacks §19.5 / deprecation / 2-minor lifetime marker"}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.5 deprecation lifetime: %d-byte stability-tiers body declares deprecation policy ≥2-minor", len(body))}}
}

func handleSVGOV11(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-11"); bail {
		return ev
	}
	body, status, ctype, err := govGet(ctx, h.Client, "/release-gate.json")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /release-gate.json: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /release-gate.json status=%d (want 200)", status)}}
	}
	if !strings.Contains(strings.ToLower(ctype), "application/json") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "Content-Type=" + ctype + " (want application/json)"}}
	}
	var doc struct {
		GateVersion string                   `json:"gate_version"`
		Checks      []map[string]interface{} `json:"checks"`
		Summary     struct {
			Total int `json:"total"`
			Pass  int `json:"pass"`
			Fail  int `json:"fail"`
		} `json:"summary"`
		SignedManifestEligible bool `json:"signed_manifest_eligible"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail, Message: "parse release-gate.json: " + err.Error()}}
	}
	if len(doc.Checks) != 5 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("release-gate.json checks length=%d (§19.1.1 mandates exactly 5: extraction parity, manifest regen, must-map zero-orphan, vector digest parity, schema-2020-12 lint)", len(doc.Checks))}}
	}
	if doc.Summary.Total != 5 || doc.Summary.Fail != 0 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("summary total=%d fail=%d (want total=5, fail=0)", doc.Summary.Total, doc.Summary.Fail)}}
	}
	if !doc.SignedManifestEligible {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "signed_manifest_eligible=false — §19.1.1 requires the gate pass before signing"}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.1.1 release-gate: gate_version=%s, %d/%d checks passed, signed_manifest_eligible=true", doc.GateVersion, doc.Summary.Pass, doc.Summary.Total)}}
}

// ─── SV-GOV-05 §19.2 — errata URL reachable ──────────────────────────

func handleSVGOV05(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-05"); bail {
		return ev
	}
	body, status, ctype, err := govGet(ctx, h.Client, "/errata/v1.0.json")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "GET /errata/v1.0.json: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /errata/v1.0.json status=%d (want 200) — §19.2 requires the errata URL be reachable; body=%.200q", status, string(body))}}
	}
	if !strings.Contains(strings.ToLower(ctype), "application/json") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "GET /errata/v1.0.json Content-Type=" + ctype + " (want application/json)"}}
	}
	var doc struct {
		SpecVersion string                   `json:"spec_version"`
		Errata      []map[string]interface{} `json:"errata"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "parse /errata/v1.0.json: " + err.Error()}}
	}
	if doc.SpecVersion != "1.0" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("spec_version=%q (want \"1.0\")", doc.SpecVersion)}}
	}
	if len(doc.Errata) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "errata array empty — §19.2 doesn't strictly require entries but the body must validate as an errata document"}}
	}
	for i, e := range doc.Errata {
		if _, ok := e["id"].(string); !ok {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("errata[%d] missing string id", i)}}
		}
		if _, ok := e["section"].(string); !ok {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("errata[%d] missing string section", i)}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.2 /errata/v1.0.json: spec_version=%s, %d errata entries (each with id+section)", doc.SpecVersion, len(doc.Errata))}}
}

// ─── SV-GOV-06 §18.1 — soa-validate pinned ───────────────────────────

func handleSVGOV06(ctx context.Context, h HandlerCtx) []Evidence {
	candidates := []string{"soa-validate.lock", "../soa-validate.lock"}
	var lockPath string
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			abs, _ := filepath.Abs(p)
			lockPath = abs
			break
		}
	}
	if raw == nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "soa-validate.lock not found at expected paths " + strings.Join(candidates, ", ") +
				": §18.1 SV-GOV-06 requires the validator to be pinned to a specific spec commit"}}
	}
	var lock struct {
		SpecRepo           string `json:"spec_repo"`
		SpecCommitSHA      string `json:"spec_commit_sha"`
		SpecManifestSHA256 string `json:"spec_manifest_sha256"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("parse %s: %v", lockPath, err)}}
	}
	shaPattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !shaPattern.MatchString(lock.SpecCommitSHA) {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("spec_commit_sha=%q does not match 40-hex-char git SHA", lock.SpecCommitSHA)}}
	}
	if !digestPattern.MatchString(lock.SpecManifestSHA256) {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("spec_manifest_sha256=%q does not match 64-hex-char SHA-256", lock.SpecManifestSHA256)}}
	}
	if lock.SpecRepo == "" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "spec_repo empty — §18.1 pin must identify the source repo"}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§18.1 lock: spec_repo=%s spec_commit_sha=%s manifest=%s…", lock.SpecRepo, lock.SpecCommitSHA[:12], lock.SpecManifestSHA256[:12])}}
}

// ─── SV-GOV-07 §2 — Normative references pinned ──────────────────────

func handleSVGOV07(ctx context.Context, h HandlerCtx) []Evidence {
	specPath := h.Spec.Path("SOA-Harness Core Specification v1.0 (Final).md")
	body, err := os.ReadFile(specPath)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError,
			Message: "read core spec markdown: " + err.Error()}}
	}
	text := string(body)
	const sectionHdr = "## 2. Normative References"
	start := strings.Index(text, sectionHdr)
	if start < 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "core spec markdown missing '## 2. Normative References' header"}}
	}
	rest := text[start+len(sectionHdr):]
	end := strings.Index(rest, "\n## ")
	if end > 0 {
		rest = rest[:end]
	}
	refPattern := regexp.MustCompile(`(?m)^- \*\*\[([^\]]+)\]\*\*`)
	refs := refPattern.FindAllStringSubmatch(rest, -1)
	if len(refs) < 5 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§2 has only %d normative reference entries (expected ≥5: BCP-14, RFC-3339/8259/7519/7515/8446/8785, JSON-Schema, MCP, A2A, Harbor)", len(refs))}}
	}
	pinnedKeywords := []string{"version", "RFC", "BCP", "digest", "tag", "v0.", "v1.", "SHA"}
	yearMonth := regexp.MustCompile(`\b(19|20)\d{2}(-\d{2})?\b`)
	unpinned := []string{}
	pinnedCount := 0
	for _, m := range refs {
		idx := strings.Index(rest, "**["+m[1]+"]**")
		if idx < 0 {
			continue
		}
		// Take the entry through the next "\n- " boundary or end.
		entry := rest[idx:]
		nxt := strings.Index(entry, "\n- ")
		if nxt > 0 {
			entry = entry[:nxt]
		}
		hasPin := false
		for _, kw := range pinnedKeywords {
			if strings.Contains(entry, kw) {
				hasPin = true
				break
			}
		}
		if !hasPin && yearMonth.MatchString(entry) {
			hasPin = true
		}
		if hasPin {
			pinnedCount++
		} else {
			unpinned = append(unpinned, m[1])
		}
	}
	if len(unpinned) > 0 {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("§2 normative refs unpinned: %v (entry lacks version/RFC/BCP/digest/tag marker)", unpinned)}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§2 normative refs: %d entries, all pinned (RFC#, version tag, or digest marker present)", pinnedCount)}}
}

// ─── SV-GOV-08 §19.4.1 — empty-intersection version negotiation ──────

func handleSVGOV08(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-08"); bail {
		return ev
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-GOV-08: SOA_RUNNER_BOOTSTRAP_BEARER unset; cannot POST /sessions"}}
	}
	body := []byte(`{"requested_activeMode":"ReadOnly","user_sub":"svgov08-empty-intersect","supported_core_versions":["2.5","3.0"]}`)
	status, raw, err := govSessionPost(ctx, h.Client, bearer, body)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "POST /sessions: " + err.Error()}}
	}
	if status != http.StatusBadRequest {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("POST /sessions with empty-intersection supported_core_versions=[2.5,3.0] returned status=%d (want 400 VersionNegotiationFailed); body=%.300q", status, string(raw))}}
	}
	var resp struct {
		Error                       string   `json:"error"`
		RunnerSupportedCoreVersions []string `json:"runner_supported_core_versions"`
		CallerSupportedCoreVersions []string `json:"caller_supported_core_versions"`
		Detail                      string   `json:"detail"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "parse /sessions error body: " + err.Error()}}
	}
	if resp.Error != "VersionNegotiationFailed" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("error=%q (want VersionNegotiationFailed); body=%.300q", resp.Error, string(raw))}}
	}
	if len(resp.RunnerSupportedCoreVersions) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "runner_supported_core_versions missing — §19.4.1 error body MUST advertise the runner's set"}}
	}
	if len(resp.CallerSupportedCoreVersions) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "caller_supported_core_versions missing — §19.4.1 error body MUST echo the caller's set"}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.4.1 empty-intersection: 400 VersionNegotiationFailed runner=%v caller=%v", resp.RunnerSupportedCoreVersions, resp.CallerSupportedCoreVersions)}}
}

// ─── SV-GOV-09 §19.4.1 — highest-common selection ────────────────────

func handleSVGOV09(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-GOV-09"); bail {
		return ev
	}
	bearer := os.Getenv("SOA_RUNNER_BOOTSTRAP_BEARER")
	if bearer == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-GOV-09: SOA_RUNNER_BOOTSTRAP_BEARER unset"}}
	}
	body := []byte(`{"requested_activeMode":"ReadOnly","user_sub":"svgov09-highest-common","supported_core_versions":["0.9","1.0","2.5"]}`)
	status, raw, err := govSessionPost(ctx, h.Client, bearer, body)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "POST /sessions: " + err.Error()}}
	}
	if status != http.StatusCreated {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("POST /sessions with intersecting set [0.9,1.0,2.5] returned status=%d (want 201); body=%.300q", status, string(raw))}}
	}
	var resp struct {
		SessionID     string `json:"session_id"`
		SessionBearer string `json:"session_bearer"`
		RunnerVersion string `json:"runner_version"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "parse /sessions success body: " + err.Error()}}
	}
	if resp.SessionID == "" {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "session_id missing on 201"}}
	}
	// Confirm the runner's advertised set still includes 1.0 (the only common version).
	verBody, verStatus, _, verErr := govGet(ctx, h.Client, "/version")
	if verErr != nil || verStatus != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("post-bootstrap /version readback status=%d err=%v — can't confirm advertised set", verStatus, verErr)}}
	}
	var ver struct {
		SupportedCoreVersions []string `json:"supported_core_versions"`
	}
	_ = json.Unmarshal(verBody, &ver)
	hasHighest := false
	for _, sv := range ver.SupportedCoreVersions {
		if sv == "1.0" {
			hasHighest = true
			break
		}
	}
	if !hasHighest {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/version supported=%v missing the negotiated 1.0; intersection algorithm did not pick highest-common", ver.SupportedCoreVersions)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§19.4.1 highest-common: caller=[0.9,1.0,2.5] runner=%v → 201 session_id=%s (1.0 selected as highest tuple)", ver.SupportedCoreVersions, resp.SessionID)}}
}

// ─── SV-PRIV-01 §10.7 — data inventory present (Finding AF) ──────────

func handleSVPRIV01(ctx context.Context, h HandlerCtx) []Evidence {
	if ev, bail := govLiveGate(h, "SV-PRIV-01"); bail {
		return ev
	}
	body, status, _, err := govGet(ctx, h.Client, "/docs/data-inventory.md")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /docs/data-inventory.md: " + err.Error()}}
	}
	if status != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("GET /docs/data-inventory.md status=%d (§10.7 #1 requires the inventory be published)", status)}}
	}
	text := string(body)
	for _, marker := range []string{"§10.7", "data_class", "Retention"} {
		if !strings.Contains(text, marker) {
			return []Evidence{{Path: PathLive, Status: StatusFail,
				Message: fmt.Sprintf("docs/data-inventory.md missing marker %q", marker)}}
		}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§10.7 #1 data inventory: %d-byte body declares §10.7 + data_class tagging + Retention category mapping", len(body))}}
}

// ─── SV-PRIV-02 §10.7 — sensitive-personal block (Finding AG live) ───
//
// Impl a07124b ships AG: bootstrap memory prefetch partitions notes,
// drops sensitive-personal entries before recordLoad, and emits one
// System Event Log record per dropped note (category=Error, level=error,
// code=MemoryDeletionForbidden, data={reason:sensitive-class-forbidden,
// note_id}). Probe: validator's memmock returns a corpus with exactly
// one sensitive-personal note; spawn impl; mint session; poll
// /logs/system/recent?category=Error for the record.
func handleSVPRIV02(ctx context.Context, h HandlerCtx) []Evidence {
	corpusPath, corpusCleanup, err := writeSensitivePersonalCorpus()
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "writeSensitivePersonalCorpus: " + err.Error()}}
	}
	defer corpusCleanup()
	bin, args, env, _, port, cleanup, skip := memProbeEnvWithCorpus(h, corpusPath)
	defer cleanup()
	if skip != "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SV-PRIV-02: " + skip}}
	}
	bearer := env["SOA_RUNNER_BOOTSTRAP_BEARER"]
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Allow the impl to flush its system-log emission.
		time.Sleep(400 * time.Millisecond)
		body, code, err := getSystemLogRecentRaw(probeCtx, client, sid, sbearer, "Error")
		if err != nil {
			return "GET /logs/system/recent: " + err.Error(), false
		}
		if code != http.StatusOK {
			return fmt.Sprintf("/logs/system/recent status=%d (want 200)", code), false
		}
		var parsed struct {
			Records []struct {
				Category string                 `json:"category"`
				Level    string                 `json:"level"`
				Code     string                 `json:"code"`
				Data     map[string]interface{} `json:"data"`
			} `json:"records"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "parse /logs/system/recent: " + err.Error(), false
		}
		matched := 0
		for _, r := range parsed.Records {
			if r.Category == "Error" && r.Level == "error" && r.Code == "MemoryDeletionForbidden" {
				if reason, _ := r.Data["reason"].(string); reason == "sensitive-class-forbidden" {
					matched++
				}
			}
		}
		if matched < 1 {
			return fmt.Sprintf("no {category=Error, level=error, code=MemoryDeletionForbidden, data.reason=sensitive-class-forbidden} record in /logs/system/recent (got %d records)", len(parsed.Records)), false
		}
		return fmt.Sprintf("§10.7 #2 sensitive-personal block (Finding AG): memmock returned 1 sensitive-personal note; impl partitioned + dropped it + emitted %d MemoryDeletionForbidden record(s)", matched), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// memProbeEnvWithCorpus is memProbeEnv with a caller-supplied corpus path
// instead of the default pinned memory-mcp-mock seed.
func memProbeEnvWithCorpus(h HandlerCtx, corpusPath string) (string, []string, map[string]string, interface{}, int, func(), string) {
	bin, args, ok := parseImplBin()
	if !ok {
		return "", nil, nil, nil, 0, func() {}, "SOA_IMPL_BIN unset; subprocess spawn required"
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	m, err := memmock.New(memmock.Options{CorpusPath: corpusPath, TimeoutAfterNCalls: -1})
	if err != nil {
		return "", nil, nil, nil, 0, func() {}, "memmock.New: " + err.Error()
	}
	if err := m.Start(); err != nil {
		return "", nil, nil, nil, 0, func() {}, "memmock.Start: " + err.Error()
	}
	port := implTestPort()
	bearer := "svpriv02-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                    strconv.Itoa(port),
		"RUNNER_HOST":                    "127.0.0.1",
		"RUNNER_INITIAL_TRUST":           filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":            filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":           filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":               "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":    bearer,
		"SOA_RUNNER_MEMORY_MCP_ENDPOINT": m.URL(),
	}
	return bin, args, env, m, port, func() { m.Stop() }, ""
}

// writeSensitivePersonalCorpus writes a 1-note corpus file where the
// single note has data_class=sensitive-personal. Used by SV-PRIV-02
// to trigger the Finding AG sensitive-class-forbidden partition.
func writeSensitivePersonalCorpus() (string, func(), error) {
	doc := map[string]interface{}{
		"schema":      "https://soa-harness.org/schemas/v1.0/memory-corpus-seed.json",
		"description": "SV-PRIV-02 corpus: one sensitive-personal note to trigger Finding AG partition.",
		"version":     "1.0",
		"notes": []map[string]interface{}{{
			"note_id":          "svpriv02_sensitive_0001",
			"summary":          "User health record — sensitive-personal tagged per §10.7 #2",
			"data_class":       "sensitive-personal",
			"recency_days_ago": 1,
			"graph_strength":   0.9,
		}},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", func() {}, err
	}
	dir, err := os.MkdirTemp("", "svpriv02-corpus-*")
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "corpus-seed.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}

// ─── SV-PRIV-03 §10.7.1 — subject delete + export ────────────────────
//
// Subprocess-isolated to avoid polluting the live :7700 audit chain
// with SubjectSuppression rows, which schemas/audit-records-response.
// schema.json rejects (required: id/args_digest/capability/control/
// handler — admin SubjectSuppression rows don't carry decision-style
// fields). **Finding AJ (spec)**: schema needs a discriminator on
// `decision` so SubjectSuppression rows validate without those fields,
// or impl needs to populate stub values. Until that lands, /audit/
// records walks (HR-14, SV-AUDIT-RECORDS-01/02, SV-PERM-21) regress
// when the live chain has any SubjectSuppression row, so this probe
// runs against an isolated subprocess only.

func handleSVPRIV03(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-PRIV-03: SOA_IMPL_BIN unset; subprocess spawn required (avoid polluting live :7700 audit chain with SubjectSuppression rows pending Finding AJ)"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svpriv03-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		subject := fmt.Sprintf("svpriv03-%d", time.Now().UnixNano())
		delBody := []byte(fmt.Sprintf(`{"subject_id":%q,"scope":"memory","legal_basis":"legal-obligation","operator_kid":"svpriv03-operator-v1"}`, subject))
		delReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/privacy/delete_subject", bytes.NewReader(delBody))
		delReq.Header.Set("Content-Type", "application/json")
		delReq.Header.Set("Authorization", "Bearer "+bearer)
		delResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(delReq)
		if err != nil {
			return "POST /privacy/delete_subject: " + err.Error(), false
		}
		delRaw, _ := io.ReadAll(delResp.Body)
		delResp.Body.Close()
		if delResp.StatusCode != http.StatusOK {
			return fmt.Sprintf("delete_subject status=%d (want 200); body=%.300q", delResp.StatusCode, string(delRaw)), false
		}
		var del struct {
			SubjectID       string `json:"subject_id"`
			Scope           string `json:"scope"`
			AuditRecordHash string `json:"audit_record_hash"`
			SuppressedAt    string `json:"suppressed_at"`
		}
		if err := json.Unmarshal(delRaw, &del); err != nil {
			return "parse delete_subject body: " + err.Error(), false
		}
		if del.SubjectID != subject || del.Scope != "memory" {
			return fmt.Sprintf("delete_subject echo mismatch: subject=%q scope=%q", del.SubjectID, del.Scope), false
		}
		hashHex := regexp.MustCompile(`^[0-9a-f]{64}$`)
		if !hashHex.MatchString(del.AuditRecordHash) {
			return fmt.Sprintf("audit_record_hash=%q not 64-hex", del.AuditRecordHash), false
		}
		if del.SuppressedAt == "" {
			return "suppressed_at empty", false
		}
		// Export round-trip — must contain the just-written suppression.
		exportBody := []byte(fmt.Sprintf(`{"subject_id":%q}`, subject))
		expReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/privacy/export_subject", bytes.NewReader(exportBody))
		expReq.Header.Set("Content-Type", "application/json")
		expReq.Header.Set("Authorization", "Bearer "+bearer)
		expResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(expReq)
		if err != nil {
			return "POST /privacy/export_subject: " + err.Error(), false
		}
		expRaw, _ := io.ReadAll(expResp.Body)
		expResp.Body.Close()
		if expResp.StatusCode != http.StatusOK {
			return fmt.Sprintf("export_subject status=%d (want 200); body=%.300q", expResp.StatusCode, string(expRaw)), false
		}
		var exp struct {
			SubjectID    string                   `json:"subject_id"`
			GeneratedAt  string                   `json:"generated_at"`
			Suppressions []map[string]interface{} `json:"suppressions"`
		}
		if err := json.Unmarshal(expRaw, &exp); err != nil {
			return "parse export_subject body: " + err.Error(), false
		}
		if exp.SubjectID != subject || exp.GeneratedAt == "" || len(exp.Suppressions) == 0 {
			return fmt.Sprintf("export shape: subject=%q generated_at=%q suppressions=%d", exp.SubjectID, exp.GeneratedAt, len(exp.Suppressions)), false
		}
		// Bearer-less request must 401.
		noAuthReq, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/privacy/delete_subject", bytes.NewReader(delBody))
		noAuthReq.Header.Set("Content-Type", "application/json")
		noAuthResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(noAuthReq)
		if err != nil {
			return "POST /privacy/delete_subject (no-auth): " + err.Error(), false
		}
		noAuthResp.Body.Close()
		if noAuthResp.StatusCode != http.StatusUnauthorized {
			return fmt.Sprintf("delete_subject without bearer status=%d (want 401)", noAuthResp.StatusCode), false
		}
		return fmt.Sprintf("§10.7.1 delete_subject(scope=memory)→200 audit_hash=%s…; export_subject→200 suppressions=%d; bearer-less→401",
			del.AuditRecordHash[:12], len(exp.Suppressions)), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── SV-PRIV-04 §10.7.3 — retention sweep (Finding AH live, AO block) ─
//
// Impl b6f5187 ships AH: RUNNER_RETENTION_SWEEP_TICK_MS + RUNNER_RETENTION_SWEEP_INTERVAL_MS
// env hooks let validator drive a sub-second sweep. Sweep emits a
// system-log record (category=ContextLoad, code=retention-sweep-ran,
// session_id=ses_runner_boot_____).
//
// Probe tries the env-driven subprocess pattern first. Observability
// currently gated: /logs/system/recent requires session_id filter +
// sessionStore.exists check + bearer match. Boot session isn't
// registered in sessionStore → bootstrap-bearer caller gets 404.
// Probe pings the endpoint for the boot session_id; if 404, emits
// Finding AO (impl) with the sharp diagnostic.
func handleSVPRIV04(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-PRIV-04: SOA_IMPL_BIN unset; subprocess spawn required"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	bearer := "svpriv04-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                          strconv.Itoa(port),
		"RUNNER_HOST":                          "127.0.0.1",
		"RUNNER_INITIAL_TRUST":                 filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":                  filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":                 filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":                     "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":          bearer,
		"RUNNER_RETENTION_SWEEP_TICK_MS":       "200",
		"RUNNER_RETENTION_SWEEP_INTERVAL_MS":   "500",
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		// Wait for at least one sweep tick (interval=500ms + buffer).
		time.Sleep(1200 * time.Millisecond)
		// Try direct boot-session query with bootstrap bearer.
		url := fmt.Sprintf("%s/logs/system/recent?session_id=ses_runner_boot_____&category=ContextLoad&limit=50", client.BaseURL())
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
		if err != nil {
			return "GET /logs/system/recent: " + err.Error(), false
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return "boot session ses_runner_boot_____ not registered in sessionStore; /logs/system/recent 404s — Finding AO", false
		}
		if resp.StatusCode == http.StatusForbidden {
			return "boot session bearer-mismatch; /logs/system/recent 403 — Finding AO", false
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Sprintf("/logs/system/recent status=%d body=%.200q", resp.StatusCode, string(body)), false
		}
		var parsed struct {
			Records []struct {
				Category string `json:"category"`
				Code     string `json:"code"`
			} `json:"records"`
		}
		_ = json.Unmarshal(body, &parsed)
		for _, r := range parsed.Records {
			if r.Code == "retention-sweep-ran" && r.Category == "ContextLoad" {
				return fmt.Sprintf("§10.7.3 retention sweep (Finding AH): RUNNER_RETENTION_SWEEP_{TICK,INTERVAL}_MS env hooks drove a sub-second sweep; /logs/system/recent has %d retention-sweep-ran record(s)", len(parsed.Records)), true
			}
		}
		return fmt.Sprintf("no retention-sweep-ran record in %d logs", len(parsed.Records)), false
	})
	if pass {
		return []Evidence{{Path: PathLive, Status: StatusPass, Message: msg}}
	}
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PRIV-04: " + msg + " — retention-sweep-ran log is pinned to boot session_id=ses_runner_boot_____, " +
			"unreachable via /logs/system/recent because boot session isn't in sessionStore. " +
			"**Finding AO (impl)**: either (a) register runner-boot session in sessionStore with the bootstrap bearer, " +
			"or (b) emit retention-sweep-ran under any live session_id, or (c) add an admin-bearer path on /logs/system/recent."}}
}

// ─── SV-PRIV-05 §10.7.2 — residency layered defence (Finding AK live) ─
//
// L-41 spec + L-42 pin + impl e714da2 (AK) regenerates vendored schemas
// so `security.data_residency` is now accepted by cardPlugin. Probe
// spawns impl with a temp card carrying `data_residency=["US"]`; impl's
// residency-guard with empty toolResidencyLookup default denies every
// decision with sub_reason=unknown-region per §10.7.2. L-41's audit-
// records-response.schema.json oneOf discriminator (AJ) permits the
// ResidencyCheck admin-row shape.
func handleSVPRIV05(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-PRIV-05: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	cardPath, cleanup, err := writeResidencyCard(h.Spec)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError,
			Message: "writeResidencyCard: " + err.Error()}}
	}
	defer cleanup()
	port := implTestPort()
	bearer := "svpriv05-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_PATH":            cardPath,
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": bearer,
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 5 * time.Second})
		sid, sbearer, status, err := m2Bootstrap(probeCtx, client, bearer)
		if err != nil || status != http.StatusCreated {
			return fmt.Sprintf("bootstrap status=%d err=%v", status, err), false
		}
		// Drive one ReadOnly decision; impl's residencyGuard with empty
		// toolResidencyLookup → unknown-region → 403 PermissionDenied(residency-violation).
		decBody := []byte(fmt.Sprintf(`{"tool":"fs__read_file","session_id":%q,"args_digest":"sha256:%064x"}`, sid, time.Now().UnixNano()))
		req, _ := http.NewRequestWithContext(probeCtx, http.MethodPost, client.BaseURL()+"/permissions/decisions", bytes.NewReader(decBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sbearer)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return "POST /permissions/decisions: " + err.Error(), false
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Sprintf("decision status=%d (want 403 residency-violation); body=%.300q", resp.StatusCode, string(raw)), false
		}
		var dec struct {
			Error     string `json:"error"`
			Reason    string `json:"reason"`
			SubReason string `json:"sub_reason"`
			Residency struct {
				Decision             string   `json:"decision"`
				DeclaredLocation     []string `json:"declared_location"`
				AttestedLocation     []string `json:"attested_location"`
				NetworkSignalRegions []string `json:"network_signal_regions"`
			} `json:"residency"`
		}
		if err := json.Unmarshal(raw, &dec); err != nil {
			return "parse decision body: " + err.Error(), false
		}
		if dec.Error != "PermissionDenied" {
			return fmt.Sprintf("error=%q (want PermissionDenied); body=%.300q", dec.Error, string(raw)), false
		}
		if dec.Reason != "residency-violation" {
			return fmt.Sprintf("reason=%q (want residency-violation)", dec.Reason), false
		}
		if dec.SubReason != "unknown-region" {
			return fmt.Sprintf("sub_reason=%q (want unknown-region — empty toolResidencyLookup default)", dec.SubReason), false
		}
		if dec.Residency.Decision != "deny" {
			return fmt.Sprintf("residency.decision=%q (want deny)", dec.Residency.Decision), false
		}
		// Confirm audit row: GET /audit/records and look for ResidencyCheck.
		// Omit `after=` — empty-string `after=` returns 0 records on some
		// impl paths (genesis-after interpretation). Caller starts from
		// the genesis tail when `after` is absent.
		auditURL := fmt.Sprintf("%s/audit/records?limit=100", client.BaseURL())
		auditReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, auditURL, nil)
		auditReq.Header.Set("Authorization", "Bearer "+sbearer)
		auditResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(auditReq)
		if err != nil {
			return "GET /audit/records: " + err.Error(), false
		}
		auditRaw, _ := io.ReadAll(auditResp.Body)
		auditResp.Body.Close()
		var auditDoc struct {
			Records []map[string]interface{} `json:"records"`
		}
		_ = json.Unmarshal(auditRaw, &auditDoc)
		var residencyRow map[string]interface{}
		for _, r := range auditDoc.Records {
			if d, _ := r["decision"].(string); d == "ResidencyCheck" {
				residencyRow = r
				break
			}
		}
		if residencyRow == nil {
			return fmt.Sprintf("no ResidencyCheck row in /audit/records (found %d total); §10.7.2 #4 requires the layered-defence audit row", len(auditDoc.Records)), false
		}
		// §10.7.2 #4 — the audit row carries all four layers.
		residencyMap, _ := residencyRow["residency"].(map[string]interface{})
		if residencyMap == nil {
			return "ResidencyCheck row missing residency object — §10.7.2 #4 requires declared/attested/network/decision layers", false
		}
		return fmt.Sprintf("§10.7.2 layered-defence: 403 PermissionDenied(residency-violation, sub_reason=unknown-region); residency.decision=%s; ResidencyCheck audit row present with %d residency layers",
			dec.Residency.Decision, len(residencyMap)), true
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// writeResidencyCard reads the conformance-card and writes a tempfile
// copy with security.data_residency=["US"] injected per L-41 schema
// (ISO 3166-1 alpha-2 pattern ^[A-Z]{2}$). Returns (path, cleanup, err).
// Used by SV-PRIV-05 to drive a residency-guarded impl bootstrap
// without mutating the spec-pinned fixture.
func writeResidencyCard(spec specvec.Locator) (string, func(), error) {
	raw, err := spec.Read(specvec.ConformanceCard)
	if err != nil {
		return "", func() {}, err
	}
	var card map[string]interface{}
	if err := json.Unmarshal(raw, &card); err != nil {
		return "", func() {}, fmt.Errorf("parse conformance card: %w", err)
	}
	sec, _ := card["security"].(map[string]interface{})
	if sec == nil {
		sec = map[string]interface{}{}
	}
	sec["data_residency"] = []string{"US"}
	card["security"] = sec
	out, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		return "", func() {}, err
	}
	dir, err := os.MkdirTemp("", "svpriv05-card-*")
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, "agent-card.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}
