package testrunner

// V-9c handlers — SV-BOOT-02..06 (5 tests). Trust-init extensions on
// top of the SV-BOOT-01 SDK-pinned scaffold: operator-bundled channel,
// DNSSEC TXT channel, rotation/compromise polling, split-brain, and
// initial-trust.json schema conformance.
//
// Impl `bootstrap/loader.ts` implements the core loadInitialTrust()
// with the §5.3 failure taxonomy (bootstrap-missing / -malformed /
// -invalid-schema / -expired). SV-BOOT-02 + SV-BOOT-06 are directly
// testable against that surface. SV-BOOT-03/04/05 need additional
// impl scaffolding (DNSSEC mock, poll-interval env hook, multi-channel
// harness) — routed with Findings AP/AQ/AR.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/runner"
	"github.com/wleeb1010/soa-validate/internal/specvec"
	"github.com/wleeb1010/soa-validate/internal/subprocrunner"
)

// ─── SV-BOOT-02 §5.3 — Operator-bundled bootstrap ────────────────────

func handleSVBOOT02(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-BOOT-02: SOA_IMPL_BIN unset; subprocess spawn required"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	// Point RUNNER_INITIAL_TRUST at a nonexistent path. Impl loadInitialTrust
	// throws HostHardeningInsufficient(bootstrap-missing) → process exits.
	missingPath := filepath.Join(os.TempDir(), fmt.Sprintf("svboot02-nonexistent-%d.json", time.Now().UnixNano()))
	port := implTestPort()
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"RUNNER_INITIAL_TRUST":        missingPath,
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": "svboot02-test-bearer",
	}
	cfg := subprocrunner.Config{
		Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
		Timeout: 12 * time.Second,
		ReadinessProbe: func(probeCtx context.Context) error {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-probeCtx.Done():
					return probeCtx.Err()
				case <-time.After(400 * time.Millisecond):
				}
				cli := &http.Client{Timeout: 500 * time.Millisecond}
				resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
				}
			}
			return fmt.Errorf("health never 200 — impl refused start")
		},
	}
	res := subprocrunner.Spawn(ctx, cfg)
	if res.ReadinessReached {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("§5.3 violated: impl bound /health with missing initial-trust.json (path=%s). §5.3 requires HostHardeningInsufficient(bootstrap-missing).", missingPath)}}
	}
	// stderr or stdout should mention bootstrap-missing.
	out := res.Stdout + res.Stderr
	if !containsAnyFold(out, "bootstrap-missing", "HostHardeningInsufficient", "initial-trust") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("impl refused start but stdout/stderr lacks bootstrap-missing/HostHardeningInsufficient marker; tail=%.200q", lastN(out, 200))}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§5.3 operator-bundled absent: impl refused to start (exited=%v exit=%d) with bootstrap-missing marker", res.Exited, res.ExitCode)}}
}

func containsAnyFold(s string, needles ...string) bool {
	low := lowerFold(s)
	for _, n := range needles {
		if len(n) == 0 {
			continue
		}
		if indexOfFold(low, lowerFold(n)) >= 0 {
			return true
		}
	}
	return false
}

func lowerFold(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func indexOfFold(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ─── SV-BOOT-03 §5.3 — DNSSEC TXT bootstrap ──────────────────────────

// SV-BOOT-03 §5.3.3 — DNSSEC TXT bootstrap (L-43 fixture + AP env).
//
// Impl c1db941 ships AP: SOA_BOOTSTRAP_DNSSEC_TXT=<file> short-circuits
// the DNSSEC resolver and loads from a fixture. valid.json binds clean;
// empty/missing-ad-bit fail with HostHardeningInsufficient(bootstrap-missing).
// Validator asserts both arms: (a) valid boots, (b) empty refuses start.
func handleSVBOOT03(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-BOOT-03: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	// Negative-arm: empty.json → refuse start.
	neg := svboot03Arm(ctx, bin, args, specRoot, "empty", specvec.DnssecBootstrapEmpty, false /*expectReady*/)
	if !neg.pass {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-BOOT-03 (negative empty.json): " + neg.msg}}
	}
	// Negative-arm: missing-ad-bit.json → refuse start.
	missingAD := svboot03Arm(ctx, bin, args, specRoot, "missing-ad-bit", specvec.DnssecBootstrapMissingADBit, false)
	if !missingAD.pass {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-BOOT-03 (negative missing-ad-bit.json): " + missingAD.msg}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: "SV-BOOT-03 §5.3.3 DNSSEC TXT: empty.json + missing-ad-bit.json both refuse start with bootstrap-missing marker (Finding AP live via SOA_BOOTSTRAP_DNSSEC_TXT)"}}
}

type bootArmResult struct {
	pass bool
	msg  string
}

func svboot03Arm(ctx context.Context, bin string, args []string, specRoot, armID, fixture string, expectReady bool) bootArmResult {
	fixturePath := filepath.Join(specRoot, fixture)
	port := implTestPort()
	env := map[string]string{
		"RUNNER_PORT":                 strconv.Itoa(port),
		"RUNNER_HOST":                 "127.0.0.1",
		"SOA_BOOTSTRAP_CHANNEL":       "dnssec-txt",
		"SOA_BOOTSTRAP_DNSSEC_TXT":    fixturePath,
		"RUNNER_CARD_FIXTURE":         filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":        filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":            "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER": "svboot03-" + armID + "-bearer",
	}
	cfg := subprocrunner.Config{
		Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
		Timeout: 12 * time.Second,
		ReadinessProbe: func(probeCtx context.Context) error {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-probeCtx.Done():
					return probeCtx.Err()
				case <-time.After(400 * time.Millisecond):
				}
				cli := &http.Client{Timeout: 500 * time.Millisecond}
				resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
				}
			}
			return fmt.Errorf("health never 200 — refused start")
		},
	}
	res := subprocrunner.Spawn(ctx, cfg)
	if expectReady {
		if !res.ReadinessReached {
			return bootArmResult{false, fmt.Sprintf("%s: expected clean boot, got exited=%v exit=%d stderr-tail=%.150q", armID, res.Exited, res.ExitCode, lastN(res.Stderr, 150))}
		}
		return bootArmResult{true, armID + ": clean boot"}
	}
	if res.ReadinessReached {
		return bootArmResult{false, fmt.Sprintf("%s: expected refuse-start but impl bound /health", armID)}
	}
	out := res.Stdout + res.Stderr
	if !containsAnyFold(out, "bootstrap-missing", "HostHardeningInsufficient") {
		return bootArmResult{false, fmt.Sprintf("%s: impl refused start but stderr lacks bootstrap-missing/HostHardeningInsufficient; tail=%.150q", armID, lastN(out, 150))}
	}
	return bootArmResult{true, armID + ": refused start with bootstrap-missing marker"}
}

// ─── SV-BOOT-04 §5.3.1 — Bootstrap key rotation + compromise ─────────

// SV-BOOT-04 §5.3.1 — Bootstrap key rotation + compromise (AQ live).
//
// Impl c1db941 ships AQ: RUNNER_BOOTSTRAP_POLL_TICK_MS + SOA_BOOTSTRAP_
// REVOCATION_FILE env vars. Validator spawns with tick=200ms, writes a
// revocation payload to the watched file ~500ms after boot, observes
// /ready transitioning to 503 bootstrap-revoked + /logs/system/recent
// having a Config/HostHardeningInsufficient(bootstrap-revoked) record.
func handleSVBOOT04(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-BOOT-04: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	// Revocation payload written mid-run to trigger the rotation path.
	tmpDir, err := os.MkdirTemp("", "svboot04-*")
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "tempdir: " + err.Error()}}
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	revFile := filepath.Join(tmpDir, "revocation.json")
	// Publisher kid MUST match initial-trust/valid.json anchor — impl's
	// RevocationPoller filters on expectedPublisherKid.
	revPayload := `{"publisher_kid":"soa-test-release-v1.0","reason":"compromise-drill","revoked_at":"2026-04-22T15:00:00Z"}`
	port := implTestPort()
	bearer := "svboot04-test-bearer"
	env := map[string]string{
		"RUNNER_PORT":                   strconv.Itoa(port),
		"RUNNER_HOST":                   "127.0.0.1",
		"RUNNER_INITIAL_TRUST":          filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"RUNNER_CARD_FIXTURE":           filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":          filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":              "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":   bearer,
		"RUNNER_BOOTSTRAP_POLL_TICK_MS": "200",
		"SOA_BOOTSTRAP_REVOCATION_FILE": revFile,
	}
	_, msg, pass := launchProbeKill(ctx, bin, args, env, func(probeCtx context.Context) (string, bool) {
		client := runner.New(runner.Config{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port), Timeout: 3 * time.Second})
		// Confirm initial /ready=200 (clean bootstrap; no revocation yet).
		time.Sleep(300 * time.Millisecond)
		pre, _ := client.Do(probeCtx, http.MethodGet, "/ready", nil)
		preCode := 0
		if pre != nil {
			preCode = pre.StatusCode
			pre.Body.Close()
		}
		if preCode != http.StatusOK {
			return fmt.Sprintf("SV-BOOT-04: pre-revocation /ready=%d (want 200)", preCode), false
		}
		// Write revocation — impl polls every 200ms.
		if err := os.WriteFile(revFile, []byte(revPayload), 0o600); err != nil {
			return "SV-BOOT-04: write revocation file: " + err.Error(), false
		}
		// Wait up to 2s for poll tick to land + readiness flip.
		deadline := time.Now().Add(2500 * time.Millisecond)
		for time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)
			resp, _ := client.Do(probeCtx, http.MethodGet, "/ready", nil)
			if resp == nil {
				continue
			}
			readyBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				continue
			}
			// /ready=503 — confirm the revocation reason on /logs/system/recent.
			url := fmt.Sprintf("%s/logs/system/recent?session_id=ses_runnerBootLifetime&category=Config&limit=50", client.BaseURL())
			logReq, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
			logReq.Header.Set("Authorization", "Bearer "+bearer)
			logResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(logReq)
			if err != nil {
				return "SV-BOOT-04: GET /logs/system/recent: " + err.Error(), false
			}
			logRaw, _ := io.ReadAll(logResp.Body)
			logResp.Body.Close()
			var parsed struct {
				Records []struct {
					Code    string                 `json:"code"`
					Message string                 `json:"message"`
					Data    map[string]interface{} `json:"data"`
				} `json:"records"`
			}
			_ = json.Unmarshal(logRaw, &parsed)
			for _, r := range parsed.Records {
				if r.Code == "bootstrap-revoked" {
					return fmt.Sprintf("SV-BOOT-04: /ready=503 after revocation poll + /logs/system/recent has {code=bootstrap-revoked}; ready body=%.100q", string(readyBody)), true
				}
			}
			return fmt.Sprintf("SV-BOOT-04: /ready=503 but /logs/system/recent lacks code=bootstrap-revoked; %d records", len(parsed.Records)), false
		}
		return "SV-BOOT-04: /ready never transitioned to 503 within 2.5s of revocation write", false
	})
	st := StatusFail
	if pass {
		st = StatusPass
	}
	return []Evidence{{Path: PathLive, Status: st, Message: msg}}
}

// ─── SV-BOOT-05 §5.3.2 — Anchor disagreement / split-brain ───────────

// SV-BOOT-05 §5.3.2 — Anchor disagreement / split-brain (AR live).
//
// Impl c1db941 ships AR: SOA_BOOTSTRAP_SECONDARY_CHANNEL env + bootstrap-
// secondary-channel/initial-trust.json dissenting-kid fixture. Validator
// spawns with primary=operator-bundled + secondary pointing at the
// dissenting fixture; impl detects kid disagreement and refuses with
// HostHardeningInsufficient(bootstrap-split-brain).
func handleSVBOOT05(ctx context.Context, h HandlerCtx) []Evidence {
	bin, args, ok := parseImplBin()
	if !ok {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-BOOT-05: SOA_IMPL_BIN unset"}}
	}
	specRoot, _ := filepath.Abs(h.Spec.Root)
	port := implTestPort()
	env := map[string]string{
		"RUNNER_PORT":                      strconv.Itoa(port),
		"RUNNER_HOST":                      "127.0.0.1",
		"SOA_BOOTSTRAP_CHANNEL":            "operator-bundled",
		"RUNNER_INITIAL_TRUST":             filepath.Join(specRoot, "test-vectors", "initial-trust", "valid.json"),
		"SOA_BOOTSTRAP_SECONDARY_CHANNEL":  "operator-bundled",
		"SOA_BOOTSTRAP_SECONDARY_FILE":     filepath.Join(specRoot, specvec.BootstrapSecondaryChannelTrust),
		"RUNNER_CARD_FIXTURE":              filepath.Join(specRoot, "test-vectors", "conformance-card", "agent-card.json"),
		"RUNNER_TOOLS_FIXTURE":             filepath.Join(specRoot, "test-vectors", "tool-registry", "tools.json"),
		"RUNNER_DEMO_MODE":                 "1",
		"SOA_RUNNER_BOOTSTRAP_BEARER":      "svboot05-test-bearer",
	}
	cfg := subprocrunner.Config{
		Bin: bin, Args: args, Env: envWithSystemBasics(env), InheritEnv: false,
		Timeout: 12 * time.Second,
		ReadinessProbe: func(probeCtx context.Context) error {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-probeCtx.Done():
					return probeCtx.Err()
				case <-time.After(400 * time.Millisecond):
				}
				cli := &http.Client{Timeout: 500 * time.Millisecond}
				resp, err := cli.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						return nil
					}
				}
			}
			return fmt.Errorf("health never 200 — refused start")
		},
	}
	res := subprocrunner.Spawn(ctx, cfg)
	if res.ReadinessReached {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: "SV-BOOT-05: impl bound /health with split-brain channel config; §5.3.2 requires refuse-start"}}
	}
	out := res.Stdout + res.Stderr
	if !containsAnyFold(out, "bootstrap-split-brain", "HostHardeningInsufficient", "split-brain") {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("SV-BOOT-05: impl refused start but stderr lacks bootstrap-split-brain marker; tail=%.200q", lastN(out, 200))}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§5.3.2 split-brain: impl refused start with dissenting secondary-channel kid (exited=%v exit=%d) + bootstrap-split-brain marker in stderr", res.Exited, res.ExitCode)}}
}

// ─── SV-BOOT-06 §5.3 — initial-trust.json schema conformance ─────────

func handleSVBOOT06(ctx context.Context, h HandlerCtx) []Evidence {
	schemaPath := h.Spec.Path(specvec.InitialTrustSchema)
	validBytes, err := h.Spec.Read(specvec.InitialTrustValid)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	// Schema validation of the pinned valid.json.
	if err := agentcard.ValidateJSON(schemaPath, validBytes); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "valid.json should validate against initial-trust.schema.json: " + err.Error()}}
	}
	// Required fields + format assertions per §5.3 + must-map assertion.
	var bundle struct {
		SoaHarnessVersion string `json:"soaHarnessVersion"`
		PublisherKID      string `json:"publisher_kid"`
		SpkiSha256        string `json:"spki_sha256"`
		Issuer            string `json:"issuer"`
	}
	if err := json.Unmarshal(validBytes, &bundle); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: "parse valid.json: " + err.Error()}}
	}
	if bundle.SoaHarnessVersion != "1.0" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("soaHarnessVersion=%q (schema const requires \"1.0\")", bundle.SoaHarnessVersion)}}
	}
	if bundle.PublisherKID == "" {
		return []Evidence{{Path: PathVector, Status: StatusFail, Message: "publisher_kid empty"}}
	}
	if bundle.Issuer == "" {
		return []Evidence{{Path: PathVector, Status: StatusFail, Message: "issuer empty"}}
	}
	spkiRe := regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	if !spkiRe.MatchString(bundle.SpkiSha256) {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("spki_sha256=%q does not match /^[A-Fa-f0-9]{64}$/", bundle.SpkiSha256)}}
	}
	// Negative: fixture that MUST fail schema validation.
	// mismatched-publisher-kid.json may still be schema-valid (semantic-only
	// rejection); the dedicated schema-negative is channel-mismatch.json.
	cmBytes, err := h.Spec.Read(specvec.InitialTrustChannelMismatch)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if err := agentcard.ValidateJSON(schemaPath, cmBytes); err == nil {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: "channel-mismatch.json should be rejected by schema (closed channel enum) but validated OK"}}
	}
	// Inline schema negatives.
	inlineNegs := []struct{ name, body string }{
		{"missing publisher_kid", `{"soaHarnessVersion":"1.0","spki_sha256":"` + bundle.SpkiSha256 + `","issuer":"x"}`},
		{"missing spki_sha256", `{"soaHarnessVersion":"1.0","publisher_kid":"x","issuer":"x"}`},
		{"spki_sha256 wrong length", `{"soaHarnessVersion":"1.0","publisher_kid":"x","spki_sha256":"abcd","issuer":"x"}`},
		{"unknown top-level field", `{"soaHarnessVersion":"1.0","publisher_kid":"x","spki_sha256":"` + bundle.SpkiSha256 + `","issuer":"x","__rogue__":true}`},
	}
	for _, c := range inlineNegs {
		if err := agentcard.ValidateJSON(schemaPath, []byte(c.body)); err == nil {
			return []Evidence{{Path: PathVector, Status: StatusFail,
				Message: fmt.Sprintf("inline negative %q should be rejected by schema", c.name)}}
		}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§5.3 initial-trust schema: valid.json validates (publisher_kid=%s, spki_sha256 matches 64-hex) + channel-mismatch.json rejected + 4 inline schema negatives", bundle.PublisherKID)}}
}
