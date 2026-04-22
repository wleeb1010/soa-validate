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
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
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

func handleSVBOOT03(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-BOOT-03 (§5.3.3 DNSSEC TXT bootstrap): L-43 ships the fixture trio " +
			"test-vectors/dnssec-bootstrap/{valid,empty,missing-ad-bit}.json + normative SOA_BOOTSTRAP_DNSSEC_TXT env hook. " +
			"Awaiting impl ship of the hook — Runner must short-circuit DNSSEC resolver when the env points at a fixture file, " +
			"bind on valid.json, HostHardeningInsufficient(bootstrap-missing) on empty.json + missing-ad-bit.json."}}
}

// ─── SV-BOOT-04 §5.3.1 — Bootstrap key rotation + compromise ─────────

func handleSVBOOT04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-BOOT-04 (§5.3.1 bootstrap rotation + compromise): L-43 ships normative RUNNER_BOOTSTRAP_POLL_TICK_MS + " +
			"SOA_BOOTSTRAP_REVOCATION_FILE env vars (production-guard loopback-only, same shape as AC/AD/AH/AK). " +
			"Awaiting impl ship — validator probe will subprocess with tick=200ms, write a revocation update to the watched file " +
			"after first poll, observe Card rejection with HostHardeningInsufficient(bootstrap-revoked) + SI halt + " +
			"SuspectDecision audit flags on MANIFEST JWS accepted in the preceding 24h."}}
}

// ─── SV-BOOT-05 §5.3.2 — Anchor disagreement / split-brain ───────────

func handleSVBOOT05(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-BOOT-05 (§5.3.2 split-brain): L-43 ships normative SOA_BOOTSTRAP_SECONDARY_CHANNEL env + " +
			"test-vectors/bootstrap-secondary-channel/initial-trust.json dissenting-kid fixture. Awaiting impl ship — " +
			"validator probe will subprocess with primary channel + SOA_BOOTSTRAP_SECONDARY_CHANNEL pointing at the dissenting " +
			"fixture, observe HostHardeningInsufficient(bootstrap-split-brain) + SI halt per §5.3.2."}}
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
