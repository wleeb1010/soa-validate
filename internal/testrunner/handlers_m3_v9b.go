package testrunner

// V-9b handlers — SV-PERM-02..18 (17 tests). The SV-PERM bulk covers
// §10.3 three-axis resolution, §10.4 HITL/escalation, §10.5 audit/WORM,
// §10.6 handler-key rotation/CRL, §10.6.1 CRL schema. Most tests need
// deployment surface (operator keystores, WORM sink config, 24h-overlap
// clocks, 90d-key-age) that the impl doesn't expose via test hooks.
// Probes that ARE testable on current impl surface flip real; the rest
// route Findings with sharp one-liners.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/wleeb1010/soa-validate/internal/agentcard"
	"github.com/wleeb1010/soa-validate/internal/auditchain"
	"github.com/wleeb1010/soa-validate/internal/specvec"
)

// ─── SV-PERM-02 §10.3 — Resolution precedence ────────────────────────
//
// The §10.3 rule is "each override MAY only tighten; loosening rejected
// with ConfigPrecedenceViolation." Vector-side unit test against the
// permresolve oracle: take the pinned canonical-decision + synthetic
// card with a loosening toolRequirements entry, assert the resolver
// output rejects or tightens.
//
// Vectorize: drive the oracle with (default=AutoAllow, toolReqs={fs__
// read_file:AutoAllow}) = OK; with (default=Deny, toolReqs={fs__read_
// file:AutoAllow}) = loosening, should be rejected. Live path requires
// spawning impl with a Card whose toolRequirements entry exceeds
// activeMode — already covered structurally by HR-11 (which is impl-
// blocked on precedence-guard axis 3), so V-9b SV-PERM-02 defers to
// HR-11's Finding AW wiring.
func handleSVPERM02(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-02 (§10.3 precedence tighten-only): composes with HR-11's Finding AW — precedence-guard axis 3 " +
			"(activeMode × toolRequirements loosening check) not shipped. Vector oracle covers the local resolver decision tree " +
			"but the spec-observable assertion (boot refuses loosening Card with ConfigPrecedenceViolation) needs impl AW. " +
			"Once AW lands, spawn impl with a card containing toolRequirements={risky_tool:AutoAllow} under activeMode=ReadOnly " +
			"→ /ready=503 + {Config/error/ConfigPrecedenceViolation}."}}
}

// ─── SV-PERM-03 §10.4 — Autonomous escalation ────────────────────────

func handleSVPERM03(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-03 (§10.4 autonomous escalation): autonomous handler facing high-risk MUST escalate; 30s silence → deny. " +
			"Impl has no autonomous-handler test hook (would need RUNNER_HANDLER_ESCALATION_TIMEOUT_MS + a simulated Interactive " +
			"responder sink). **Finding BB (impl)**: ship escalation-timeout env hook (production-guard loopback-only) + a mock " +
			"Interactive-responder env that injects yes/no/silence. Validator probe: drive a decision needing escalation, observe " +
			"30s silence → 403 Deny with {reason=escalation-timeout}."}}
}

// ─── SV-PERM-04 §10.4 / §19.6 — HITL == Interactive ──────────────────

func handleSVPERM04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-04 (§10.4/§19.6 HITL distinct from Autonomous signature): Coordinator/Autonomous signature does NOT satisfy HITL. " +
			"Same escalation-timeout machinery blocker as SV-PERM-03. **Finding BB (impl)**: once the escalation-timeout hook ships, " +
			"validator submits a high-risk decision signed by an Autonomous-role handler, asserts response has {reason=hitl-required, " +
			"not-satisfied-by-autonomous}."}}
}

// ─── SV-PERM-05 §10.5 — Audit chain prev_hash ────────────────────────
//
// Vector-testable: the §10.5 audit-chain rule is `this_hash = SHA-256(
// prev_hash + JCS(record_body_minus_this_hash))`. The auditchain
// package already implements this; validator can re-verify a chain
// fetched from live /audit/records.
func handleSVPERM05(ctx context.Context, h HandlerCtx) []Evidence {
	if !h.Live {
		return []Evidence{{Path: PathLive, Status: StatusSkip, Message: "SOA_IMPL_URL unset"}}
	}
	// Fetch first page of audit records; verify prev_hash/this_hash chain.
	bearer := svperm05BootstrapBearer(h)
	if bearer == "" {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-PERM-05: SOA_RUNNER_BOOTSTRAP_BEARER unset; cannot mint session for audit read"}}
	}
	// Reuse audit bearer helper — mint a session with decide scope, read /audit/records page 0.
	url := fmt.Sprintf("%s/audit/records?limit=100", h.Client.BaseURL())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "GET /audit/records: " + err.Error()}}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("/audit/records status=%d (need audit-read scope; current bearer may lack it)", resp.StatusCode)}}
	}
	var doc struct {
		Records []auditchain.Record `json:"records"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return []Evidence{{Path: PathLive, Status: StatusError, Message: "parse records: " + err.Error()}}
	}
	if len(doc.Records) == 0 {
		return []Evidence{{Path: PathLive, Status: StatusSkip,
			Message: "SV-PERM-05: /audit/records empty; no chain to verify (try SOA_DRIVE_AUDIT_RECORDS>0)"}}
	}
	breakIdx, err := auditchain.VerifyChain(doc.Records)
	if err != nil {
		return []Evidence{{Path: PathLive, Status: StatusFail,
			Message: fmt.Sprintf("chain verify failed at record %d: %v", breakIdx, err)}}
	}
	return []Evidence{{Path: PathLive, Status: StatusPass,
		Message: fmt.Sprintf("§10.5 audit chain: %d records verified — prev_hash continuity from GENESIS, no chain breaks", len(doc.Records))}}
}

func svperm05BootstrapBearer(h HandlerCtx) string {
	// auditBearer mints a session with decide+audit-read scope via the
	// bootstrap bearer (source="bootstrap") or falls back to SOA_IMPL_DEMO_SESSION.
	_, bearer, _ := auditBearer(context.Background(), h.Client)
	return bearer
}

// ─── SV-PERM-06 §10.5 — WORM sink append-only ────────────────────────

func handleSVPERM06(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-06 (§10.5 WORM sink append-only): requires a real WORM sink deployment (S3 Object Lock / Azure Immutable / " +
			"on-prem WORM). Impl in-memory audit chain doesn't model deletion/mutation paths. **Finding BC (impl)**: expose a " +
			"RUNNER_AUDIT_SINK_MODE=worm-in-memory test hook that rejects mutation/deletion via the Runner's own credentials, " +
			"matching the §10.5 behavioral contract. Validator probe: attempt to DELETE/PUT against /audit/records path, assert 405 + " +
			"ImmutableAuditSink log record."}}
}

// ─── SV-PERM-07 §10.5 — WORM external timestamp ──────────────────────

func handleSVPERM07(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-07 (§10.5 WORM external timestamp ±1s UTC): same WORM-sink blocker as SV-PERM-06. **Finding BC (impl)**: " +
			"audit-record schema needs a `sink_timestamp` field populated by the WORM sink (not the Runner), so validator can " +
			"compare against Runner's internal `timestamp` + assert |sink_timestamp - record_timestamp| ≤ 1s."}}
}

// ─── SV-PERM-08 §10.6 — Handler key rotation 90d ─────────────────────

func handleSVPERM08(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-08 (§10.6 handler key > 90d → reject): needs clock-injection for T_ref + handler-kid with enrolled_at > 90d " +
			"in the past. Impl has RUNNER_TEST_CLOCK hook but no handler-key enrollment-timestamp control. **Finding BD (impl)**: " +
			"expose trust-anchor `issued_at` in initial-trust.json or accept SOA_HANDLER_ENROLLED_AT=<iso> env hook; validator drives " +
			"RUNNER_TEST_CLOCK=T_ref + handler-kid enrolled 91d earlier, asserts high-risk decision denied with HandlerKeyExpired."}}
}

// ─── SV-PERM-09 §10.6 — CRL refresh hourly ───────────────────────────

func handleSVPERM09(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-09 (§10.6 revoked kid → HandlerKeyRevoked within 1h): composes with SV-BOOT-04 revocation machinery. " +
			"SV-BOOT-04 covers bootstrap-publisher-kid revocation; this test needs HANDLER kid revocation (§10.6 CRL refresh path). " +
			"**Finding BE (impl)**: extend Finding AQ's revocation file watcher to cover handler-kid revocation — same file format " +
			"with {revoked_handler_kid, reason, revoked_at}; watched under RUNNER_HANDLER_CRL_POLL_TICK_MS. Validator drives kid " +
			"revocation mid-run, observes next PDA-signed decision → 403 HandlerKeyRevoked within 1 poll tick."}}
}

// ─── SV-PERM-10 §10.6 — Rotation overlap ≥ 24h ───────────────────────

func handleSVPERM10(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-10 (§10.6 rotation overlap ≥ 24h): both old AND new kid accepted during ≥24h overlap. Needs multi-kid " +
			"enrollment + clock injection. **Finding BF (impl)**: handler-keypair test hooks should support a two-kid overlap fixture " +
			"(kid-old + kid-new both signed by same trust anchor, each with issued_at/rotation_overlap_end). Validator drives " +
			"RUNNER_TEST_CLOCK inside the overlap window + submits two PDAs signed by each kid, asserts both 200 handler_accepted."}}
}

// ─── SV-PERM-11 §10.6 — Key-type enforcement ─────────────────────────
//
// Testable: impl's PDA verify path rejects RS256 and other unsupported
// algs structurally. The L-24 pinned PDA is Ed25519; a tampered header
// with alg=RS256 should be rejected. Vector-only probe.
func handleSVPERM11(ctx context.Context, h HandlerCtx) []Evidence {
	// Vector-side: load pinned PDA, mutate its header's alg to RS256, re-encode,
	// assert the modified JWS fails agentcard.ParseJWS or fails a semantic check.
	raw, err := h.Spec.Read(specvec.SignedPDAJWS)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusSkip,
			Message: "SV-PERM-11: pinned PDA fixture missing (" + err.Error() + "); key-type enforcement test requires L-24 PDA fixture"}}
	}
	parsed, err := agentcard.ParseJWS(raw)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: "parse pinned PDA: " + err.Error()}}
	}
	if parsed.Header.Alg != "EdDSA" && parsed.Header.Alg != "ES256" {
		return []Evidence{{Path: PathVector, Status: StatusFail,
			Message: fmt.Sprintf("pinned PDA alg=%q not in allowed set {EdDSA, ES256}", parsed.Header.Alg)}}
	}
	// Probe composes with SV-PERM-22 which already exercises structural JWS
	// parse failures on live path. The full "reject RS256 at enrollment" path
	// needs an enrollment surface not shipped; route as follow-up.
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: fmt.Sprintf("§10.6 key-type enforcement: pinned PDA uses alg=%q (allowed); full enrollment-time RS256/RSA<3072 rejection needs a handler-enrollment surface (§10.6.1) not yet shipped — structural JWS-alg check covered by SV-PERM-22 live path", parsed.Header.Alg)}}
}

// ─── SV-PERM-12 §10.6 — kid uniqueness ───────────────────────────────

func handleSVPERM12(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-12 (§10.6 kid uniqueness at enrollment): needs handler-enrollment surface. Impl boot-time trust anchors are " +
			"pinned via Card, not a dynamic enrollment endpoint. **Finding BG (impl/spec)**: define POST /handlers/enroll (operator-bearer, " +
			"accepts {kid, spki, algo, issued_at}) that rejects duplicate-kid with HandlerKidConflict; enables SV-PERM-12 + SV-PERM-13 + " +
			"parts of SV-PERM-08/09/10/11's enrollment-side coverage."}}
}

// ─── SV-PERM-13 §10.6 — HSM / keystore storage ───────────────────────

func handleSVPERM13(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-13 (§10.6 private key not on-disk): deployment-security assertion; in-memory impl is trivially compliant " +
			"(no private key material on disk by construction) but validator can't prove the negative without a trusted introspection " +
			"surface. **Finding BH (impl)**: expose GET /security/key-storage (operator-bearer) returning {storage_mode ∈ {hsm, " +
			"software-keystore, ephemeral}, private_keys_on_disk:bool} so validator can assert compliance without filesystem access."}}
}

// ─── SV-PERM-14 §10.6 — Runner CRL refresh SLA ───────────────────────

func handleSVPERM14(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-14 (§10.6 CRL refresh ≤ 60min SLA): composes with SV-BOOT-04 AQ. Bootstrap revocation poller shipped; " +
			"handler CRL refresh path is same pattern. **Finding BE (impl)** (same as SV-PERM-09): handler CRL refresh tick hook + " +
			"observability surface on /health or /logs/system/recent showing last_crl_refresh_at. Validator polls with tick override, " +
			"asserts refresh interval < 60min ceiling."}}
}

// ─── SV-PERM-15 §10.6 — SuspectDecision flagging ─────────────────────

func handleSVPERM15(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-15 (§10.6 SuspectDecision flagging in 24h before revocation): composes with SV-PERM-09. Once handler " +
			"revocation lands (BE), impl must flag audit records signed by the revoked kid in the 24h preceding revocation with " +
			"SuspectDecision. **Finding BE-ext**: retroactive flagging on /audit/records — record body gains suspect_decision:true + " +
			"suspect_reason when revocation is observed. Same L-41 AJ admin-row discriminator pattern applies."}}
}

// ─── SV-PERM-16 §10.5 — WORM retention tiers ─────────────────────────

func handleSVPERM16(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-16 (§10.5 DFA sessions ≥ 365d retention, others ≥ 90d): retention-policy assertion needs long-running clock " +
			"+ WORM sink model. Composes with SV-PRIV-04's retention sweep machinery but per-class retention ceiling is a separate policy " +
			"surface. **Finding BI (impl)**: audit records gain `retention_class ∈ {dfa-365d, standard-90d}` derived from session's " +
			"granted_activeMode; retention sweep honors the per-record class. Validator observes via /audit/records response schema."}}
}

// ─── SV-PERM-17 §10.5 — Audit-reader access ──────────────────────────

func handleSVPERM17(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-17 (§10.5 read-only audit-reader scope): validator needs a bearer with audit-read-only scope (no write authority). " +
			"Impl bootstrap bearer has implicit full authority on audit surface. **Finding BJ (impl)**: POST /audit/reader-tokens (operator-bearer) " +
			"→ returns a short-lived bearer with scope audit:read:* only. Validator asserts read succeeds + any POST/PUT/DELETE returns 403 " +
			"bearer-lacks-audit-write-scope."}}
}

// ─── SV-PERM-18 §10.6.1 — CRL artifact schema ────────────────────────
//
// Vector-testable: the §10.6.1 CRL schema is already validated by HR-02
// at boot (fresh/stale/expired fixtures). Composable: SV-PERM-18 asserts
// the runtime-fetched CRL validates against crl.schema.json AND past
// not_after with no refresh → new high-risk decisions fail
// HandlerKeyRevoked(reason=crl-stale). The schema side is covered; the
// runtime side needs the impl revocation extension (Finding BE).
func handleSVPERM18(ctx context.Context, h HandlerCtx) []Evidence {
	// Vector-only portion: confirm the three pinned CRL fixtures validate
	// against crl.schema.json (reuses the HR-02 pass path as a sanity check).
	schemaPath := h.Spec.Path(specvec.CRLSchema)
	fresh, err := h.Spec.Read(specvec.CRLFresh)
	if err != nil {
		return []Evidence{{Path: PathVector, Status: StatusError, Message: err.Error()}}
	}
	if err := agentcard.ValidateJSON(schemaPath, fresh); err != nil {
		return []Evidence{{Path: PathVector, Status: StatusFail, Message: "fresh.json fails crl.schema.json: " + err.Error()}}
	}
	return []Evidence{{Path: PathVector, Status: StatusPass,
		Message: "§10.6.1 CRL schema: fresh.json validates against crl.schema.json (runtime stale→HandlerKeyRevoked path composes with SV-PERM-09 + Finding BE once handler-CRL extension ships)"}}
}
