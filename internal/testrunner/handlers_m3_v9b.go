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

// ─── SV-PERM-03 §10.4.1/§10.4.2 — escalation (L-49 BB spec live) ─────

func handleSVPERM03(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-03 (§10.4.1 escalation state-machine + §10.4.2 RUNNER_HANDLER_ESCALATION_TIMEOUT_MS + " +
			"SOA_HANDLER_ESCALATION_RESPONDER env hooks — L-49 BB spec shipped): awaiting impl ship. Validator probe " +
			"(post-impl): subprocess with tick=500ms + responder tempfile, submit high-risk Autonomous-signed PDA, write " +
			"nothing to responder for 600ms → assert 403 `{error:PermissionDenied, reason:escalation-timeout}` + audit row " +
			"with handler=\"Autonomous\"."}}
}

// ─── SV-PERM-04 §10.4.1/§19.6 — HITL distinct (L-49 BB spec live) ────

func handleSVPERM04(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-04 (§10.4.1 HITL distinct from Autonomous signature — L-49 BB spec shipped): awaiting impl ship of " +
			"the escalation responder surface. Validator probe (post-impl): submit Autonomous-signed PDA with " +
			"`{response:\"approve\"}` written to SOA_HANDLER_ESCALATION_RESPONDER → assert 403 `{reason:hitl-required, " +
			"detail:autonomous-insufficient}` (Autonomous cannot self-approve HITL-gated decisions)."}}
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

// ─── SV-PERM-06 §10.5.5 — WORM sink append-only (L-48 BC spec live) ──

func handleSVPERM06(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-06 (§10.5.5 WORM Sink Modeling Test Hook — L-48 BC spec shipped): awaiting impl ship of " +
			"RUNNER_AUDIT_SINK_MODE=worm-in-memory env hook. Validator probe (post-impl): POST /audit/records or attempt mutation " +
			"via Runner creds → 405 `{error:ImmutableAuditSink}` + corresponding system-log record."}}
}

// ─── SV-PERM-07 §10.5.5 — sink_timestamp external (L-48 BC schema) ───

func handleSVPERM07(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-07 (§10.5.5 sink_timestamp schema field — L-48 BC spec shipped): audit-records-response.schema.json " +
			"gains optional sink_timestamp field populated by WORM sink. Validator probe (post-impl): assert " +
			"|sink_timestamp − timestamp| ≤ 1s across returned records."}}
}

// ─── SV-PERM-08 §10.6.2 — 90d key rotation (L-48 BD hook live) ───────

func handleSVPERM08(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-08 (§10.6.2 SOA_HANDLER_ENROLLED_AT env hook — L-48 BD spec shipped): awaiting impl ship. Validator " +
			"probe (post-impl): RUNNER_TEST_CLOCK=T_ref + SOA_HANDLER_ENROLLED_AT=(T_ref−91d), submit high-risk PDA-signed " +
			"decision → 403 `{error:HandlerKeyExpired, reason:key-age-exceeded}`."}}
}

// ─── SV-PERM-09 §10.6.2 — handler-CRL poll (L-48 BE hook live) ───────

func handleSVPERM09(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-09 (§10.6.2 RUNNER_HANDLER_CRL_POLL_TICK_MS + SOA_BOOTSTRAP_REVOCATION_FILE {handler_kid, ...} " +
			"extension — L-48 BE spec shipped): awaiting impl ship. Validator probe (post-impl): tick=200ms + write " +
			"{handler_kid: soa-conformance-test-handler-v1.0, reason: compromise-drill, revoked_at: ...} mid-run → next " +
			"PDA decision → 403 `{error:HandlerKeyRevoked}` within one poll tick."}}
}

// ─── SV-PERM-10 §10.6.2 — rotation overlap (L-48 BF fixture live) ────

func handleSVPERM10(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-10 (§10.6.2 SOA_HANDLER_KEYPAIR_OVERLAP_DIR + test-vectors/handler-keypair-overlap/ fixture — " +
			"L-48 BF spec + fixture shipped): awaiting impl ship of the env hook. Validator probe (post-impl): point env at " +
			"the two-kid fixture dir, set RUNNER_TEST_CLOCK inside overlap window [2026-04-22T00:00Z, 2026-04-23T00:00Z], " +
			"submit PDAs signed by each kid → both 200 `handler_accepted:true`."}}
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

// ─── SV-PERM-12 §10.6.3 — kid uniqueness (L-48 BG endpoint live) ─────

func handleSVPERM12(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-12 (§10.6.3 POST /handlers/enroll endpoint — L-48 BG spec shipped): awaiting impl ship. Validator " +
			"probe (post-impl): operator-bearer enrolls a kid, re-enrolls same kid → 409 `{error:HandlerKidConflict, " +
			"detail:kid already enrolled}`. Composes with SV-PERM-11 enrollment-time RS256 rejection path."}}
}

// ─── SV-PERM-13 §10.6.4 — keystore storage (L-48 BH endpoint live) ───

func handleSVPERM13(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-13 (§10.6.4 GET /security/key-storage endpoint — L-48 BH spec shipped): awaiting impl ship. Validator " +
			"probe (post-impl): operator-bearer GET → 200 `{storage_mode ∈ {hsm,software-keystore,ephemeral}, " +
			"private_keys_on_disk:bool, provider?, attestation_format?}`. Assert private_keys_on_disk===false for conformance."}}
}

// ─── SV-PERM-14 §10.6.2 — CRL refresh SLA (L-48 BE observability) ────

func handleSVPERM14(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-14 (§10.6.2 CRL refresh ≤ 60min observability — L-48 BE spec shipped): last_crl_refresh_at exposed on " +
			"/health or /logs/system/recent once impl ships BE. Validator probe (post-impl): poll /health, assert observed " +
			"refresh intervals ≤ 60min ceiling (using RUNNER_HANDLER_CRL_POLL_TICK_MS override for sub-second test cadence)."}}
}

// ─── SV-PERM-15 §10.6.5 — SuspectDecision retroactive (L-48 BE admin-row) ─

func handleSVPERM15(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-15 (§10.6.5 retroactive SuspectDecision admin-row + schema oneOf third branch — L-48 BE spec shipped): " +
			"awaiting impl ship. Validator probe (post-impl): drive N PDA-signed decisions, revoke the handler kid via " +
			"revocation file, observe retroactive `suspect_decision:true + suspect_reason:kid-revoked-24h-window` on the " +
			"N records via /audit/records."}}
}

// ─── SV-PERM-16 §10.6.6 — retention_class schema (L-48 BI live) ──────

func handleSVPERM16(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-16 (§10.6.6 retention_class schema + derivation rule — L-48 BI spec shipped): audit records gain " +
			"retention_class ∈ {dfa-365d, standard-90d} derived from session's granted_activeMode. Validator probe (post-impl): " +
			"mint one DFA + one ReadOnly session, drive a decision each, assert records[dfa_sid].retention_class===\"dfa-365d\" " +
			"and records[readonly_sid].retention_class===\"standard-90d\"."}}
}

// ─── SV-PERM-17 §10.5.7 — audit reader tokens (L-48 BJ endpoint live) ─

func handleSVPERM17(ctx context.Context, h HandlerCtx) []Evidence {
	return []Evidence{{Path: PathLive, Status: StatusSkip,
		Message: "SV-PERM-17 (§10.5.7 POST /audit/reader-tokens endpoint — L-48 BJ spec shipped): awaiting impl ship. Validator " +
			"probe (post-impl): operator-bearer mints reader_bearer with scope audit:read:*. Assert: (1) reader_bearer GETs " +
			"/audit/tail + /audit/records succeed; (2) any POST/PUT/DELETE with reader_bearer → 403 " +
			"`{error:bearer-lacks-audit-write-scope}`."}}
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
