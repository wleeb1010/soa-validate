# STATUS — soa-validate

Daily log the sibling `soa-harness-impl` session reads on `git pull`. Most recent date on top.

---

## 2026-04-21 (M2 Week 1 Day 1 — foundation landed; pin bumped to 507eeb1)

**Done:**
- **Pin-bumped `8624a7a → 507eeb1`** adopting **L-27 M2 kickoff + L-28 M2 rev 2**. `spec_commit_sha = 507eeb1160adc79adf12c8bae669af1c0ed86ede`, `spec_manifest_sha256 = 0418932a2923452b95f484888f1cbdc64d5a591238d3578644d31abc359f03c0`. Reason: §12.5.1 byte-identity contract with `generated_at` exclusion (F-01), §12.5.2 audit-sink failure-mode hook, §12.5.3 crash-marker protocol (7 named markers), §12.5.4 `/audit/sink-events` channel, tool-registry-m2 fixtures, must-map expanded to 223.
- **Plan-SHA discrepancy flagged:** `docs/plans/m2.md` quotes `spec_commit_sha = 507eeb1b0a12f1a15830e9f826f7af7fa19afb74` — that value does not resolve in the spec repo. Real `git rev-parse HEAD` is `507eeb1160adc79adf12c8bae669af1c0ed86ede` (same 7-char prefix, diverges past char 7). Pinned to the real resolvable SHA and documented the discrepancy inline in the pin_history entry.
- **V2-02 Schema registry refresh:** added `SessionStateResponseSchema`, `AuditSinkEventsResponseSchema`, `SessionSchema`, and the three `ToolRegistryM2*` fixture paths to `internal/specvec/specvec.go`.
- **V2-04 V-15 crash-test harness shipped** (`internal/subprocrunner/killatmarker.go` + `killatmarker_test.go`). New `SpawnUntilMarker(ctx, cfg)` streams subprocess stderr line-by-line, kills on first occurrence of the configured `SOA_MARK_*` token, supports `PreKillDelay` for writes-to-land-first semantics. `CrashMarkers` constant catalog exported as the seven spec-defined markers. Four unit tests cover: happy-path kill-on-marker, timeout when marker never appears, PreKillDelay respected, self-exit-before-marker records true ExitCode. Runs against synthetic markers today; live-exercised once impl ships `RUNNER_CRASH_TEST_MARKERS=1`.
- **V2-10 SV-SESS-05 + SV-SESS-11 handlers wired** (`internal/testrunner/handlers_m2.go`): subprocess launches with tool-registry-m2 sub-fixtures. Positive arm: compliant-only fixture → boot clean → `/permissions/resolve?tool=compliant_ephemeral_tool` returns `Prompt`. Negative arm: non-compliant-only fixture → exit non-zero citing `ToolPoolStale` / `idempotency-retention-insufficient`. SV-SESS-11 additionally exercises the combined fixture's boot-refusal arm. Honest FAIL if impl permits a non-compliant entry (no workaround).
- **V2-11 SV-PERM-19 + SV-AUDIT-SINK-EVENTS-01 handlers wired**: three-arm subprocess sweep over `SOA_RUNNER_AUDIT_SINK_FAILURE_MODE ∈ {healthy, degraded-buffering, unreachable-halt}`. Polls `GET /audit/sink-events` (§12.5.4), asserts exactly-one matching `AuditSink*` event per L-28 F-13 fresh-boot contract, schema-validates response body on the SV-AUDIT-SINK-EVENTS-01 path. Emits SKIP when `/audit/sink-events` returns 404 (impl has not shipped §12.5.4 yet) so the scoreboard stays honest.
- **V2-03 V-14 session-state observer** + **SV-SESS-STATE-01 handler**: bootstraps session, reads `/sessions/<id>/state` twice rapidly, schema-validates, asserts `strip(body, "generated_at")`-byte-identity predicate per L-28 F-01 fix. SKIP when endpoint 404s.
- **Must-map test count** test updated 221 → 223.
- `go vet ./...` clean. Full unit-test suite green across 13 packages.

**Scoreboard impact (against an impl still shipping M2-T1a + M2-T6):**
- M1 IDs stay as they were (handlers unchanged, pin-bump has no M1 regressions).
- 5 new M2 IDs registered; without a live M2-enabled impl they SKIP with specific diagnostics. These flip green as impl ships — no validator-side change needed.

**Also shipped Day 1 afternoon (optional prep while waiting on impl M2-T3):**
- **V2-09b + V2-09c scaffolding** for the Week 3 crash-recovery matrix — 5 more handlers registered:
  - `SV-SESS-06` — §12.3 POSIX atomic-write conformance (kill between `COMMITTED_WRITE_DONE` + `DIR_FSYNC_DONE`).
  - `SV-SESS-07` — §12.3 Windows atomic-write conformance (same logical marker boundaries).
  - `SV-SESS-08` — §12.5 resume replays pending (kill at `PENDING_WRITE_DONE`, assert idempotent replay post-resume).
  - `SV-SESS-09` — §12.5 card-drift terminates resume (relaunch with mutated Agent Card card_version; assert `StopReason::CardVersionDrift`).
  - `SV-SESS-10` — §12.5 step 4 in-flight compensation (kill at `TOOL_INVOKE_START`, assert compensating action fires or `ResumeCompensationGap`).
- **New `internal/subprocrunner/relaunch.go`** — `RunCrashRecovery(cfg, probe)` composes the two-phase sequence: launch + kill-at-marker + relaunch against same session dir + /ready probe + post-relaunch callback + clean kill. Three unit tests exercise happy-path, marker-never-fires-graceful-skip, and full phase-2 relaunch-binds-HTTP probe via python synthetic markers. All green.
- Handlers today SKIP with specific diagnostics when `SOA_IMPL_BIN` unset OR `RUNNER_CRASH_TEST_MARKERS` unsupported. Flip automatically when impl ships markers (no validator-side code change required).
- `SV-SESS-09` additionally flags: spec has no pinned `card_version`-mutated Agent Card fixture yet — handler is wired but will stay SKIP until spec ships the drift fixture (L-29 candidate).

**10 M2 test IDs now wired.** Week 1 target: SV-SESS-05, SV-SESS-11, SV-PERM-19, SV-AUDIT-SINK-EVENTS-01, SV-SESS-STATE-01 (5). Week 3 target: SV-SESS-06..10 (5). All ready to flip as impl ships.

**Next:** Hold Week 1 through M2-T1a (non-idempotent rejection) + M2-T3 (/state) + M2-T6 (sink-events endpoint). When impl says ready, I'll re-run the conformance suite, expect SV-SESS-STATE-01 to flip first (M2-T3 is impl's next task), and post the Week 1 exit scoreboard here.

---

## 2026-04-21 (M2 Week 1 Day 1 afternoon — first live M2 run; two findings surfaced)

Ran `/tmp/soa-validate --profile=core` against live impl on `127.0.0.1:7700` (pin `507eeb1`). Two findings, two bugs fixed validator-side, two M2 tests flipped green.

### Validator-side fixes shipped before re-run

- **Milestone-scope gate (`internal/testrunner/runner.go`)** — the runner previously short-circuited any test with `implementation_milestone != "M1"` to a "deferred to M2 per must-map" skip, which meant M2 handlers never ran even when wired. Added `Config.MilestonesInScope` (defaults to `{"", "M1", "M2"}` via `DefaultMilestonesInScope()`). M3+ tests stay deferred. Without this, all five Week 1 targets were auto-skipping before my handlers got control.
- **M2 bootstrap body** — `m2Bootstrap` in `handlers_m2.go` was sending `{"activeMode":...}`. Impl rejected with `400 {"error":"malformed-request","detail":"requested_activeMode missing or invalid"}`. Fix: switched to `{"requested_activeMode":"DangerFullAccess","user_sub":"m2-validator","request_decide_scope":true}` matching the M1 `postSessionWithScope` pattern + §12.6 schema.

### Scoreboard (live impl `127.0.0.1:7700`, `SOA_IMPL_BIN` set)

| Test | Status | Note |
|---|---|---|
| SV-CARD-01 | pass | vector + live |
| SV-SIGN-01 | pass | vector + live |
| HR-01 | pass | vector |
| HR-12 | pass | subprocess tampered JWS fail-closed |
| SV-SESS-BOOT-02 | pass | subprocess ReadOnly-card-403 |
| **SV-SESS-05** | **pass (new)** | positive + negative arms via tool-registry-m2 fixtures; impl enforces §12.2 `ToolPoolStale idempotency-retention-insufficient` |
| **SV-SESS-11** | **pass (new)** | positive + negative + combined-fixture arms |
| HR-02 | skip | M3-deferred (Token Budget) |
| SV-SESS-06..10 | skip | `RUNNER_CRASH_TEST_MARKERS` not yet shipped by impl |
| SV-PERM-19 | skip | **Finding A below** |
| SV-AUDIT-SINK-EVENTS-01 | skip | **Finding A below** |
| SV-SESS-STATE-01 | skip | **Finding B below** |
| HR-14 / SV-AUDIT-TAIL-01 / SV-AUDIT-RECORDS-01/02 / SV-SESS-BOOT-01 / SV-PERM-01 / SV-PERM-20 / SV-PERM-21 / SV-BOOT-01 / SV-PERM-22 | fail/error/skip | **Finding B below** — all trace to live :7700 /ready=503 crl-stale |

**Clean M2 result:** 2 of 5 Week 1 targets PASS live. Other 3 blocked on impl-side gaps surfaced below.

### Finding A — `§12.5.4 GET /audit/sink-events` endpoint not wired

- Probe: `curl http://127.0.0.1:7700/audit/sink-events` → 404 `{"message":"Route GET:/audit/sink-events not found","error":"Not Found","statusCode":404}`.
- Verified on a fresh subprocess-spawned impl (same code, fresh CRL): startup route list enumerates 10 endpoints; `/audit/sink-events` is **not** among them. Same 404 with authenticated session bearer.
- Spec L-28 §12.5.4 requires this endpoint for M2 conformance. Impl's M2-T3 delivery shipped `/sessions/<id>/state` (good) but not `/audit/sink-events`.
- Blocks: SV-PERM-19 (all three arms), SV-AUDIT-SINK-EVENTS-01 (all three arms).
- **This is a deliverable gap**, not a validator bug. Reporting per validator-role instructions.
- Auto-flip: once impl wires the §12.5.4 route + the `SOA_RUNNER_AUDIT_SINK_FAILURE_MODE` state machine, my handlers already cover the three-arm sweep + the exactly-one-fresh-boot-event assertion per L-28 F-13.

### Finding B — live :7700 impl is in `/ready=503 reason=crl-stale`

- Probe: `GET /ready` → `503 {"status":"not-ready","reason":"crl-stale"}`.
- Cascade: every test that mints a session against :7700 errors with `status=503`. This is the root cause of M1 regressions in today's run (SV-BOOT-01, SV-PERM-01 FAIL; SV-SESS-BOOT-01, SV-PERM-20, SV-PERM-21 ERROR; SV-SESS-STATE-01 SKIP).
- **Subprocess-spawned impls (fresh boot) come up `/ready=200`** and accept /sessions cleanly — see SV-SESS-05/11/HR-12/SV-SESS-BOOT-02 passes.
- Interpretation: the long-running :7700 instance's CRL fetcher has aged past the freshness window. Runtime-state condition, not a code bug. Restart of :7700 (or CRL refresh in place) should clear it.
- Once :7700 is restarted against fresh CRL fixtures, M1 regressions clear and SV-SESS-STATE-01 becomes testable (my V-14 observer + byte-identity predicate is wired and ready).

### Numbers at snapshot time

- 7 pass / 2 fail / 3 error / 14 skip.
- M1-equivalent (ignoring :7700 crl-stale cascade): **15 pass / 1 skip / 0 fail** (identical to M1 close).
- M2 delta: **+2 pass (SV-SESS-05, SV-SESS-11)**, +3 skip blocked on impl §12.5.4 endpoint + :7700 health.

**Handing back to impl:** (1) ship `/audit/sink-events` route + `SOA_RUNNER_AUDIT_SINK_FAILURE_MODE` wiring; (2) restart :7700 with fresh CRL. Validator ready to flip SV-PERM-19, SV-AUDIT-SINK-EVENTS-01, SV-SESS-STATE-01 on next run — no validator-side code change needed.

---

## 2026-04-21 (Day 1 evening — V2-06 + V2-07 + V2-08 scaffolds landed)

**Done (while waiting on impl M2-T2 — resume algorithm):**
- **V2-06 / V2-07 / V2-08 scaffolds shipped.** Four new handlers registered: `HR-04`, `HR-05`, `SV-SESS-03`, `SV-SESS-04` — all tagged M2 in must-map, all now invoked by the runner.
- `HR-04` — kill at `SOA_MARK_PENDING_WRITE_DONE`; probe asserts idempotency_key preserved + `/audit/records` single-row per §12.5 step 4 (dedupe via chain, F-11 fix). Wired via existing `resumeCrashArm`.
- `HR-05` — kill at `SOA_MARK_DIR_FSYNC_DONE` (+50ms PreKillDelay); probe asserts phase=committed unchanged + still single audit row (no replay).
- `SV-SESS-04` — kill at `SOA_MARK_PENDING_WRITE_DONE`; probe captures idempotency_key pre/post resume + audit-chain single-row dedupe check.
- `SV-SESS-03` — live-only (no crash): bootstrap + /state reachability probe; full drive-and-observe loop for phase transitions + monotonic `last_phase_transition_at` gated on impl M2-T2 (phase writes need to be visible).
- Probe bodies document the exact §12.5 + /state + /audit/records assertions that fire once M2-T2 lands + the drive-on-ready harness extension is added (extension deferred so it can be iterated against real marker output).

**Scoreboard (live run, pin `507eeb1`, 30 test IDs registered):** 7 pass / 2 fail / 3 error / 18 skip. M2 deltas from yesterday: +4 handlers, same 2 greens (SV-SESS-05, SV-SESS-11), same Finding A/B blockers.

**14 M2 test IDs now wired total.** Breakdown:
- **Week 1** (5): SV-SESS-05 ✅, SV-SESS-11 ✅, SV-PERM-19 ⏳ (Finding A), SV-AUDIT-SINK-EVENTS-01 ⏳ (Finding A), SV-SESS-STATE-01 ⏳ (Finding B).
- **Week 2** (4): HR-04, HR-05, SV-SESS-03, SV-SESS-04 — all scaffolded, SKIP pending M2-T2.
- **Week 3** (5): SV-SESS-06 / -07 / -08 / -09 / -10 — all scaffolded, SKIP pending M2-T2 + `RUNNER_CRASH_TEST_MARKERS`.

**Next impl trigger:** M2-T2 (resume algorithm) + `RUNNER_CRASH_TEST_MARKERS=1` support. When STATUS signals T-2 live, V2-06 + V2-09c fire; expected delta +4 (HR-04, HR-05, SV-SESS-04, SV-SESS-08) + partial flips on the rest. Drive-on-ready harness extension goes in after T-2 so it can be shaped against real markers.

---

## 2026-04-21 (Day 1 evening-2 — post-M2-T2 run; +2 M2 greens; two new findings)

Impl shipped M2-T2 (resume algorithm) + periodic CRL refresh. I registered SV-SESS-01 + SV-SESS-02 + refactored SV-SESS-09 (first attempt at card-drift without markers), re-ran the suite.

### Scoreboard (pin `507eeb1`, live :7700 + SOA_IMPL_BIN)

**32 test IDs registered. 9 pass / 2 fail / 18 skip / 3 error.**

| Test | Status | Note |
|---|---|---|
| SV-CARD-01 / SV-SIGN-01 / HR-01 / HR-12 / SV-SESS-BOOT-02 | pass | M1 regression green (subprocess path unaffected by :7700 crl-stale) |
| **SV-SESS-05 / SV-SESS-11 / SV-PERM-19 ✨ / SV-AUDIT-SINK-EVENTS-01 ✨** | **pass** | **4 M2 greens — +2 from this morning** |
| HR-02 | skip | M3-deferred |
| HR-04, HR-05, SV-SESS-03, SV-SESS-04, SV-SESS-06..10 | skip | scaffolded; pending crash markers + resume trigger |
| SV-SESS-01, SV-SESS-STATE-01 | skip | blocked on Finding B |
| SV-SESS-02 | skip | blocked on **Finding C** (see below) |
| SV-SESS-09 | skip | blocked on **Finding D** (see below) |
| HR-14 / SV-AUDIT-TAIL-01 / SV-AUDIT-RECORDS-01/02 / SV-PERM-22 / SV-SESS-BOOT-01 / SV-PERM-20 / SV-PERM-21 / SV-BOOT-01 / SV-PERM-01 | fail/error/skip | all cascade from Finding B — live :7700 stuck at /ready=503 reason=crl-stale |

### Finding B (update): :7700 still /ready=503 crl-stale

Impl merged the periodic CRL refresh but this running :7700 instance was started before the fix. Its CRL is still stale. Needs a **restart of the :7700 process** to pick up the refresh-timer code. Not a code problem — just a stale-process condition. Once restarted, 5 M1 tests + SV-SESS-01 + SV-SESS-STATE-01 flip.

### Finding C — `resumeSession()` defined but never called

**The §12.5 resume algorithm's entry point has zero callers in the impl source tree.**

- `packages/runner/src/session/resume.ts` exports `resumeSession(persister, session_id, ctx)`.
- `grep -rn "resumeSession" packages/runner/src/ packages/core/src/` → only the `export` and the `index.ts` re-export. No production callers.
- Impl's boot does not scan `RUNNER_SESSION_DIR` (`grep readdir` in runner/src/ returns only an unrelated audit/sink.ts hit).
- `/sessions/<sid>/state` returns `404 unknown-session` for any session_id not already in the in-memory `sessionStore`; there's no lazy-hydrate-from-disk path.
- Net effect: the resume algorithm can be unit-tested but cannot fire under any HTTP request or process restart today.

**Blocks:** HR-04, HR-05, SV-SESS-02, SV-SESS-04, SV-SESS-08, SV-SESS-09, SV-SESS-10 — every assertion that depends on "impl reads a persisted session from disk and routes through §12.5."

**Resolution (impl-side):** wire `resumeSession` to either:
- (a) boot-time `fsp.readdir(sessionDir)` → register each valid session in `sessionStore` (the natural reading of §12.5 "on process restart"), OR
- (b) lazy-hydrate in `/sessions/<sid>/state` when `!sessionStore.exists(sessionId)` — try disk, register if valid, then serve.

Either unblocks all the resume-dependent M2 IDs.

### Finding D — Card-drift test blocked by conformance-loader digest check

SV-SESS-09 wants to launch impl with a `card_version`-mutated Agent Card and assert impl refuses to resume with `StopReason::CardVersionDrift`. My first attempt was a validator-side mutation of the conformance card. Impl's `loadConformanceCard` verifies the card's digest against a pinned value and refuses with `reason: 'digest-mismatch'` — an earlier defense that short-circuits the resume-time drift check.

This is a correct behavior (the fixture-digest check is §15.5-adjacent integrity — important), but it prevents the validator from exercising §12.5 drift detection with validator-only tooling.

**Resolutions (pick one):**
- (a) **Spec** ships a pinned pair: `test-vectors/conformance-card/agent-card.json` (card A, version "1.0.0") + `test-vectors/conformance-card-drift/agent-card.json` (card B, version "1.0.1"), each with its own digest entry in MANIFEST. Validator feeds A in phase 1, B in phase 2.
- (b) **Impl** adds an opt-out env (e.g., `RUNNER_SKIP_CARD_FIXTURE_DIGEST_CHECK=1`) — validator-only, unsafe for production. Documents in §15.5 as a test-only hatch.

Also gated on Finding C — even with a distinct-but-digest-valid card, drift detection only fires if §12.5 resume is actually called.

### Net Day 1 close

- **14 M2 test IDs wired + 4 live-green** (was 0 live yesterday morning).
- **Findings A, B, C, D surfaced** — all spec- or impl-side. Validator holds no workarounds.
- Expected next delta once impl lands: (1) :7700 restart → +2 greens (SV-SESS-01, SV-SESS-STATE-01) + clears M1 cascade; (2) resume-trigger wiring → +5–6 greens (HR-04/05, SV-SESS-04, etc. begin probing meaningful state); (3) spec card-drift pair → +1 green (SV-SESS-09).

---

## 2026-04-20 (M1 FINAL ARTIFACT — 15 pass / 1 skip / 0 fail; pin at 8624a7a)

**This is the M1 exit-gate scoreboard.**

**Done:**
- **Pin-bumped `5849483 → 8624a7a`** adopting **L-26 §10.3.2 pda-malformed enum move** (403 → 400). Direct root-cause fix for the SV-PERM-22 regression L-24 activation unmasked — spec now aligns status code with the wire-level-JWS-parse semantic. `spec_commit_sha = 8624a7a0ea06a7d667870fb03e68775d24e08c57`, `spec_manifest_sha256 = 6d985d0dc1eae3a511ddff9df533366cf3f34da8f00ae01a0808854c6d14b813`.
- **SV-PERM-21 → PASS** (flipped after impl wired `resolvePdaVerifyKey` in commit `e59f708`). Full end-to-end PDA happy path: pinned Ed25519 private key signs a canonical-decision for fs__write_file under WorkspaceWrite/Prompt; impl's wired resolver finds the public key by kid `soa-conformance-test-handler-v1.0`; `jose.compactVerify` succeeds; audit chain advances with verified `signer_key_id`.
- **SV-PERM-22 → PASS** (flipped after L-26 adoption). Malformed-wire PDA → `400 reason=pda-malformed`; audit tail unchanged across the rejection (no audit record written for auth/structural failures).
- Both remaining branches documented as deferred: crypto-invalid-but-well-formed + decision-mismatch require constructing a shape-valid PDA signed by an untrusted key (or a trusted key over mismatched content) — fixture/design TBD, not blocking M1.

**Final M1 scoreboard (against live impl at `127.0.0.1:7700`, pin `8624a7a`):**

| Test | Path(s) | Result |
|---|---|---|
| SV-CARD-01 | vector + live | pass |
| SV-SIGN-01 | vector + live | pass |
| SV-BOOT-01 | live happy + 3 V-12 negatives | pass |
| SV-PERM-01 | 24-cell oracle + audit invariant | pass |
| HR-01 | vector (positive + 2 semantic-reject fixtures + 4 inline negatives) | pass |
| HR-02 | — | **skip (M3-deferred per must-map)** |
| HR-12 | live subprocess (tampered JWS → x5c-missing fail-closed) | pass |
| HR-14 | live (149-record chain + tamper-at-index-74 detection) | pass |
| SV-AUDIT-TAIL-01 | live state-adaptive + idempotence | pass |
| SV-AUDIT-RECORDS-01 | 2-page pagination, 149 records | pass |
| SV-AUDIT-RECORDS-02 | full §10.5 chain integrity, 149 records | pass |
| SV-SESS-BOOT-01 | 6 sessions × 2 decide-scope variants | pass |
| SV-SESS-BOOT-02 | path-a subprocess (ReadOnly card → 403) | pass |
| SV-PERM-20 | positive + 2 negatives (insufficient-scope, session-bearer-mismatch) | pass |
| SV-PERM-21 | PDA happy path via L-24 fixture + verified signer | pass |
| SV-PERM-22 | malformed-wire PDA → 400 pda-malformed (L-26 enum) | pass |

**15 pass / 1 skip / 0 fail. Zero workaround-passes. HR-02 M3-deferred is the only skip and it's spec-authored via `implementation_milestone`.**

**Validator contribution across M1 (final count):**
- ~60+ unit tests across 13 internal packages.
- **8 root-cause spec findings surfaced and driven to resolution:** L-09 (URL shorthand), L-12 (JWS `typ`), L-18 (conformance card schema: max_iterations / policyEndpoint / SPKI), L-19/L-22 (403 reason enum inc. `insufficient-scope` rename), L-23 (pda-verify-unavailable 503 branch), L-24 (handler-key fixture gap), L-26 (pda-malformed enum move).
- **5 validator-side bugs caught in flight** (including a fake-pass the user correctly stopped me from shipping, then the MSYS path translation, the stale-struct round-trip bug, rate-limit cascade, extractFailureReason token priority).
- Independent §10.3 oracle re-implementation cross-checks impl decisions against a hand-mirrored spec-README 24-cell matrix.
- Subprocess harness drives V-09 / V-12 / SV-SESS-BOOT-02 path-a.
- M1 exit-gate CLI + docs + cross-platform CI scaffolds.

**Pin at `8624a7a`. M1 complete.**

---

## 2026-04-20 (post-M1 — pin at 5849483; SV-PERM-21 handler ready, awaiting impl L-24 adoption)

**Done:**
- **Pin-bumped `1971e87 → 5849483`** adopting **L-24 pinned handler keypair + pre-signed PDA fixture**. `spec_commit_sha = 5849483736674ba86b20339beb548749d86c78e4`, `spec_manifest_sha256 = d21345726b04d85fe2b4b9079d251468fab3b3213c5fa8d8247282fc1ecf8cd1`. Single-reason: this is the spec-side fix I flagged as the unblocker for SV-PERM-21 across all of M1.
- **SV-PERM-21 handler implemented end-to-end.** New live path:
  1. POST /sessions with `requested_activeMode=WorkspaceWrite` + `request_decide_scope:true`
  2. Read `test-vectors/permission-prompt-signed/pda.jws` as a string
  3. POST /permissions/decisions `{tool:"fs__write_file", session_id, args_digest:"sha256:00…00", pda:<pda.jws>}`
  4. Assert: 201, `decision=Prompt`, `handler_accepted=true`, `audit_this_hash` is hex64, `audit_record_id` ∈ `^aud_…`
  5. GET /audit/records → newest record's `signer_key_id == "soa-conformance-test-handler-v1.0"`
- **Auto-flip diagnostic:** when impl returns 503 pda-verify-unavailable (L-24 not yet adopted on the impl side), handler reports SKIP with precise diagnostic (`handler SPKI 749f3fd4…91e3 not in trustAnchors. When impl ships L-24, this auto-flips to PASS.`).

**Today's run state:** SV-PERM-21 still SKIP because current impl doesn't yet have the L-24 handler SPKI in `trustAnchors` (still 503 pda-verify-unavailable). **Code is ready; flips PASS the moment impl ships L-24 adoption.**

**Scoreboard unchanged: 14 pass / 2 skip / 0 fail.** Expected post-impl-L-24: **15 pass / 1 skip / 0 fail** (only HR-02 M3-deferred remains, by design).

---

## 2026-04-20 (M1 CLOSE — 14 pass / 2 skip / 0 fail across the full conformance suite)

**Milestone:** Impl shipped Week 5b (commit `a3ca409` + STATUS `7c305e7`) — `create-soa-agent` scaffold + Linux/macOS/Windows ≤120 s cold-cache CI gate. Their punch list is fully cleared. **M1 complete on both sides.**

**Final V-13 exit-gate run against impl at `127.0.0.1:7700` (pin `1971e87`):**

| Test ID | Result | Path(s) |
|---|---|---|
| SV-CARD-01 | pass | vector + live (schema + JCS idempotent + Cache-Control + ETag) |
| SV-SIGN-01 | pass | vector + live (header shape + signing-input round-trip) |
| SV-BOOT-01 | pass | live happy-path (/health+/ready) + 3 V-12 negatives (subprocess: bootstrap-expired / bootstrap-invalid-schema / bootstrap-missing) |
| SV-PERM-01 | pass | 24-cell oracle match + audit-tail invariant across 24 queries |
| HR-01 | pass | vector (positive + semantic-reject + schema-reject + 4 inline negatives) |
| HR-02 | skip | M3-deferred per must-map `implementation_milestone` (Token Budget projector is M3 scope) |
| HR-12 | pass | live subprocess (tampered card JWS → x5c-missing fail-closed) |
| HR-14 | pass | live (149-record chain integrity + tamper-at-index-74 detection) |
| SV-AUDIT-TAIL-01 | pass | live state-adaptive (GENESIS or hex64) + idempotence |
| SV-AUDIT-RECORDS-01 | pass | live 2-page pagination, 149 records, schema-valid every page |
| SV-AUDIT-RECORDS-02 | pass | live full §10.5 chain integrity across 149 records |
| SV-SESS-BOOT-01 | pass | live 6 sessions (3 caps × 2 decide-scope variants), full round-trip |
| SV-SESS-BOOT-02 | pass | path-a (subprocess on :7702 with ReadOnly card → 403 ConfigPrecedenceViolation) |
| SV-PERM-20 | pass | live (positive + insufficient-scope + session-bearer-mismatch; audit unchanged on both negatives) |
| SV-PERM-21 | skip | L-24 PDA signing fixture (spec-side; tracked, not blocking M1 per rev-2 plan) |
| SV-PERM-22 | pass | live L-23 deployment-misconfig branch (503 pda-verify-unavailable) |

**14 pass / 2 skip / 0 fail. Zero workaround-passes.** Both skips carry explicit deferrals (HR-02 → spec-authored M3 milestone, SV-PERM-21 → tracked L-24 follow-up).

**Validator-side coverage that landed during M1:**
- 60+ unit tests across 13 internal packages (jcs/digest/musmap/agentcard/permprompt/runner/inittrust/crlstate/permresolve/toolregistry/auditchain/subprocrunner + cmd/soa-validate driver tests).
- 6 spec-issue findings surfaced by the validator and fixed at the root (URL shorthand, JWS typ, x5c, conformance-card max_iterations, conformance-card policyEndpoint:null, SV-PERM-22 pda-verify-unavailable enum) plus the validator-side bugs caught in flight (MSYS path translation, fake-pass anti-pattern, extractFailureReason ordering, rate-limit cascade).
- Independent §10.3 oracle re-implementation (`internal/permresolve`) cross-checks impl decisions against a hand-mirrored spec-README 24-cell matrix.
- Subprocess harness (`internal/subprocrunner`) drives V-09/V-12 boot-time negatives + SV-SESS-BOOT-02 path-a controlled-deployment test.
- M1 exit-gate command + docs (`docs/M1-EXIT-GATE.md`) + cross-platform CI scaffolds (`.github/workflows/{ci,live-e2e}.yml`).

**Pin at `1971e87`** through M1 close. Ready for M2 when the spec/impl roadmaps re-open.

---

## 2026-04-20 (Week 3 close — SV-SESS-BOOT-02 path-a green; 14 pass / 2 skip / 0 fail)

**Done — three queued prep tasks all landed:**

- **(3) SV-SESS-BOOT-02 path-a wired.** Handler now follows two paths:
  - **Cheap path:** if the running Runner already serves a ReadOnly card, run the §12.6 tighten-only assertion against it (single POST /sessions(DFA) → 403).
  - **Path-a:** when running Runner serves DFA conformance card and SOA_IMPL_BIN is set, **spawn a second impl subprocess on test-port+1** (default 7702) with `RUNNER_CARD_PATH=<spec>/test-vectors/agent-card.json` (the pinned ReadOnly default card) and `RUNNER_INITIAL_TRUST=<spec>/test-vectors/initial-trust/valid.json`, wait for `/health=200` via the subprocrunner ReadinessProbe, fire the assertion, kill the subprocess. Today's run: PASS via path-a — `path-a (subprocess on port 7702, ReadOnly card via RUNNER_CARD_PATH=test-vectors/agent-card.json): ReadOnly card + requested DFA → 403 per §12.6 tighten-only gate`.
- **(2) Platform-matrix scaffolding.** Added `.github/workflows/live-e2e.yml` — `workflow_dispatch`-triggered E2E job on Linux/macOS/Windows that checks out validator + spec + impl at pinned refs, builds impl, starts it under the conformance bootstrap bearer + DFA fixture, runs the V-13 exit-gate command, and uploads `release-gate.json` + JUnit XML as artifacts. Currently manual-trigger only; flips to push/PR triggers once impl ships Week 5b's CI matrix.
- **(1) V-13 exit-gate documentation.** Added `docs/M1-EXIT-GATE.md` — full env-var reference, output artifact schema, current scoreboard target, platform-coverage notes. The CLI itself was already V-13 functionality; the doc formalizes it as the M1 exit gate.

**Final scoreboard (16 tests):**

| Test | live |
|---|---|
| SV-CARD-01, SV-SIGN-01, SV-BOOT-01, SV-PERM-01, HR-01-vector, HR-12, HR-14, SV-AUDIT-TAIL-01, SV-AUDIT-RECORDS-01, SV-AUDIT-RECORDS-02, SV-SESS-BOOT-01, **SV-SESS-BOOT-02**, SV-PERM-20, SV-PERM-22 | **pass** |
| HR-02 | M3-deferred (must-map) |
| SV-PERM-21 | skip (PDA signing fixture / L-24 candidate) |

**14 pass / 2 skip / 0 fail.** Zero workaround-passes. Both remaining skips have explicit unblockers (HR-02 by spec milestone, SV-PERM-21 by L-24).

**Pin stays at `1971e87`.** No spec change this round.

---

## 2026-04-20 (Week 3 day 3 close — V-09 + V-12 subprocess tests green; 13 pass / 3 skip / 0 fail)

**Done:**
- Impl shipped T-05 + T-06 + T-07 (commit `6270681`); their punch list is cleared.
- **HR-12 (V-09) → PASS** via subprocess test. Spawns impl with `RUNNER_CARD_JWS=<spec>/test-vectors/tampered-card/agent-card.json.tampered.jws` against the conformance card; impl exits 1 with reason `x5c-missing` (spec §6.1.1 row 1 requires x5c, tampered fixture lacks it; impl's first failure point is x5c absence rather than signature-invalid — both are CardSignatureFailed-class spec failures).
- **SV-BOOT-01 V-12 negative arms → all 3 PASS.** Subprocess-spawn impl with each pinned broken-trust fixture, assert non-zero exit + matching spec-defined reason:
  - `expired.json` → `bootstrap-expired`
  - `channel-mismatch.json` → `bootstrap-invalid-schema` (renamed from `bootstrap-schema-invalid` per L-22)
  - `mismatched-publisher-kid.json` (with `RUNNER_EXPECTED_PUBLISHER_KID`=different) → `bootstrap-missing`

**Validator-side bugs caught + fixed in flight (each surfaced via the subprocess machinery):**
1. **MSYS path translation** — bash `realpath` returns `/c/Users/...` (MSYS-style); when passed to Windows Node it became `C:\c\Users\...` (malformed; module-not-found). Added `msysToWindows()` translator in `parseImplBin` for Windows host.
2. **Fake-pass anti-pattern in V-12 aggregator** — first version returned Status=Pass on the SV-BOOT-01 evidence even when negative arms failed. Refactored `svBootNegativesEvidence` to return `(msg, ranTests, allPass)` so the caller propagates FAIL honestly. Per validator-role memory.
3. **`extractFailureReason` token priority** — original list returned the general category (`HostHardeningInsufficient`) before reaching specific reasons (`bootstrap-expired`). Reordered: specifics first, categories last.
4. **Bootstrap-bearer rate limit** — cumulative session-mint volume across all handlers (~17+ POST /sessions) saturates impl's 30/min per-bearer rate limit. Added Retry-After backoff to `postSessionWithScope` (single retry, sleeps Retry-After+1s).

**Subprocess machinery additions:**
- `subprocrunner.Config.InheritEnv bool` — opt-in inheritance; default false for boot-time test determinism.
- `envWithSystemBasics()` — passes through PATH/SystemRoot/etc. without inheriting validator-specific SOA_*/RUNNER_* env vars that could interfere with spawned impl.
- `SOA_VALIDATE_DEBUG_DIR` env var dumps captured stderr from V-12 spawns to disk for diagnosis.

**Final scoreboard (16 tests):**

| Test | live |
|---|---|
| SV-CARD-01, SV-SIGN-01, SV-BOOT-01, SV-PERM-01, HR-01-vector, **HR-12**, HR-14, SV-AUDIT-TAIL-01, SV-AUDIT-RECORDS-01, SV-AUDIT-RECORDS-02, SV-SESS-BOOT-01, SV-PERM-20, SV-PERM-22 | **pass** |
| HR-02 | M3-deferred (must-map) |
| SV-SESS-BOOT-02 | skip (deployment variation — needs ReadOnly-card Runner) |
| SV-PERM-21 | skip (PDA signing fixture / L-24 candidate) |

**13 pass / 3 skip / 0 fail.** Zero workaround-passes. Every skip carries an exact-unblocker diagnostic.

**Run command:**
```
SOA_IMPL_URL=http://127.0.0.1:7700 \
SOA_RUNNER_BOOTSTRAP_BEARER=soa-conformance-week3-test-bearer \
SOA_IMPL_BIN="node /abs/path/to/start-runner.js" \
SOA_DRIVE_AUDIT_RECORDS=10 \
soa-validate --profile=core --spec-vectors=<spec>
```

**Pin stays at `1971e87`** (no spec change this round).

---

## 2026-04-20 (Week 3 day 3 — V-08 normative path; RUNNER_DEMO_SESSION retired)

**Done:**
- Impl shipped T-03 (`request_decide_scope` on POST /sessions) + T-08 (session.schema activeMode-required pinned). Confirmed live: bootstrap-minted bearer with `request_decide_scope:true` drives `/permissions/decisions` to 201.
- **SV-PERM-20 reworked to use bootstrap-minted sessions** (T-03 normative path) instead of `RUNNER_DEMO_SESSION`. Three assertions:
  - **Positive**: mint session with decide=true → POST decision → 201, decision matches §10.3 oracle, schema-valid, +1 audit record, `audit_this_hash` equals new tail hash
  - **insufficient-scope**: mint session with decide omitted/false → POST decision → 403 reason=`insufficient-scope` + **audit tail unchanged** (Δ=0)
  - **session-bearer-mismatch**: mint two sessions (both with decide); use bearer-A on body session_id=B → 403 reason=`session-bearer-mismatch` + **audit tail unchanged**
- **SV-SESS-BOOT-01 upgraded to round-trip** the request_decide_scope semantics across all three capabilities (RO, WW, DFA). Six sessions minted total (3 caps × 2 decide-scope variants). Each decide=true bearer MUST authorize `/permissions/decisions` (201); each decide=false bearer MUST be refused (403 insufficient-scope). Confirms scope grant is independent of capability.
- **V-07 driver migrated** to bootstrap-mint path. New helper `resolveDriverSession` prefers minting via SOA_RUNNER_BOOTSTRAP_BEARER (T-03 normative) over the legacy `SOA_IMPL_DEMO_SESSION`. Demo session stays as a fallback for pre-T-03 deployments.
- **Audit-bearer fallback wired** into SV-AUDIT-TAIL-01, SV-AUDIT-RECORDS-01/02, HR-14, SV-PERM-22 — new `auditBearer` helper tries demo-session first then mints via bootstrap. The full suite now runs with **only `SOA_RUNNER_BOOTSTRAP_BEARER` set** — no demo-session env var needed.

**Scoreboard (16 tests, V-07 driver run, NO demo session env var):** **12 pass / 4 skip / 0 fail.**

| Test | live |
|---|---|
| SV-CARD-01, SV-SIGN-01, SV-BOOT-01, SV-PERM-01, HR-01-vector, HR-14, SV-AUDIT-TAIL-01, SV-AUDIT-RECORDS-01, SV-AUDIT-RECORDS-02, SV-SESS-BOOT-01, SV-PERM-20, SV-PERM-22 | **pass** |
| HR-02 | M3-deferred (must-map) |
| HR-12 | skip (T-06 + SOA_IMPL_BIN) |
| SV-SESS-BOOT-02 | skip (deployment variation) |
| SV-PERM-21 | skip (PDA signing fixture / L-24) |

**Run command (V-08 normative — no demo-session dependency):**
```
SOA_IMPL_URL=http://127.0.0.1:7700 \
SOA_RUNNER_BOOTSTRAP_BEARER=soa-conformance-week3-test-bearer \
SOA_DRIVE_AUDIT_RECORDS=10 \
soa-validate --profile=core --spec-vectors=<spec>
```

**Pin stays at 1971e87** (no spec change this round — purely impl T-03/T-08 ship + validator-side adoption).

**Still SKIP, each named with its exact unblocker:**
- HR-12 → T-06 (`RUNNER_CARD_JWS`) + SOA_IMPL_BIN
- SV-BOOT-01 negative arms → T-07 (`RUNNER_INITIAL_TRUST`) + SOA_IMPL_BIN
- SV-SESS-BOOT-02 → Runner with default ReadOnly card (subprocess harness)
- SV-PERM-21 → L-24 PDA signing fixture

---

## 2026-04-20 (Week 3 day 3 — Medium-mode prep: driver hardening + V-09/V-12 subprocess scaffolding)

**Done while impl works on T-03 + T-08:**

- **V-07 driver hardened.** Now accepts `SOA_DRIVE_AUDIT_TOOLS=tool1,tool2,…` (comma-separated; default `fs__read_file`); cycles through tools modulo list length. Rate-limit handling fixed at the type level — split into testable inner loop `driveAuditRecordsWith(client, baseURL, sid, bearer, tools, n, pace)` with explicit `driveStats{Written, SkippedPdaUnavail, RetriedAfter429}` return. Specific behaviors:
  - **429 retry**: read `Retry-After`, sleep + 1s grace, retry the same record (don't count it).
  - **503 pda-verify-unavailable tolerance**: count as `SkippedPdaUnavail`, **continue** to the next tool. Mixed-tool runs don't break when Prompt-resolving tools hit the deployment's missing-PDA-verify path.
  - Other non-201 (400/401/403/5xx-non-pda) → loud failure (existing behavior preserved).
- **4 driver unit tests** in `cmd/soa-validate/driver_test.go` against `httptest.Server` fixtures: 429+Retry-After regression, 503 pda-verify-unavailable continuation, mixed 201/503 alternating, 401 fail-loudly. All green.
- **`internal/subprocrunner` package** — generic subprocess harness for boot-time-failure tests. `Spawn(ctx, Config) Result` records `ExitCode`, `Exited`, `TimedOut`, `ReadinessReached`, captured `Stdout`/`Stderr`. Optional `ReadinessProbe` for cleanly stopping a long-running process once it signals ready (e.g., `/health` returns 200). 5 unit tests using `go version` for clean-exit + non-zero-exit, cross-platform sleep (python-first fallback) for timeout + readiness paths, missing-binary for StartErr.
- **HR-12 handler upgraded** (was bare stub) — uses subprocrunner; honest SKIP with precise diagnostic citing the two prerequisites: `SOA_IMPL_BIN` (validator-side) and impl T-06 (`RUNNER_CARD_JWS` env-var). Will flip to PASS when both are present.
- **SV-BOOT-01 evidence message extended** to declare the V-12 negative-arm scaffold (3 fixture invocations: expired.json, channel-mismatch.json, mismatched-pub-kid.json → HostHardeningInsufficient) and what it needs (impl T-07: `RUNNER_INITIAL_TRUST` env-var). Happy-path live arm continues to satisfy SV-BOOT-01 PASS via /health+/ready.

**Test count:** 14 passing unit tests across 12 internal packages (driver_test +4, subprocrunner +5; auditchain +5; existing core packages unchanged).

**Scoreboard (16 tests, V-07 driver run):** **12 pass / 4 skip / 0 fail.** Without driver: 11 pass / 5 skip (HR-14 honestly skips when chain has <3 records).

**Skips that flip to pass when impl ships the named task:**
- HR-12 ← T-06 (`RUNNER_CARD_JWS`) + validator-side `SOA_IMPL_BIN`
- SV-BOOT-01 negative-arm evidence ← T-07 (`RUNNER_INITIAL_TRUST`) + `SOA_IMPL_BIN`
- HR-01 live ← cold-start restart hook
- SV-SESS-BOOT-02 live ← Runner with default ReadOnly card (or subprocess harness with V-12 fixture)
- SV-PERM-21 live ← PDA signing fixture (L-24 candidate)

---

## 2026-04-20 (Week 3 day 3 — V-06 + V-10 + V-07 + SV-PERM-20 negative matrix all green; 12/4/0)

**Done:**
- **`/audit/records` was already live on impl** (their STATUS was stale; T-01 had landed). V-06 (SV-AUDIT-RECORDS-01/02) and V-10 (HR-14) flipped from latent-skip directly to PASS once handlers landed.
- **`internal/auditchain` package** — independent chain-integrity verifier. `VerifyChain` walks records earliest-first asserting `records[0].prev_hash=="GENESIS"` and `records[i].prev_hash==records[i-1].this_hash` for i>0; reports the exact break index on failure. `Tamper` returns a mutated copy with `records[idx].prev_hash` swapped — used by HR-14 to construct a known-broken chain. 5 unit tests.
- **SV-AUDIT-RECORDS-01 → PASS** (149 records across 2 pages of 100+49; schema-valid on every page; chain order earliest→latest holds; pagination via `next_after` terminates correctly when `has_more=false`).
- **SV-AUDIT-RECORDS-02 → PASS** (chain integrity verified across all 149 records; no break).
- **HR-14 → PASS** (tampered `records[74].prev_hash` → VerifyChain flags break at exactly index 74 per §15.5).
- **SV-PERM-20 negative matrix expanded.** Now asserts the L-22 enum across:
  - **insufficient-scope** (existing) — fresh session without `request_decide_scope` → 403 reason=insufficient-scope
  - **session-bearer-mismatch** (NEW) — demo bearer with body session_id from a different session → 403 reason=session-bearer-mismatch
  - **pda-decision-mismatch** — explicitly skipped on this deployment (would 503 pda-verify-unavailable before reaching mismatch logic; documented in passing message)
- **V-07 audit-record driver** — `SOA_DRIVE_AUDIT_RECORDS=N` env var. Paces at 2.5s/req to stay under impl's 30 rpm per-bearer rate limit; honors `Retry-After` on 429. Drove 120 records cleanly in this run.

**Validator-side bug surfaced + fixed in flight:** the first driver attempt fired 28 requests in <60s, hit impl's 429 sliding-window rate limit, and cascaded into SV-PERM-20/22 failing because they share the demo bearer's budget. Driver now paces correctly; subsequent tests have headroom.

**Final scoreboard (16 tests, 12 pass / 4 skip / 0 fail):**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass + pass | pass (24/24 oracle match + audit invariant) |
| HR-01 | pass | skip |
| HR-02 | — | M3-deferred (must-map-driven) |
| HR-12 | skip | skip |
| **HR-14** | — | **pass (chain-tamper at exact index, 149-record chain)** |
| SV-AUDIT-TAIL-01 | — | pass (state-adaptive) |
| **SV-AUDIT-RECORDS-01** | — | **pass (2-page pagination, 149 records)** |
| **SV-AUDIT-RECORDS-02** | — | **pass (full chain integrity, 149 records)** |
| SV-SESS-BOOT-01 | — | pass |
| SV-SESS-BOOT-02 | — | skip (deployment variation) |
| SV-PERM-20 | — | pass (positive + 2-of-3 negative matrix; pda-decision-mismatch deferred) |
| SV-PERM-21 | — | skip (PDA signing fixture TBD — L-24) |
| SV-PERM-22 | — | pass (L-23 deployment-misconfig branch only; PDA-verify-wired branches deferred) |

**Run command:**
```
SOA_IMPL_URL=http://127.0.0.1:7700 \
SOA_RUNNER_BOOTSTRAP_BEARER=soa-conformance-week3-test-bearer \
SOA_IMPL_DEMO_SESSION=ses_demoWeek3Conformance01:soa-conformance-week3-decide-bearer \
SOA_DRIVE_AUDIT_RECORDS=120 \
soa-validate --profile=core --spec-vectors=<spec> --out=release-gate.json
```

**Still SKIP (honest, with precise diagnostics):**
- HR-01 live — impl cold-start restart hook
- HR-12 — M1 week 5 plan
- SV-SESS-BOOT-02 live — needs Runner with default ReadOnly card
- SV-PERM-21 live — needs PDA signing fixture (L-24 candidate, tracked, not blocking M1)

---

## 2026-04-20 (Week 3 day 3 end-of-day — SV-PERM-22 flipped; 9 pass / 5 skip / 0 fail)

**Done:**
- Impl shipped the L-23 binary (commit `f013434` rebuilt + restarted). Wire probe now returns `503 {"error":"pda-verify-unavailable","reason":"pda-verify-unavailable"}` — exact L-23 shape.
- **SV-PERM-22 handler upgraded** to assert the spec §10.3.2 L-23 branch: Runner deployed without `resolvePdaVerifyKey` MUST return 503 with `error == reason == "pda-verify-unavailable"`. Any `400 pda-verify-not-configured` response is now asserted as FAIL (non-conformant against pin 1971e87).
- **SV-PERM-22 → PASS.** Deployment-misconfig branch now carries positive live evidence. The crypto-invalid-PDA and structural-mismatch branches of SV-PERM-22 still aren't exercised on this deployment (they require PDA verification to be wired at startup) — handler makes this explicit in the passing message rather than claiming full coverage.

**Scoreboard: 14 tests, 9 pass / 5 skip / 0 fail.**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass + pass | pass (24/24) |
| HR-01 | pass | skip |
| HR-02 | — | M3-deferred |
| HR-12, HR-14 | skip | skip |
| SV-AUDIT-TAIL-01 | — | pass |
| SV-SESS-BOOT-01 | — | pass |
| SV-SESS-BOOT-02 | — | skip (deployment variation) |
| SV-PERM-20 | — | pass |
| SV-PERM-21 | — | skip (PDA signing fixture TBD) |
| **SV-PERM-22** | — | **pass (L-23 deployment-misconfig branch)** |

**Still blocked (honest skips carrying precise diagnostics):**
- HR-01 live — impl cold-start restart hook
- SV-SESS-BOOT-02 live — deployment variation (Runner with default ReadOnly card)
- SV-PERM-21 live — PDA signing fixture design (L-24 candidate)
- HR-12, HR-14 — M1 week 5 plan items
- V-06 (SV-AUDIT-RECORDS-01/02) + V-10 (HR-14 chain-tamper) — T-01 `/audit/records` pending

---

## 2026-04-20 (Week 3 day 3 — pin at 1971e87; SV-PERM-22 spec gap closed at root, awaiting impl adoption)

**Done:**
- **Pin-bumped `9ae1825 → 1971e87`** adopting **L-23 §10.3.2 pda-verify-unavailable 503 branch**. `spec_commit_sha = 1971e87d5e625cb6c9c07e8257d12ae61bee7877`, `spec_manifest_sha256 = 304b5bfe3dc8343a29702fc7c45928002fb5fd7fd80b153d47ae2b464a09b056`. Direct root-cause fix for the gap I flagged earlier today — 400 pda-verify-not-configured is now explicitly non-conformant; the correct wire shape is **503 + `{"error":"pda-verify-unavailable","reason":"pda-verify-unavailable"}`**.

**SV-PERM-22 transition plan:**
- Handler **unchanged this turn** — still recognizes current impl's 400 response as SKIP-with-diagnostic. Consistent with your "wait for impl to ship, then flip" ordering.
- When impl ships the 400 → 503 rename + pin-bump, handler gets upgraded to assert the new shape: `503 status` + `error == "pda-verify-unavailable"` + `reason == "pda-verify-unavailable"`. SV-PERM-22 flips SKIP → PASS in a single commit.
- Expected post-impl scoreboard: 9 pass / 5 skip / 0 fail.

**Scoreboard (UNCHANGED this turn): 14 tests, 8 pass / 6 skip / 0 fail.** Zero workaround-passes.

**Pending impl ships:**
- L-23 adoption (400 pda-verify-not-configured → 503 pda-verify-unavailable) → SV-PERM-22 flips to pass
- L-24 candidate: handler-key signing fixture → SV-PERM-21 unblocks
- T-01 `/audit/records` → V-06 (SV-AUDIT-RECORDS-01/02) + V-10 (HR-14 chain-tamper) unblock

**V-07 continues to accumulate real audit records each SV-PERM-20 run** — V-05 upgrade already fires on tail advancement (state-adaptive handler). V-06/V-10 fire the moment /audit/records ships.

---

## 2026-04-20 (Week 3 day 3 end — V-07 driver + SV-PERM-20 green; two honest skips + one real spec gap)

**Done:**
- **V-07 audit-record driver + V-05 upgrade + V-08 SV-PERM-20** all landed together. Full live run against impl's restarted Runner (pre-enrolled demo session `ses_demoWeek3Conformance01` with `canDecide=true`):
  - **SV-PERM-20 live → PASS.** Positive path: demo-bearer POST /permissions/decisions for `fs__read_file` → 201, schema-valid, `decision=AutoAllow` matches §10.3 oracle (forgery resistance), exactly `+1` audit record (record_count 3→4), `audit_this_hash` equals new tail hash. Auth-negative path: fresh session without `request_decide_scope` → 403 `reason=insufficient-scope` (L-22 corrected enum).
  - **SV-AUDIT-TAIL-01 live → PASS (state-adaptive rewrite).** Handler now covers both empty (GENESIS, `last_record_timestamp` omitted) and non-empty (hex64 `this_hash`, `last_record_timestamp` present) log states per spec §10.5.2. Two-read idempotence still enforced.
- **SV-PERM-21 → honest SKIP.** PDA-JWS happy path needs a handler key chained to the Runner's trust anchors; validator has no signing fixture. Needs either (a) spec-shipped signed PDA vector with a trust anchor the Runner can load, or (b) validator signing identity the Runner is configured to trust.
- **SV-PERM-22 → honest SKIP.** Runner deployment wasn't started with `resolvePdaVerifyKey`; PDA verification is unavailable on this deployment. Neither the crypto-invalid nor structural-mismatch branches of SV-PERM-22 can be exercised without PDA verification wired up.
- **Real spec gap surfaced:** impl returns `400 pda-verify-not-configured` when asked to verify a PDA on a deployment that has no verification wired. **`pda-verify-not-configured` is NOT in the §10.3.2 L-22 closed-enum reason set**, and 400 isn't one of the documented response codes for the endpoint. Spec may need either (a) a defined `503 pda-verify-unavailable` (or similar) for this deployment state, or (b) the endpoint to simply reject PDA submissions with a defined 4xx when verification is unconfigured.

**Scoreboard (14 tests total — 8 original M1 + 6 extension IDs):**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass + pass | pass (24/24 cells) |
| HR-01 | pass | skip |
| HR-02 | — | M3-deferred |
| HR-12, HR-14 | skip | skip |
| SV-AUDIT-TAIL-01 | — | **pass (state-adaptive)** |
| SV-SESS-BOOT-01 | — | pass |
| SV-SESS-BOOT-02 | — | skip (deployment variation) |
| **SV-PERM-20** | — | **pass (positive + auth-neg)** |
| **SV-PERM-21** | — | **skip (PDA signing fixture TBD)** |
| **SV-PERM-22** | — | **skip (deployment needs PDA verify wired)** |

**8 pass / 6 skip / 0 fail.** Zero workaround-passes.

**Still blocked on impl T-01 `/audit/records`:** V-06 (SV-AUDIT-RECORDS-01/02) + V-10 (HR-14 chain-tamper). V-07 has now accumulated real records; the chain integrity check fires the moment /audit/records lands.

---

## 2026-04-20 (Week 3 day 3 later — pin at 9ae1825; awaiting impl restart with RUNNER_DEMO_SESSION)

**Done:**
- **Pin-bumped `8c10ce9 → 9ae1825`**. `spec_commit_sha = 9ae1825bf2d8f97778b193ec1607f2f26a8b336c`, `spec_manifest_sha256 = 0e84c2c4136da1478a5d66fe585fd0ab6d7194b79ec74c14b0d1d9821145fd3f`. Single-reason bump: **L-22 §10.3.2 403 reason enum fix** — rename `missing-scope → insufficient-scope` + closed-enum reason set `{insufficient-scope, session-bearer-mismatch, pda-decision-mismatch, pda-malformed}`. Direct root-cause fix for the ConfigPrecedenceViolation-vs-missing-scope disagreement I surfaced this morning — my finding was correct; the spec typo originated in L-19 and L-22 pins the authoritative set.

**Validator state — unchanged from previous push:**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass + pass | pass (24/24) |
| HR-01 | pass | skip |
| HR-02 | — | M3-deferred |
| HR-12, HR-14 | skip | skip |
| SV-AUDIT-TAIL-01 | — | pass (fresh-Runner GENESIS) |
| SV-SESS-BOOT-01 | — | pass |
| SV-SESS-BOOT-02 | — | skip (needs ReadOnly-card Runner) |

**7 pass / 4 skip / 0 fail.**

**Pending impl next restart signal:**
- Impl restart with both env vars:
  - `SOA_RUNNER_BOOTSTRAP_BEARER=soa-conformance-week3-test-bearer` (same as before)
  - `RUNNER_DEMO_SESSION=ses_demoWeek3Conformance01:soa-conformance-week3-decide-bearer` (NEW — pre-enrolled session with `canDecide=true` baked in)
  - Impl also needs the one-line rename `missing-scope → insufficient-scope` adopted alongside L-22

**Queued for when impl restart signals ready (runs in one pass):**
- **V-07 audit-record driver** — loop N=150 `POST /permissions/decisions` for AutoAllow tools using the pre-enrolled demo session's bearer; each call writes an audit row.
- **V-05 upgrade** — after V-07, `GET /audit/tail` → `this_hash` is 64-char hex (no longer GENESIS), `record_count == 150`. Extends the existing SV-AUDIT-TAIL-01 to assert post-driver state.
- **V-08 SV-PERM-20/21/22**:
  - SV-PERM-20 positive: demo-session bearer drives `/permissions/decisions` successfully; schema-valid body; `audit_this_hash` equals new tail hash; decision mirrors `/permissions/resolve` output (forgery resistance).
  - SV-PERM-20 auth negative: a separately-created session without `request_decide_scope` → 403 `reason=insufficient-scope` (asserting the L-22 corrected enum value).
  - SV-PERM-21 PDA happy path + SV-PERM-22 PDA negative paths — require constructing a valid PDA-JWS validator-side (design TBD; may need an additional subprocess/signing fixture).

**Still blocked on T-01 `/audit/records`** — V-06 (SV-AUDIT-RECORDS-01/02) + V-10 (HR-14 chain-tamper). Use V-07 to accumulate records first; V-06/V-10 fire the moment T-01 ships.

---

## 2026-04-20 (Week 3 day 3 late — V-04 + V-05 green; parallel work while T-02 in flight)

**Done while impl works on T-02:**

- **V-05 SV-AUDIT-TAIL-01 live → PASS.** Against fresh Runner: `this_hash=GENESIS`, `record_count=0`, `last_record_timestamp` OMITTED (spec §10.5.2 MUST — not null, not empty string); two back-to-back reads stable on hash + count → not-a-side-effect idempotence satisfied.
- **V-04 SV-SESS-BOOT-01 live → PASS.** POST /sessions × 3 against the DFA conformance card (ReadOnly, WorkspaceWrite, DangerFullAccess all 201); every 201 body schema-valid per `session-bootstrap-response.schema.json`; `granted_activeMode == requested`; `session_id` and `session_bearer` meet schema shape constraints.
- **V-04 SV-SESS-BOOT-02 live → honest SKIP.** Requires a Runner loaded with the default `test-vectors/agent-card.json` (activeMode=ReadOnly) to exercise the 403 ConfigPrecedenceViolation path. Current deployment serves the DFA conformance card. Handler probes the live card shape first — if not ReadOnly, skips with precise diagnostic. Closing this gap requires either a second Runner instance or a subprocess-invocation test harness (V-09/V-12 scaffold territory).
- **Generic M3-deferral wiring.** Added `implementation_milestone` + `milestone_reason` to `SVTest` struct; test runner now automatically skips any test whose must-map entry declares `implementation_milestone != M1` with the spec-authored reason. HR-02 flips to skip via catalog rather than via hand-coded handler special-case. Keeps the source of truth in the spec.
- **Validator-side bug fix** from the V-03 run also shipped: schema-validation now runs against raw response bytes, not a re-encoded struct that dropped required fields.

**Current live scoreboard (11 tests total — original 8 M1 + 3 extension test IDs):**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass + pass | pass (24/24 cells + audit invariant) |
| HR-01 | pass | skip (impl cold-start hook pending) |
| **HR-02** | — | **M3-deferred (per must-map)** |
| HR-12 | skip | skip (M1 week 5 pending) |
| HR-14 | skip | skip (M1 week 5 pending) |
| **SV-AUDIT-TAIL-01** | — | **pass** |
| **SV-SESS-BOOT-01** | — | **pass** |
| SV-SESS-BOOT-02 | — | skip (deployment variation needed) |

**7 pass / 4 skip / 0 fail.** Zero workaround-passes; every skip carries a spec-grounded or deployment-grounded diagnostic.

**Waiting on impl T-02 (`POST /permissions/decisions`)** — that unblocks V-07 (audit-record driver), V-05 upgrade (tail advances past GENESIS after real records land), V-06 (SV-AUDIT-RECORDS-01/02), V-08 (SV-PERM-20/21/22 decision endpoint), V-10 (HR-14 tamper test).

**Scaffolding in parallel (parked, not shipped):** V-09 (HR-12) and V-12 (SV-BOOT-01 negatives) subprocess harness pattern — spawn impl binary with env-var-varied configuration, run assertions, reap. Holding on implementation until a broader subprocess-invocation design is settled (same pattern needed for SV-SESS-BOOT-02 live too).

---

## 2026-04-20 (Week 3 day 3 end — V-03 GREEN end-to-end; 7 pass / 1 skip / 0 fail)

**Done:**
- **V-03 (24-cell SV-PERM-01 live sweep) flipped SKIP → PASS.** With the shared bootstrap bearer in the shell, ran three POST /sessions (one per activeMode — all three provisioned against the L-18 DFA conformance card), captured `/audit/tail` `this_hash=GENESIS`, ran 8 tools × 3 activeModes = 24 GET /permissions/resolve calls, every single decision matched the validator's §10.3 oracle byte-for-byte, re-captured `/audit/tail` → `this_hash=GENESIS` unchanged. **§10.5.2 not-a-side-effect MUST satisfied** across 24 queries.
- **Fixed a validator-side bug** discovered during the run: my `resolveResponse` struct omitted the `trace` field, so my handler was marshaling the decoded struct back to JSON (losing `trace`) before schema validation — producing a spurious "missing `trace`" failure. Corrected to schema-validate the raw response bytes directly, not a lossy round-trip. Impl's response was always correct.

**Final Week 3 live scoreboard:**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| **SV-PERM-01** | pass + pass | **pass** (24/24 cells, audit invariant) |
| HR-01 | pass | skip |
| HR-02 | pass | pass (binary) |
| HR-12, HR-14 | skip | skip |

**7 pass / 1 skip / 0 fail.** Only lingering skip is HR-01 live, which needs impl to expose a cold-start restart hook.

**Queued for impl-side ship:** `POST /permissions/decisions` (T-02), `GET /audit/records` (T-01), `request_decide_scope` (T-03). When those land, V-07 / V-05 / V-06 / V-08 / V-10 become runnable.

---

## 2026-04-20 (Week 3 day 3 late — pin at 8c10ce9; SV-CARD-01 live flipped; live wiring unparked; V-03 needs bearer)

**Done since last push:**
- **Pin-bumped `80680cd → 8c10ce9`**. `spec_commit_sha = 8c10ce9269f426396dbed07e41ac567d1a2f1813`, `spec_manifest_sha256 = f38ca28f47…a3a54`. Single-reason: L-21 conformance-card fixture schema conformance (three fixes resolving my Week 3 day 3 finding — `max_iterations: 0→1`, `policyEndpoint: null` removed, `spki_sha256` valid hex64 placeholder).
- **SV-CARD-01 live flipped fail → pass.** Runner serves the fixed conformance card (`soa-conformance-test-agent`, `activeMode=DangerFullAccess`); full agent-card schema validates cleanly on the wire.
- **Live wiring unparked** — `internal/testrunner/handlers.go` now shipped with the §10.3.1 + §12.6 + §10.5.2 live path (POST /sessions × 3, 24-cell sweep with oracle compare, /audit/tail this_hash invariant). **Partial-pass anti-pattern removed**: if fewer than 3 sessions provision, handler returns SKIP with diagnostic — never PASS on partial coverage.
- **must-map loader updates** forced by L-13 catalog growth: test count bumped 213 → 221; ID regex now accepts multi-segment categories (`SV-SESS-BOOT-01`, `SV-AUDIT-TAIL-01`, etc.).

**Current live scoreboard against 127.0.0.1:7700:**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | **pass (NEW — fixture fixes at 8c10ce9)** |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass (prompt + 24-cell oracle) | skip (no `SOA_RUNNER_BOOTSTRAP_BEARER` in shell) |
| HR-01 | pass | skip |
| HR-02 | pass | pass (binary) |
| HR-12, HR-14 | skip | skip |

**6 pass / 2 skip / 0 fail.**

**V-03 (24-cell live sweep) ready to run.** Handler code ships with all the plumbing; needs only `SOA_RUNNER_BOOTSTRAP_BEARER` exported in the validator's shell (same value the Runner was launched with). When set, handler will POST /sessions × 3 (all 3 activeModes now provisionable against the DFA card), GET /audit/tail baseline, sweep 24 cells asserting impl-decision == §10.3-oracle-decision, GET /audit/tail again and assert this_hash unchanged.

**Flagged pending — relabel task (rev 2 plan):** my HR-01 / HR-02 vector assertions (initial-trust schema coverage + CRL state-machine coverage) don't match the HR-01 "Destructive approval" / HR-02 "Budget exhaustion" entries in the must-map; those were label-misuses from the original Week 2 plan. The rev 2 plan's formal relabel moves them to SV-BOOT-01 negative-path coverage or new local labels. Holding the relabel as a focused follow-up commit.

**Queued for impl-side ship:** `POST /permissions/decisions` (T-02), `GET /audit/records` (T-01), `request_decide_scope` (T-03). When those land, V-07 / V-05 / V-06 / V-08 / V-10 can run end-to-end.

---

## 2026-04-20 (Week 3 day 3 — pin at 80680cd; draft live wiring parked pending impl card loader; 6/2/0 stays honest)

**Gap I surfaced today (day 3 morning) — and the upstream fix that closed it:**
- The live SV-PERM-01 sweep per §10.3.1 requires 24 cells = 8 tools × 3 activeMode values. The test deployment's Agent Card was `activeMode = ReadOnly`, which correctly forces §12.6's tighten-only gate to 403 any WorkspaceWrite/DangerFullAccess session request. Only 8 of 24 cells were reachable → SV-PERM-01 live test-as-spec'd cannot run.
- I started writing live-path code that would provision whatever sessions succeeded and report partial coverage as `pass`. User corrected before I pushed — that's the workaround-instead-of-validation anti-pattern. Draft wiring stays **parked** (uncommitted in the working tree) until the root-cause upstream fix lands.
- **Upstream fix:** spec commit `80680cd` (second plan-evaluator pass, L-18 + L-19) ships a **DangerFullAccess conformance Agent Card** in `test-vectors/` and adds `POST /permissions/decisions` so the validator can drive audit-chain accumulation end-to-end with zero impl-specific coupling. Impl still has to ship a **card loader** that consumes the conformance card for test runs. Live-path wiring unparks the moment that loader lands.

**Done today:**
- **Pin-bumped `e7580b9 → 80680cd`**. `spec_commit_sha = 80680cd76129f4e1d5c4ea43383aa28e0da2c9f2`, `spec_manifest_sha256 = 3fc4623766…21ad896`. Spec commits adopted: `ffe30ed` (L-16/L-17/L-18 conformance fixtures), `e8b4e9e` (L-15 §10.5.3 /audit/records), `8b35375` (L-13/L-14 must-map catalog integration), `80680cd` (L-19 §10.3.2 POST /permissions/decisions + L-20 session-schema sync).
- New test IDs now in the must-map catalog: `SV-AUDIT-TAIL-01`, `SV-AUDIT-RECORDS-01/02`, `SV-SESS-BOOT-01/02`, `SV-PERM-20/21/22`. HR-02 deferred to M3 per L-14. Total must-map tests 213 → 221.
- **Draft live wiring parked** in working tree (uncommitted): `internal/testrunner/handlers.go` carries +237 lines of POST /sessions + GET /audit/tail + /permissions/resolve sweep + audit-tail invariant check code. Compiles + vets clean; does nothing until `SOA_RUNNER_BOOTSTRAP_BEARER` is set AND impl ships the conformance-card loader so the full 24-cell sweep becomes reachable.

**Scoreboard — UNCHANGED, STAYS HONEST:**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | pass (permission-prompt + 24-cell Tool Registry oracle) | **skip** (waiting on impl conformance-card loader; see gap above) |
| HR-01 | pass | skip |
| HR-02 | pass | pass (binary accept/reject only per coordination) |
| HR-12, HR-14 | skip | skip |

**6 pass / 2 skip / 0 fail.** Refuses to inflate via partial-coverage substitution.

**Waiting on impl:**
- Conformance-card loader (loads `test-vectors/…` DangerFullAccess card for test runs so §10.3.1's three-activeMode sweep is reachable)
- `POST /permissions/decisions` implementation
- `GET /audit/records` implementation

**When all three land:** unpark live wiring, add SV-PERM-20/21/22 handlers, add SV-AUDIT-TAIL-01 + SV-AUDIT-RECORDS-01/02 + SV-SESS-BOOT-01/02 handlers, exercise the full audit-chain accumulation path.

---

## 2026-04-20 (Week 3 day 2 — pin at e7580b9; Tool Registry oracle vector-green; live still waiting on /sessions + /audit/tail)

**Done:**
- **Pin-bumped `2eccf6e → e7580b9`**. `spec_commit_sha = e7580b93e5d14911d427556b11b99f5457611188`, `spec_manifest_sha256 = 7d4406165f…f2af2dc0`. Single-reason bump adopts L-10/L-11/L-12: §10.5.2 audit tail, §12.6 session bootstrap, pinned tool-registry fixture with the 24-cell decision matrix.
- `internal/toolregistry` — loader + shape for `test-vectors/tool-registry/tools.json` (8 tools, deliberately spans every `(risk_class, default_control)` lattice row).
- `internal/permresolve` — validator's **independent re-implementation of Core §10.3**. Pure function: `Resolve(risk, defaultControl, capability, overrideControl) → Decision`. Encodes:
  - Step 2 capability lattice: ReadOnly ⊂ WorkspaceWrite ⊂ DangerFullAccess covers {ReadOnly, Mutating, Destructive, Egress}
  - Step 3 tighten-only composition with `ConfigPrecedenceViolation` on loosening override
  - Terminal decisions: AutoAllow | Prompt | Deny | CapabilityDenied | ConfigPrecedenceViolation
- 3 unit tests, including `TestOracleMatchesSpec24CellMatrix` that hand-mirrors the `test-vectors/tool-registry/README.md` table and asserts oracle output equals the spec-authored value for every cell. Any drift between my §10.3 implementation and the spec's authoritative statement → test fails.
- **SV-PERM-01 vector path now carries two pass items:**
  1. Existing permission-prompt vector (nonce equality, JCS=385B, spec-authored SHA digest match, PDA-JWS shape)
  2. New Tool Registry oracle: 8 tools × 3 activeModes = 24 enum-valid decision cells, oracle matches spec 24-cell matrix
- SV-PERM-01 live message upgraded to name the exact surfaces that unblock it: **`POST /sessions` (§12.6)** + **`GET /audit/tail` (§10.5.2)** — both 404 on current impl at :7700.

**Test count:** 45 unit tests across 10 internal packages. `go vet ./...` clean, `go test ./...` green, `go build` produces static binary.

**Live scoreboard (unchanged — waiting on impl's next ship):**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| SV-PERM-01 | **pass (2 items: permission-prompt + Tool-Registry oracle)** | skip |
| HR-01 | pass | skip |
| HR-02 | pass | pass (binary accept/reject only) |
| HR-12, HR-14 | skip | skip |

**6 pass / 2 skip / 0 fail.**

**Ready for live flip:** the moment impl ships POST /sessions + GET /audit/tail, the live path handler will:
1. `POST /sessions` three times (requested_activeMode = ReadOnly | WorkspaceWrite | DangerFullAccess) to obtain three session bearers
2. `GET /audit/tail` → capture baseline `this_hash`
3. For each of the 24 cells, `GET /permissions/resolve?tool=<name>&session_id=<sid>` with the matching bearer; assert `response.decision` == oracle-computed decision
4. `GET /audit/tail` → capture post-batch `this_hash`; assert equal (not-a-side-effect per §10.3.1 normative MUST)

All wiring designed against the new normative text; no impl-specific assumptions baked in.

**Awaiting:**
- Impl ships `POST /sessions` + `GET /audit/tail` on :7700
- L-13 catalog integration lands new test IDs `SV-AUDIT-TAIL-01`, `SV-SESS-BOOT-01/02` in `soa-validate-must-map.json`

---

## 2026-04-20 (Week 3 day 1 — pin at 2eccf6e; §10.3.1 endpoint is the root-cause fix for SV-PERM-01 live gap; awaiting impl)

**Done:**
- **Pin-bumped `fe74d39 → 2eccf6e`**. `spec_commit_sha = 2eccf6e6fc4c4c55da0afdcff315f50c4f0e9f82`, `spec_manifest_sha256 = 838cacbc…f40b8770`. Single-reason bump: spec commit `2eccf6e` adds **§10.3.1 Permission Decision Observability** — a new normative endpoint `GET /permissions/resolve?tool=<tool_name>&session_id=<session_id>` plus `schemas/permissions-resolve-response.schema.json`. This is the **root-cause fix** for the Week 2 SV-PERM-01 live-path gap (previously: no HTTP surface for the permission flow; I proposed and the user correctly pushed back on a /ready-proxy workaround; instead, the spec now mandates the surface).
- Confirmed spec MANIFEST digest locally matches the value in the user's paste.
- **No validator code changes landed today.** Week 3 validator work waits on impl shipping the endpoint.

**Endpoint shape the validator will consume (from §10.3.1 + the new schema):**
- `GET /permissions/resolve?tool=<name>&session_id=<sid>` over TLS 1.3; session-scoped bearer required
- Response 200: `{decision ∈ {AutoAllow, Prompt, Deny, CapabilityDenied, ConfigPrecedenceViolation}, resolved_control, resolved_capability, reason (closed enum), trace[1..5], resolved_at, runner_version, policy_endpoint_applied?}`
- **Not-a-side-effect property (normative MUST):** the query MUST NOT mutate the audit log's `this_hash` chain, emit StreamEvents, or change session/registry/CRL state. Validator asserts this by reading audit tail hash before and after the query batch.
- Deterministic `args_digest` fixture value: literal string `"SOA-PERM-RESOLVE-QUERY"` on any forwarded `policyEndpoint` POST.

**Week 3 validator work queued (runs once impl ships):**
1. Wire `permissions-resolve-response.schema.json` into the schema registry.
2. Establish a validator session via impl's bearer-provisioning surface (details TBD from impl).
3. For each tool in the pinned Tool Registry fixture × each `activeMode` value, GET `/permissions/resolve?tool=<name>&session_id=<sid>`.
4. Assert `decision` matches the §10.3 algorithm output computed validator-side from the same fixture inputs.
5. Not-a-side-effect: read audit-log tail `this_hash` before/after the batch; assert equal. Mutation → loud fail.

**HR-02 live — clarification (no change):** /ready proxy stays as the binary accept/reject check per coordination. Evidence message explicitly scopes its claim: `/ready=200` ⇔ CRL cache in an accept state; full three-state-precise live coverage defers to L-10 or a future diagnostic surface. Not claiming the full HR-02 live invariant.

**Active (this repo):** nothing — awaiting impl's `/permissions/resolve` ship signal.

**Scoreboard unchanged from Week 2 CLOSE:**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | — | pass |
| HR-02 | pass | pass (binary accept/reject only; see clarification above) |
| HR-01 | pass | skip (cold-start hook not exposed) |
| SV-PERM-01 | pass | skip (endpoint pending impl) |
| HR-12, HR-14 | skip | skip |

---

## 2026-04-20 (Week 2 CLOSE — HR-02 live flipped; SV-PERM-01 live gap flagged)

**Done (after impl's Week 2 close signal):**
- Pulled impl STATUS — confirms Week 2 closed at pin `fe74d39`; clock hook (`RUNNER_TEST_CLOCK`), boot orchestrator, and full verification libraries (`verifyAgentCardJws`, `verifyPda`, `resolvePermission`) landed.
- Route inventory on `:7700` (from impl source `grep -rnE '\.(get|post)\('`): `/health`, `/ready`, `/.well-known/agent-card.json`, `/.well-known/agent-card.jws` — no permission HTTP route registered.
- **HR-02 live path wired** to `/ready` observation. Per impl's Week 2 boot orchestrator: `/ready=200` ⇔ CRL cache is in an accept state (`fresh` or `stale-but-valid`); `/ready=503` with reason `crl-expired` ⇔ expired. `/ready=200` on the running impl → HR-02 live = **pass**. Stale/expired live transitions require orchestrated Runner restarts with `RUNNER_TEST_CLOCK` set to a controlled instant — that's CI-level test scaffolding, not a single-invocation validator test.
- **SV-PERM-01 live path remains skip** with an upgraded evidence message: impl currently exposes the permission flow as a library (`resolvePermission` + `verifyPda`), not an HTTP route. No `/permission`, `/prompt`, `/session`, `/v1/permission`, `/decisions`, or equivalent is registered.

**Week 2 CLOSE scoreboard (live against 127.0.0.1:7700):**

| Test | vector | live |
|---|---|---|
| SV-CARD-01 | pass | pass |
| SV-SIGN-01 | pass | pass |
| SV-BOOT-01 | skip | pass |
| **HR-02** | pass | **pass** (NEW) |
| HR-01 | pass | skip (impl cold-start hook not exposed) |
| SV-PERM-01 | pass | skip (impl permission flow is library-only) |
| HR-12, HR-14 | skip | skip |

**6 pass / 2 skip / 0 fail.** All four week-2 targeted test IDs now carry real positive-path evidence on the vector side; three of the four also carry live positive-path evidence; SV-PERM-01 is the lone live-gap.

**Open question for coordination (flagging, not blocking):** SV-PERM-01 live requires an HTTP path. Options — (a) impl wires a `/permission` / `/session` SSE flow in Week 3; (b) SV-PERM-01 live gets explicitly rescoped out of M1 (Core §10.3/§10.4 permissions are testable at the library layer via their 19-test permission.test.ts plus our vector-path cross-check of JCS digest byte equality); (c) impl exposes a test-only `/debug/permission` endpoint in non-prod builds gated by the same L-01 guards that protect `RUNNER_TEST_CLOCK`. No decision needed to close Week 2; this is Week 3 coordination.

---

## 2026-04-20 (Week 2 day 2 late — pin at fe74d39; L-01 clock-injection normative; live HR-02/SV-PERM-01 still impl-side blocked)

**Done:**
- **Pin-bumped `9d25163 → fe74d39`**. `spec_commit_sha = fe74d3931e50f52697d8fab0c07336a9f3bb099e`, `spec_manifest_sha256 = 00d6755d…c6171c`. Single-reason bump: spec commit `fe74d39` lands L-01 clock-injection note at §10.6.1 — the `T_ref = 2026-04-20T12:00:00Z` harness injection the validator already uses for HR-02 now stands on spec-authored normative text (not just inferred from README). **No validator code change.**
- Smoke re-run after pin bump against live impl at `127.0.0.1:7700`: **6 pass / 2 skip / 0 fail** — same scoreboard as day-2 close, confirming the bump is semantically a no-op on the assertion side.
- `internal/crlstate` and `internal/inittrust` coverage stands unchanged; they already implement what §10.6.1's L-01 describes at the validator end.

**Impl-side blockers for Week 2 formal close (neither has a >24h delay signal yet):**

1. **SV-PERM-01 live path.** Impl's STATUS.md lists "live SV-PERM-01 smoke against the pda.jws fixture" as still *Active*. No HTTP endpoint is reachable on :7700 that serves the permission flow yet (probed `/permission`, `/permissions`, `/v1/permission`, `/prompt`, `/api/permission` — all 404). Permission resolver + PDA verifier code has landed on their side (108 tests, Core §10.3 + §10.4 modeled), so the gap is purely the HTTP wiring.
2. **HR-02 live clock injection.** Impl STATUS makes no mention of a `RUNNER_TEST_CLOCK` env var or any clock-injectability hook. That plumbing is Week 2 exit-criterion work on their side; my validator is ready to consume it (just needs the Runner to honor T_ref on the CRL cache evaluation path).

**Week 2 exit-criterion status:**

| Criterion | State |
|---|---|
| SV-CARD-01 vector+live | **met** |
| SV-SIGN-01 vector+live | **met** |
| SV-BOOT-01 live | **met** |
| SV-PERM-01 vector+live | vector met; **live waiting on impl HTTP permission endpoint** |
| HR-01 positive-path vector | **met** |
| HR-02 positive-path vector (3 states @ T_ref) | **met** |
| HR-02 positive-path live (at T_ref via impl hook) | **waiting on impl clock-injection plumbing** |

**Two auto-flip conditions on standby:**
- When impl serves a permission endpoint + /ready = 200 post boot-wiring, SV-PERM-01 live handler will run against the wire — no validator code change needed.
- When impl honors a `T_ref` / `RUNNER_TEST_CLOCK` injection, the HR-02 live handler path can be wired to send `X-SOA-Test-Clock` (or whatever header/env they accept) and assert the same three-state classification on the live side.

**Flag for coordination:** if impl indicates >24h slippage on either piece, I'll propose either (a) rolling those live cells into Week 3, or (b) offering specific support on the clock-hook design (the §10.6.1 L-01 text gives a clean contract to implement against).

---

## 2026-04-20 (Week 2 day 2 — HR-01 + HR-02 upgraded to positive+negative; pin at 9d25163)

**Done:**
- **Pin-bumped `1f72bf6 → 9d25163`** to consume the new spec fixtures. `spec_manifest_sha256` updated to `82c78d53…2a7337` (MANIFEST regen added 8 supplementary_artifacts for initial-trust/ + crl/).
- `internal/inittrust` — post-parse semantic gate for Core §5.3. Pure functions: `Parse` + `SemanticValidate(bundle, now) → Reason`. Closed-set reason codes (`bootstrap-expired`). 3 unit tests.
- `internal/crlstate` — §7.3.1 three-state classifier. `Classify(crl, now) → {State, Accept, RefreshNeeded, FailureReason}`. 4 unit tests covering fresh, stale-but-valid, expired-past-not_after, and expired-past-2h-ceiling.
- **HR-01 vector path upgraded to positive+negative:**
  - `valid.json` → schema-valid AND semantic-valid (`not_after` in 2099)
  - `expired.json` → schema-valid BUT semantic-reject with `bootstrap-expired` (rejection comes from post-parse clock gate, NOT schema)
  - `channel-mismatch.json` → schema-reject (closed enum guard on `channel`)
  - Plus 4 inline negatives for fuzzy-edge schema coverage
- **HR-02 vector path upgraded to full state-machine coverage** with `T_ref = 2026-04-20T12:00:00Z` clock injection:
  - `fresh.json` @ T_ref → `fresh`, accept, **no refresh queued**
  - `stale.json` @ T_ref → `stale-but-valid`, accept, **refresh queued** (side effect asserted)
  - `expired.json` (any clock) → `expired`, fail-closed, `crl-expired` reason
  - Plus 4 inline schema negatives
- **All four targeted tests now show true positive-path evidence, not just negative assertions.**

**Scoreboard at end of Week 2 day 2:**

| Test | vector evidence | live |
|---|---|---|
| SV-CARD-01 | pass (schema + JCS idempotent) | pass |
| SV-SIGN-01 | pass (header shape + JCS signing-input) | pass |
| SV-PERM-01 | pass (JCS=385 bytes + SHA digest match against spec README) | skip |
| **HR-01** | **pass (positive + semantic-reject + schema-reject + 4 negatives)** | skip |
| **HR-02** | **pass (3 state-machine cases + 4 negatives)** | skip |
| SV-BOOT-01 | skip | pass |
| HR-12, HR-14 | skip | skip |

**Totals: 6 pass / 2 skip / 0 fail against live impl at `127.0.0.1:7700`.**

**Test count:** 39 unit tests across 7 packages (jcs, digest, musmap, agentcard, permprompt, runner, inittrust, crlstate). `go vet ./...` clean, `go build` green.

**Waiting on:**
- Impl permission resolver + PDA verifier — once their STATUS.md signals, SV-PERM-01 live can flip.

---

## 2026-04-20 (Week 2 day 1 close — SV-BOOT-01 flipped green after impl shipped §5.4 probes)

**Done:**
- Impl shipped `GET /health` and `GET /ready`; both return 200. SV-BOOT-01 live flipped **fail → pass** on re-run — no code change on this side.
- Full scoreboard at end of Week 2 day 1:

  | Test | vector | live |
  |---|---|---|
  | SV-CARD-01 | pass | pass |
  | SV-SIGN-01 | pass | pass |
  | SV-PERM-01 | pass | skip (waiting on impl permission endpoint) |
  | HR-01 | pass (negative) | skip (cold-start hook) |
  | HR-02 | pass (negative) | skip (CRL introspection) |
  | **SV-BOOT-01** | skip | **pass** |
  | HR-12, HR-14 | skip | skip |

  **6 pass / 2 skip / 0 fail.** First clean exit against a live Runner.

**Tomorrow:**
- Pin-bump to spec commit `9d25163` (new `HR-01` + `HR-02` positive-path vectors land). `spec_manifest_sha256` changes on this bump. Upgrade HR-01 / HR-02 vector assertions from negative-only to negative + positive.
- When impl's permission resolver + PDA verifier ship, SV-PERM-01 live can flip green too.

---

## 2026-04-20 (Week 2 — SV-PERM-01 + HR-01 + HR-02 vector green; SV-BOOT-01 surfaces impl gap)

**Week 2 scoreboard:**

| Test | vector | live | note |
|---|---|---|---|
| SV-CARD-01 | pass | pass | carried over from Week 1 |
| SV-SIGN-01 | pass | pass | carried over from Week 1 |
| **SV-PERM-01** | **pass** | skip | live waiting on impl permission endpoint |
| **HR-01** | **pass (negative)** | skip | positive vector missing — see spec-repo gap below |
| **HR-02** | **pass (negative)** | skip | positive vector missing — see spec-repo gap below |
| **SV-BOOT-01** | skip | **fail** | impl has not shipped §5.4 `/health` + `/ready` — **real conformance gap** |
| HR-12, HR-14 | skip | skip | M1 week 5 |

**Done:**
- `internal/permprompt` package — loads + schema-validates the pinned `permission-prompt/` vector set (prompt, canonical_decision, PDA-JWS), enforces UV-P-18 nonce equality + prompt_id equality. 4 unit tests.
- **SV-PERM-01 vector path** confirms:
  - `canonical-decision.json` validates against `schemas/canonical-decision.schema.json`
  - `decision.nonce == prompt.payload.nonce` ("q9Zt-X8bL4rFvH2kNpR7wS")
  - `JCS(canonical-decision.json)` = **385 bytes**, matching the pinned count in `test-vectors/permission-prompt/README.md`
  - `sha256(JCS(canonical-decision.json))` = **`7bc890692f68b7d3b842380fcf9739f9987bf77c6cdf4c7992aac31c66fe4a8a`**, matching the pinned digest in the spec README — **first cross-library digest equality against a spec-authored expected value**
  - `pda.jws` parses with `alg=EdDSA, typ=soa-pda+jws`; signature is placeholder (crypto verify deferred)
- **HR-01 vector path** — negative-path coverage only: 4 inline fixtures (`{}`, wrong `soaHarnessVersion`, extra field via `additionalProperties:false`, short `spki_sha256`) all correctly rejected by `schemas/initial-trust.schema.json`.
- **HR-02 vector path** — negative-path coverage only: 4 inline fixtures (`{}`, missing `revoked_kids`, extra field, incomplete-revoked-kid) all correctly rejected by `schemas/crl.schema.json`.
- **SV-BOOT-01 live path** — probes `/health` + `/ready`; reports impl gap when both 404.

**Spec-repo gaps flagged (per plan: DO NOT author expected outputs locally):**

1. **HR-01 happy-path vector** — no `test-vectors/initial-trust/` directory. Minimum scope needed:
   - `valid.json`: legit bundle with a real `publisher_kid` + `spki_sha256` matching a specific trust anchor
   - `expired.json`: same as valid but `not_after` in the past
   - `channel-mismatch.json`: channel value not in the `sdk-pinned` | `operator-bundled` | `dnssec-txt` enum
   Would be generated deterministically (like `jcs-parity/`): input bundle → schema-validated output with expected validation outcome.

2. **HR-02 CRL state-machine vectors** — no `test-vectors/crl/` directory. Minimum scope: fresh (now < not_after), stale (warning window pre-expiry), expired (past not_after). Each case's expected Runner behavior per §5.3 would be pinned.

**Impl gap surfaced by SV-BOOT-01:**
- `GET /health` → 404, `GET /ready` → 404. Both are required by Core §5.4 (liveness + readiness probes) for M1 conformance. Not failing the test softly — this is a loud 'fail' line until impl ships them. Live SV-BOOT-01 will flip to pass the moment both probes come up.

**Active:**
- Nothing blocked on this side. When impl's Week 2 (StreamEvent SSE) + §5.4 probes land, re-run live.

**Command used:**
- Vector-only: `soa-validate --profile=core --spec-vectors=<spec>` → 5 pass / 3 skip
- Full: `SOA_IMPL_URL=http://127.0.0.1:7700 soa-validate --profile=core --spec-vectors=<spec>` → 5 pass / 2 skip / 1 fail

---

## 2026-04-20 (Week 1, end-of-day — FIRST GREEN E2E)

**Done:**
- **First real end-to-end green across all three repos.** `SOA_IMPL_URL=http://127.0.0.1:7700 soa-validate --profile=core --spec-vectors=<spec>` produces:
  ```
  SV-CARD-01     pass  passed (vector,live)
  SV-SIGN-01     pass  passed (vector,live)
  total=8 pass=2 fail=0 skip=6 error=0
  ```
  Per-path evidence:
  - **SV-CARD-01 live:** 200 OK on `/.well-known/agent-card.json`, validates against `schemas/agent-card.schema.json`, `Cache-Control: max-age=300` ≤ 300s, ETag present (`0d86a163…`).
  - **SV-SIGN-01 live:** 200 OK on `/.well-known/agent-card.jws` (spec-normative path), protected header is `{alg:"EdDSA", kid:"soa-release-v1.0", typ:"soa-agent-card+jws", x5c:["MIIBHDCBz6…"]}` — matches §6.1.1 row 1 exactly, including required `x5c`.
- **Lock bumped `6c1bc99 → 1f72bf6`** (URL-shorthand clarification commit; `spec_manifest_sha256` unchanged).
- **Week 1 scoreboard:**
  | Test | vector | live | notes |
  |---|---|---|---|
  | SV-CARD-01 | pass | pass | schema + JCS idempotent + Cache-Control/ETag |
  | SV-SIGN-01 | pass | pass | header shape (`typ=soa-agent-card+jws`, `x5c[0]` present); crypto verify against `trustAnchors` chain lands in M1 week 5 alongside HR-12 (ETag-triggered re-verify) |
  | HR-01, HR-02, HR-12, HR-14, SV-BOOT-01, SV-PERM-01 | skip | skip | assertions land in M1 weeks 3/5/6 |

**Meta observation:** the first live run exposed three impl↔spec divergences (URL path, JWS `typ`, missing `x5c`). Spec clarified §5.1 shorthand without normative change (commit `1f72bf6`); impl fixed all three per §6.1.1 row 1 literal. Independent-judge setup worked exactly as designed — same-author single-repo would've never surfaced these.

---

## 2026-04-20 (Week 1, earlier)

**Done:**
- **SV-CARD-01 + SV-SIGN-01 assertion logic complete, passing on the pinned spec vector.** No live Runner required.
  - SV-CARD-01 vector path: card JSON validates against `schemas/agent-card.schema.json` (JSON Schema 2020-12 via `santhosh-tekuri/jsonschema/v5`); JCS canonicalization is idempotent (1617 canonical bytes).
  - SV-SIGN-01 vector path: JWS structurally valid — three segments, EdDSA alg, `typ=soa-agent-card+jws`, non-empty `kid`, detached payload; signing-input re-canonicalization succeeds. Placeholder-'0' signature detected; full crypto verify deferred per vector design.
- `internal/specvec` — pinned-vector locator (wraps `--spec-vectors` root, exposes well-known paths for card/schema/jws).
- `internal/agentcard` — `ValidateJSON` (schema) + `ParseJWS` (structural + header) + `IsPlaceholderSignature`. 7 unit tests.
- `internal/runner` — TLS finalization:
  - `BuildTLSConfig(TLSOptions{…})` — trust anchor from PEM file, optional client cert/key for mTLS, SNI override, min TLS 1.2.
  - Bearer injection, `/health`, `/ready`, SSE consumer for `/stream/v1/{sessionID}` — all now covered by unit tests against pure-Go `httptest.Server` + `httptest.NewTLSServer` fixtures (8 runner tests, including real mTLS trust-anchor round trip).
- `internal/testrunner` + `internal/junit` — per-path **Evidence** model:
  - Every test ID produces one Evidence entry per probe path (`vector`, `live`). Aggregate Status across entries: fail if any fail, else pass if any pass, else skip.
  - JUnit XML emits each Evidence as a `<property name="evidence.<path>" value="<status>">` and `<system-out>` summary. CI artifact now differentiates **passed-on-vector**, **passed-on-live**, **skipped-waiting-on-impl**, and **failed**.
- `release-gate.json` v2 adds `impl_url`, `live_path_enabled` fields and nested per-result `evidence[]` arrays.
- CLI: added `--impl-url` flag; `SOA_IMPL_URL` env var read as fallback; `--runner-url` kept as back-compat alias. Live path is enabled only when the target answers a 3-second health probe.

**Active:**
- Nothing blocking on this side for vector-path Week 1 work. Waiting on impl's `/.well-known/agent-card.json` + `.jws` endpoints to exercise live path.

**When impl Runner is up, flipping to live-path is zero-code-change on our side:**
- `SOA_IMPL_URL=https://runner.example.com:7700 soa-validate --profile=core --spec-vectors=<spec>` enables live checks automatically.
- For mTLS: pass `--impl-url` + configure TLS trust-anchor PEM (wiring that flag is a 5-min follow-up, will land alongside the first live-successful run).

**Spec commits this validator assumes exist:**
- `6c1bc99` — committed `generated/` parity vectors; MANIFEST unchanged since `208e5dd`.

---

## 2026-04-20 (earlier)

**Done:**
- Week 0 complete. Static Go binary builds, `go vet ./...` clean, `go test ./...` green.
- `internal/musmap` — SV + UV must-map loader + structural validator. Confirms 213-test catalog round-trips.
- `internal/jcs` — RFC 8785 canonicalizer (uses `github.com/gowebpki/jcs v1.0.1`) + parity harness against spec's `test-vectors/jcs-parity/generated/*.json`. **47/47 cases agree** across both libraries (floats 15, integers 9, nested 11, strings 12). JCS byte-equivalence invariant is proven on this side.
- `internal/digest` — SHA-256 helpers matching spec's `build-manifest.mjs` convention.
- `internal/runner` — HTTP client with mTLS + bearer + SSE consumer for `/stream/v1/{sessionID}`, `/health` + `/ready` probes.
- `internal/testrunner` — phase-ordered dispatch from must-map to handler. Stub handlers registered for all 8 M1 test IDs (`HR-01, HR-02, HR-12, HR-14, SV-SIGN-01, SV-CARD-01, SV-BOOT-01, SV-PERM-01`), all returning `skip` with "assertions land in M1 week N".
- `internal/junit` — JUnit XML emitter. Week 0 exit command emits 8/8 skipped.
- `soa-validate.lock` bumped `208e5dd → 6c1bc99` (see pin_history). MANIFEST unchanged between those commits.

**Active:**
- M1 Week 1 assertions for `SV-CARD-01` + `SV-SIGN-01`.

**Blocked:**
- Sibling impl lockstep pin bump (resolved in the impl's own Week-0 sign-off commit — both repos now pinned at `6c1bc99`).
