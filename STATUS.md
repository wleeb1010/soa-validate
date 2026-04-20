# STATUS — soa-validate

Daily log the sibling `soa-harness-impl` session reads on `git pull`. Most recent date on top.

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
