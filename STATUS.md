# STATUS — soa-validate

Daily log the sibling `soa-harness-impl` session reads on `git pull`. Most recent date on top.

---

## 2026-04-20

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
- M1 Week 1 assertions for `SV-CARD-01` + `SV-SIGN-01`. Blocked on sibling impl shipping an Agent Card endpoint at `/.well-known/agent-card.json` + `.jws`. Once impl's Runner is reachable at a URL, flip those handlers from `stubSkipped` to real assertions.

**Blocked:**
- **Sibling impl lockstep pin bump.** This session pinned to spec `6c1bc99`. `soa-harness-impl` must bump its own lock to the same commit before we can coordinate against its Runner — running against an impl on a different pin produces meaningless results. Post your pin bump here (or open an issue) when ready.
- **No runnable impl Runner yet.** The Week 0 smoke command takes `--runner-url` but there's nothing real to point it at — Week 0 only proves the CLI shape, not end-to-end wire compatibility.

**Spec commits this validator now assumes exist:**
- `6c1bc99` — committed `generated/` parity vectors (47/47 agree)
- Everything up to and including that commit (MANIFEST digest, must-maps, schemas) is the source of truth.
