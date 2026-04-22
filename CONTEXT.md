# Context — soa-validate

> **Read this file before doing anything in a fresh Claude Code session.** It captures what a previous session (and the spec authors) already decided, so you don't re-derive it.

## CodeGraphContext (CGC)

CGC MCP is wired at user level (`~/.claude.json`) against Neo4j at `bolt://localhost:7687`. This repo is indexed alongside `soa-harness-impl` and shares the same graph; query spans both. When exploring code relationships, prefer CGC queries (`cgc find`, `cgc analyze`, `cgc query` Cypher) over grep.

- **Re-index this repo:** `cgc index --force .` (takes ~10s).
- **Post-commit refresh:** `.git/hooks/post-commit` runs `cgc index --force` in the background after every commit. Needs `PYTHONIOENCODING=utf-8` on Windows to avoid a cgc CLI emoji-encoding crash (the indexing succeeds either way, but the traceback is noisy). Hooks aren't versioned — if you re-clone, recreate the hook from the template in `docs/cgc-post-commit.sh` (or just run `cgc index .` on demand).
- **Sanity query:** `cgc find name BudgetTracker` locates the class in `soa-harness-impl/packages/runner/src/budget/tracker.ts`; a Cypher query on `(src)-[:IMPORTS]->(:Module {name contains 'budget/index'})` lists its 11 consumers (5 runner/src + 6 runner/test files).

## Where we are

**Date:** 2026-04-20
**Status:** Pre-M1 scaffold. No functional Go code. Repo has: Apache 2.0 LICENSE, README, CLAUDE.md, CONTRIBUTING.md, CODEOWNERS, COORDINATION.md, soa-validate.lock, .gitignore (Go).

**Siblings:**
- `../soa-harness=specification/` — normative spec (the source of truth for everything this validator checks)
- `../soa-harness-impl/` — TypeScript reference implementation this validator tests against

## What this repo exists to do

Run the 213 tests in `soa-validate-must-map.json` against a live Runner or Gateway. Emit JUnit XML + `release-gate.json`. Be an **independent judge** — which means:

- This repo is deliberately separate from `soa-harness-impl` (same author, separate repo; future goal: separate author entirely)
- Never compute expected conformance values here — consume them from spec test vectors
- Never modify must-map files — those belong to the spec repo
- Pin-bumping `soa-validate.lock` is a reviewable PR, never silent

## What was decided (and why)

### 1. Go, not TS
- Single static binary drops into any CI (`curl -L ... && ./soa-validate`)
- Spec endorses `gowebpki/jcs` for JCS
- Forces cross-language byte-equivalence testing — if Go validator and TS impl agree on a JCS output, that's real interop evidence

### 2. Separate repo from reference impl
- "Same author both sides" invalidates conformance claims
- Pinning protocol (`soa-validate.lock`) enforces spec-first, lockstep bumps
- Goal: eventually, second-party or independent maintainer

### 3. M1 scope: 8 test IDs, same as impl
Literal M1 list:
```
{HR-01, HR-02, HR-12, HR-14, SV-SIGN-01, SV-CARD-01, SV-BOOT-01, SV-PERM-01}
```
This validator ships a stub that runs exactly these 8. Bigger coverage lands in M2+.

### 4. JCS cross-language byte-equivalence is load-bearing
- Week 0 parity harness lives in `soa-harness-impl/packages/core/test/parity/`
- Vectors live in spec repo at `test-vectors/jcs-parity/`
- Go side uses `gowebpki/jcs`; TS side uses `canonicalize`
- If they disagree, every signed artifact fails cross-verification — **blocks M1 until resolved**

### 5. Milestone alignment with sibling impl
| M# | Duration | Scope |
|---|---|---|
| Week 0 | 1w | Go module scaffold, must-map loader, spec pin verification |
| M1 | 6w | Stub tests for 8 M1 test IDs; CI runs against live `soa-harness-impl` Runner |
| M2 | +2w | Add HR-04, HR-05, SV-SESS-01 (crash-recovery tests against impl's new persistence layer) |
| M3 | +4w | Grow to ~120/150 Core tests; JUnit XML + release-gate.json per spec §19.1.1 |
| M4 | +3w | Support Gateway validation path; participate in adopter onboarding gate |
| M5 | +6w | Full 213-test coverage; participate in cross-impl bake-off |

### 6. Conformance label strategy
Two tiers defined in spec `GOVERNANCE.md`:
- **"Reference Implementation"** — self-assigned after 213-test pass
- **"Bake-Off Verified"** — requires second-party impl convergence (zero divergence)

This validator's output IS the evidence for either claim.

## Technical decisions already made

| Decision | Choice | Why |
|---|---|---|
| Language | Go 1.22+ | Single static binary, spec-endorsed `gowebpki/jcs` |
| JCS | `github.com/gibson042/gowebpki/jcs` | Spec-named in `docs/deployment-environment.md` |
| JWS | `github.com/go-jose/go-jose/v3` | Active, passes all RFC 7515 compliance tests |
| HTTP client | stdlib `net/http` + custom mTLS config | No framework needed for a test client |
| JUnit XML | `github.com/jstemmer/go-junit-report` or similar | Standard CI consumption format |
| Must-map loader | stdlib `encoding/json` with struct mapping | Must-map JSON is simple; no need for schema generator |

## What this repo does NOT do

- ❌ Does not define conformance — the spec does that
- ❌ Does not implement any agent runtime — `soa-harness-impl` does that
- ❌ Does not compute expected test values — spec test-vector tooling does that
- ❌ Does not author must-map entries — spec repo owns them
- ❌ Does not include UI — it's a CLI / CI tool

## What graphify-spec MCP gives you (at query time)

- Every test ID in the must-maps is a node with `validated_by` edges pointing at the spec §s it covers
- Rationale and threat-model context for each test ID
- Community structure showing which tests cluster around which primitives (Agent Card tests vs PDA tests vs audit tests)
- Pre-built answers to "what does test SV-PERM-01 actually check?" — one query

Use this instead of reading the full must-map JSON every time.

## If you're starting fresh in this repo

1. Verify `claude mcp list` shows `graphify-spec` connected (user-level; always available)
2. Read `CLAUDE.md` for routing instructions
3. Read `~/.claude/plans/soa-validate-m1.md` for the tactical plan
4. Read `COORDINATION.md` for cross-session protocol
5. Check `soa-validate.lock` — this pins the spec commit you validate against
6. Start Week 0 work: `go mod init`, stub must-map loader, verify pin against spec repo on disk
