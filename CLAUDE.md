# Claude Code Instructions — soa-validate (Go Conformance Harness)

## What this repo is

The official conformance validator for SOA-Harness v1.0. Single static Go binary that consumes `soa-validate-must-map.json` and `ui-validate-must-map.json` from the spec repo, runs tests against a live Runner or Gateway, and emits JUnit XML + `release-gate.json`.

Lives in a **separate repo from the reference implementation by design**. The spec, the impl, and the validator must be independently authored and reviewed to give the word "conformant" meaning. Same-author-all-three invalidates the whole chain.

Sibling repos:
- `../soa-harness=specification/` — spec + must-maps + test vectors (source of truth, pinned by SHA)
- `../soa-harness-impl/` — the TS reference implementation we validate against

## MCP servers available

### `graphify-spec` (user-level, already configured)
Query this for anything about:
- Must-map entries: which tests validate which `§N.M` MUST
- Test ID groupings (`SV-*`, `UV-*`, `HR-*`) by phase, severity, profile
- Spec section content when writing a test assertion
- Threat-model cross-references (useful for security-related test design)

Example queries during implementation:
- Writing a test for `SV-PERM-01`? → `get_node(id='test_sv_perm_01')` returns the node plus neighbors (the §10 sections it validates, related tests, rationale)
- Need to know every test covering §10.6 Handler Keys? → `get_neighbors(node='core_section_10_6')` filtered to `validated_by` edges
- Writing conformance output for a category? → `get_community` around a god-node like UI §21.2 Emission Triggers

### `CodeGraphContext` (per-project)
Once this Go code is indexed: function-call chains, unused exports, complexity analysis across the Go codebase.

## Code-generation guardrails

1. **Never generate expected values.** Expected values come from the pinned test vectors in the spec repo (`../soa-harness=specification/test-vectors/`). If you find yourself computing an expected digest, hash, or signature — stop. It belongs in the spec repo, not here. The validator's job is to *check*, not to *define*.

2. **Never modify `soa-validate-must-map.json` or `ui-validate-must-map.json` from this repo.** Those files are owned by the spec repo. If the must-map needs changing, that's a spec-repo PR. This repo only consumes them.

3. **Pinning protocol.** `soa-validate.lock` (in this repo) records the spec MANIFEST SHA we're validating against. When the spec updates, bumping this pin is a deliberate PR with a human approving the behavioral delta.

4. **JCS goes through `canonicaljson-go`** (the RFC-8785 library endorsed by the spec). Never hand-roll canonicalization in Go either — if this validator canonicalizes differently from the TS impl, every signed test vector will fail spuriously. Cross-language byte-equivalence is the single load-bearing invariant.

5. **Runner client respects mTLS + bearer.** The Runner-facing HTTP client in `internal/runner/` uses the spec's RFC 8693 token-exchange flow (§7.4) — tests run over real mTLS sessions, not mocked HTTP.

6. **JUnit XML output is the machine-readable contract.** CI systems consume it. Don't change the schema without bumping the validator's own semver.

## Milestone discipline

M1 scope for this repo: stub tests for the 8 M1 test IDs that impl M1 also ships. These are run in CI against a live `soa-harness-impl` Runner — that's the end-to-end gate. Ships same week as impl M1.

M2–M5: expand coverage toward the full 213-test must-map.

## Before opening a PR

- `go vet ./...` — clean
- `go test ./...` — green
- `go build ./cmd/soa-validate` — produces a runnable binary
- If touching the must-map loader in `internal/musmap/`, verify all fields from the current `soa-validate-must-map.json` round-trip correctly

## Parallel Claude Code sessions

You may be running alongside a sibling session in `../soa-harness-impl/` (and occasionally in `../soa-harness=specification/`). Each session has its own task list and memory — **nothing crosses session boundaries automatically**.

**This repo's whole point is to be the independent judge.** Cross-session coordination is necessary for scheduling, never for deciding what counts as "conformant." That decision always lives in the spec repo.

Coordination scenarios:
- **Impl changed its wire format** → they open an issue here, you update test expectations, merge in lockstep
- **You found a gap in must-map coverage** → open an issue on `soa-harness-specification`, not here
- **Spec pinned to a new MANIFEST digest** → validator and impl bump `soa-validate.lock` simultaneously

See `COORDINATION.md` for the full protocol.

**Never do** in this repo:
- Compute expected conformance values (spec test-vector tooling does this)
- Modify must-map files (spec repo owns them)
- Silently bump `soa-validate.lock` (impl session depends on lockstep)
- Test against a Runner pinned to a different spec commit than your lock

## Session startup context

On first session start in this repo, read in this order:
1. `CONTEXT.md` — condensed summary of where we are, what's been decided, what ships next
2. `~/.claude/plans/soa-validate-m1.md` — the M1 tactical plan
3. `~/.claude/plans/put-a-plan-together-glittery-hartmanis.md` — the full roadmap across all three repos
4. `soa-validate.lock` — which spec commit this validator targets

`graphify-spec` MCP is already registered and connected (user level). Use it for every spec question before grepping.
