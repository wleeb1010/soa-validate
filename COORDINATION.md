# Coordination — soa-validate ↔ soa-harness-impl ↔ soa-harness-specification

## The three-repo model

```
soa-harness-specification  (normative spec, source of truth)
        │ pinned-by ↓         ↓ pinned-by
soa-harness-impl (reference impl)    soa-validate (this — Go conformance harness)
```

This validator is deliberately separate from the implementation. Same-author-all-three invalidates the word "conformant" — the validator must be authored and reviewed independently to mean anything.

## Parallel Claude Code sessions

Three concurrent sessions are supported (one per repo). They don't share task lists, memory, or working state. What they do share:

| Resource | Scope | Notes |
|---|---|---|
| `graphify-spec` MCP | User-level | Registered in `~/.claude.json`, spawned per session, reads spec `graphify-out/graph.json` as a static file. Nothing "runs" in the spec repo |
| `CodeGraphContext` MCP | Per-project | Each repo has its own Go code graph (once indexed) |
| `~/.claude/plans/` | User-level | Plan files visible to all sessions |
| `soa-validate.lock` | Per-repo | Pins this repo to a specific spec commit |

## Your job vs the impl's job

| Concern | Owned by |
|---|---|
| What "conformant" means (test IDs, expected vectors) | Spec repo |
| Computing expected digests, signatures, canonical bytes | **Spec repo test-vector tooling** (NOT this validator, NOT impl) |
| Implementing the Runner API | `soa-harness-impl` |
| Running tests against a live Runner and reporting pass/fail | **This repo** |
| Generating JUnit XML + `release-gate.json` | This repo |

If you find yourself COMPUTING an expected value in this repo, stop. Either (a) the test vector already exists in the spec repo and you should consume it, or (b) it belongs in the spec repo's test-vector tooling and you should open a spec-repo PR.

## Change-propagation protocol

### You found a validator bug (tests were wrong, harness crashes)
Standard PR flow. No sibling coordination needed unless the bug masked a real impl bug — in which case, file an issue on `soa-harness-impl` with the repro.

### Your tests pass but a must-map entry is missing
**Spec repo issue.** Do not add the test-ID entry from this repo. Open an issue on `soa-harness-specification` describing the normative gap. Spec authors the must-map update. You bump `soa-validate.lock` in this repo after the spec PR merges.

### You need to update test expectations because the impl changed its wire format
This is an impl-driven contract change. The impl session opens a GitHub issue here announcing it. You review the change, update your test expectations, coordinate merge timing — validator and impl should never ship against mismatched spec commits.

### The spec changed test vectors or schemas
Impl session will typically notice first and bump their `soa-validate.lock`. You receive a signal (GitHub issue comment or `STATUS.md`), verify your test expectations still align with the new spec commit, and bump your lock in lockstep.

## MCP model (tl;dr)

- `graphify-spec` MCP is stdio, not a daemon
- Each session spawns its own local Python subprocess reading spec's `graph.json` from disk
- Spec repo has a git hook that refreshes `graph.json` on every commit
- Your next query sees the fresh graph — no restart, no network, no coordination
- Nothing needs to be "running" in the spec repo

## Running multiple sessions

```powershell
# Terminal 1 — this repo, writing Go conformance tests
cd C:\Users\wbrumbalow\Documents\Projects\soa-validate
claude

# Terminal 2 — sibling impl session
cd C:\Users\wbrumbalow\Documents\Projects\soa-harness-impl
claude

# Terminal 3 (only when spec needs editing)
cd "C:\Users\wbrumbalow\Documents\Projects\soa-harness=specification"
claude
```

All concurrent, all independent.

## Signaling

1. **GitHub issues/PRs** for contract changes, test-ID disputes, pin-bump coordination
2. **`STATUS.md` at repo root** for cheap "working on X right now" scratchpad signals (commit + push, sibling sees on `git pull`)

## Anti-patterns

- ❌ Computing expected conformance values in this repo (those belong in spec repo test vectors)
- ❌ Editing spec files from this session
- ❌ Bumping `soa-validate.lock` without coordinating with the impl session
- ❌ Testing against a Runner pinned to a different spec commit than this validator's lock
- ❌ Parallel sessions on the same repo (not supported)
