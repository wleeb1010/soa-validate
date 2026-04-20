# Contributing to soa-validate

## Sign-off required

All commits MUST include a DCO sign-off:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s`. CI rejects unsigned commits.

## High-sensitivity paths (two reviewers required)

PRs touching these paths require approval from **two** reviewers listed in `CODEOWNERS`:

- `internal/jcs/` — Go canonicalization wrapper (RFC 8785 via `canonicaljson-go`)
- `internal/testrunner/` — per-test execution logic (defines what "passing" means)
- `internal/musmap/` — must-map loader (defines what tests even exist)
- `soa-validate.lock` — spec pin file (every bump needs informed approval)

Tag such PRs `[VALIDATOR-CORE]` so reviewers prioritize.

## Standard PRs

One reviewer + green CI:

- `go vet ./...` — clean
- `go test ./...` — green
- `go build ./cmd/soa-validate` — produces a runnable binary on Linux, macOS, Windows

## What NOT to do

- **Never modify must-map files from this repo.** `soa-validate-must-map.json` and `ui-validate-must-map.json` are owned by `soa-harness-specification`. A missing or incorrect must-map entry is a spec bug, not a validator bug.
- **Never generate expected test values.** The validator's job is to *check*, not to *compute*. If you find yourself writing code that generates an expected digest or signature, you're writing something that belongs in the spec repo's test-vector tooling, not here.
- **Never hand-roll canonicalization.** Use `canonicaljson-go`. The whole cross-language byte-equivalence property depends on both implementations using spec-endorsed libraries.
- **Never silently bump `soa-validate.lock`.** Every pin bump is a deliberate review-point — the behavioral delta between the old and new spec commits must be summarized in the PR description.

## Release cadence

This validator follows its own semver, independent of the spec and the reference implementation. A validator minor bump does NOT imply a spec change; it implies the validator's coverage, reporting, or flags have changed. A validator major bump implies backwards-incompatible CLI or output-format changes.

## Bug reports

GitHub Issues on this repo. If a test in the validator disagrees with your implementation:
1. First check whether your implementation is actually correct per the spec (`graphify-spec` MCP is your friend here)
2. If the implementation is correct and the validator is wrong, file an issue with a minimal repro
3. If the spec itself is ambiguous, that's an issue for `soa-harness-specification`, not this repo

## Security reports

GitHub Security Advisories on this repo (private). Acknowledgment within 72 hours.

## License and IPR

Apache 2.0, same as Apache-licensed sibling repos. DCO sign-off is your contribution attestation.
