# soa-validate

Conformance validator for **[SOA-Harness v1.0](https://github.com/wleeb1010/soa-harness-specification)**. Single static Go binary that verifies a Runner or Gateway implementation against the spec's must-map and emits machine-readable conformance reports.

## Why a separate repo

This validator is authored and maintained separately from the reference implementation (`soa-harness-impl`) and the spec (`soa-harness-specification`). Same-author-all-three invalidates the word "conformant" — the whole point of a validator is to be an independent judge.

Adopters running `soa-validate` against their own Runner get a meaningful signal precisely because this binary did not grow up alongside the thing it's checking.

## What it does

Consumes two must-maps from the pinned spec commit:
- `soa-validate-must-map.json` — 234 Core / Core+SI / Core+Handoff tests
- `ui-validate-must-map.json` — 186 UI Gateway profile tests

Runs each applicable test against a live Runner or Gateway (mTLS + bearer token). Emits:
- JUnit XML for CI consumption
- `release-gate.json` per spec §19.1.1
- Per-test rationale referencing the spec `§N.M` anchors

## Usage

```sh
go install github.com/wleeb1010/soa-validate/cmd/soa-validate@v1.0.0

soa-validate \
  --profile core \
  --runner-url https://runner.example.com:7700 \
  --spec-vectors /path/to/soa-harness-specification/test-vectors \
  --out release-gate.json
```

Exit code `0` means all required tests passed; non-zero enumerates failures in `report.json`.

## Spec pinning

`soa-validate.lock` in this repo records the SHA-256 of the spec's `MANIFEST.json` that this validator is calibrated against. Bumping the pin is a deliberate PR with human review — never silent.

## Conformance labels

This repo defines two tiers:

- **SOA-Harness v1.0 Reference Implementation** — an implementation self-asserts this when it passes the full 234-test suite against a specific pinned spec commit.
- **SOA-Harness v1.0 Bake-Off Verified** — requires `soa-validate` output from a second-party implementation to converge (zero divergence) with a reference run. Only this tier is meaningful for downstream adopters.

Until a second-party implementation exists and passes bake-off, no "Bake-Off Verified" labels are published.

## Sibling repos

- **[soa-harness-specification](https://github.com/wleeb1010/soa-harness-specification)** — the source of truth for must-maps, test vectors, schemas
- **[soa-harness-impl](https://github.com/wleeb1010/soa-harness-impl)** — the reference implementation this validator will first be pointed at

## License

Apache 2.0. See `LICENSE`.

## Contributing

See `CONTRIBUTING.md`. This validator's test-expectation logic is a high-sensitivity area — PRs touching `internal/testrunner/` or `internal/jcs/` require two reviewers.
