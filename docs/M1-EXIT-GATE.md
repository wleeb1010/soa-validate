# M1 Exit Gate

V-13: single CLI invocation that runs the full Week 3 conformance suite against a live SOA-Harness Runner and emits the canonical artifacts (`release-gate.json` + JUnit XML) that downstream consumers gate on.

## Command

```bash
SOA_IMPL_URL=http://127.0.0.1:7700 \
SOA_RUNNER_BOOTSTRAP_BEARER=<your-bearer> \
SOA_IMPL_BIN="node /abs/path/to/start-runner.js" \
SOA_DRIVE_AUDIT_RECORDS=20 \
soa-validate \
  --profile=core \
  --spec-vectors=/abs/path/to/soa-harness=specification \
  --out=release-gate.json
```

Exits non-zero if any test fails or errors. JUnit XML written alongside as `release-gate.junit.xml`.

## Required environment

| Var | Why |
|---|---|
| `SOA_IMPL_URL` | Live Runner base URL (HTTPS recommended; HTTP loopback for local dev) |
| `SOA_RUNNER_BOOTSTRAP_BEARER` | Same value the Runner was started with — required for POST /sessions / GET /audit/* paths |

## Optional environment

| Var | Default | Why |
|---|---|---|
| `SOA_IMPL_BIN` | unset → V-09/V-12 subprocess tests skip | Full impl spawn command for HR-12 (tampered-card refusal) and SV-BOOT-01 negative arms (broken-trust fixtures). Path can be MSYS-style (`/c/Users/…`) on Windows; auto-translated to native form. |
| `SOA_IMPL_TEST_PORT` | `7701` | Port the V-09/V-12 subprocess binds (must differ from `SOA_IMPL_URL`'s port). SV-SESS-BOOT-02 path-a uses this port + 1. |
| `SOA_DRIVE_AUDIT_RECORDS` | `0` | If >0, V-07 driver POSTs N `/permissions/decisions` calls to seed the audit chain before tests run. Required ≥3 for HR-14 chain-tamper to pass with mid-chain index. |
| `SOA_DRIVE_AUDIT_TOOLS` | `fs__read_file` | Comma-separated tool names the V-07 driver cycles through. Tolerates 503 pda-verify-unavailable on Prompt-resolving tools (skips, continues). |
| `SOA_DRIVE_PACE_MS` | `2500` | Inter-request pace for the V-07 driver. Default is set to stay under impl's 30 rpm per-bearer rate limit. |
| `SOA_IMPL_DEMO_SESSION` | unset | Legacy pre-T-03 fallback `<sid>:<bearer>`. Bootstrap-mint via `SOA_RUNNER_BOOTSTRAP_BEARER` is preferred; demo-session is now optional. |
| `SOA_VALIDATE_DEBUG_DIR` | unset | When set, V-12 negative-arm subprocess stderrs are dumped to this directory for diagnosis. |

## Outputs

- `release-gate.json` — machine-readable scoreboard. Fields: `tool`, `version`, `profile`, `impl_url`, `live_path_enabled`, totals (`total`, `passed`, `failed`, `skipped`, `errored`), and `results[]` each with `id`, `name`, `status`, per-path `evidence[]`, `seconds`.
- `release-gate.junit.xml` — JUnit XML for CI consumption. Each test case carries `<properties>` with one entry per evidence path (`vector`, `live`) so CI dashboards can distinguish passed-on-vector from passed-on-live from skipped-with-diagnostic.

## Current scoreboard target (Week 3 close)

| Test | live |
|---|---|
| SV-CARD-01, SV-SIGN-01, SV-BOOT-01, SV-PERM-01, HR-01-vector, HR-12, HR-14, SV-AUDIT-TAIL-01, SV-AUDIT-RECORDS-01, SV-AUDIT-RECORDS-02, SV-SESS-BOOT-01, SV-SESS-BOOT-02, SV-PERM-20, SV-PERM-22 | pass |
| HR-02 | M3-deferred (must-map `implementation_milestone`) |
| SV-PERM-21 | skip (PDA signing fixture / L-24 candidate) |

**14 pass / 2 skip / 0 fail.**

## Platform coverage

- Unit-test CI: `.github/workflows/ci.yml` (Linux/macOS/Windows × Go 1.22) — runs on every push + PR.
- End-to-end CI: `.github/workflows/live-e2e.yml` (same matrix; spawns impl, runs the exit-gate command, uploads artifacts) — currently `workflow_dispatch` only; flips to push/PR triggers when impl's Week 5b CI matrix lands and the lockstep gate stabilizes.
