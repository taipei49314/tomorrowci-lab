# Claim-to-evidence matrix (repair track)

Statuses used here: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

This matrix supersedes the v0.1.0 “everything PASS” ledger.  
Historical tag `v0.1.0` is **rejected** — see [audits/v0.1.0-rejection.md](audits/v0.1.0-rejection.md).

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| Rust source compiles on public CI (fmt/clippy/test) | **NOT_RUN** until green CI on repair commit | `.github/workflows/ci.yml` | pending | Actions run |
| Local workspace unit tests (scripted semantics) | **PASS** (narrow) | `cargo test --workspace` | exit 0 for classifier/sandbox unit tests | local / CI log |
| Scripted runner horizon classification | **PASS** (narrow) | `cargo test -p tomorrowci-runner --test m1_m2_pipeline` | proves plan/verdict only | test log |
| Python **live** Docker adapter (baseline + later fail) | **BLOCKED** / **NOT_RUN** until Docker run on exact commit | `tomorrowci scan fixtures/python-runtime-break --config fixtures/python-runtime-break/.tomorrowci.yml` | requires daemon | `.tomorrowci/runs/*/run.json` |
| Node live adapter | **NOT_RUN** | — | out of repair scope | — |
| Rust live adapter | **NOT_RUN** | — | out of repair scope | — |
| Dependency-axis forecasting | **NOT_RUN** | fixtures simulated / incomplete | not acceptance | — |
| Real ddmin execution | **NOT_RUN** | reduction labels only at v0.1.0 | not acceptance | — |
| Exact digest-pinned replay | **NOT_RUN** until live path + dual replay | `tomorrowci replay <run-id> --scenario <id>` ×2 | signature equality | scenario `replay.json` |
| HTML report from **live** run | **NOT_RUN** | prior demo is scripted | no acceptance | — |
| Demo report (`examples/reports/...`) | **NOT_RUN** (not acceptance evidence) | `cargo run -p tomorrowci-gen-demo` | scripted digests | example only |
| XSS log escaping helpers | **PASS** (narrow) | `node --test packages/report-ui/test/*.test.js` + report crate tests | pass | test log |
| React/TypeScript interactive report | **NOT_RUN** | zero `.tsx` / React app | later milestone | — |
| Checked-in Action file exists | presence only — not completion | `action/action.yml` | file present | action/ |
| Action dogfood (`uses: ./action`) | **FAIL** until public run invokes Action | CI must contain `uses: ./action` | pending | workflow |
| Action works from consumer repo | **NOT_RUN** until consumer CI job | separate checkout | pending | workflow |
| Remote GitHub URL scan | **NOT_RUN** | CLI rejects http(s) | honest | CLI |
| Container image publish | **NOT_RUN** | release does not build image | — | — |
| Full multi-OS release + real SBOM | **NOT_RUN** for alpha gate beyond verified artifacts | — | empty SBOM at v0.1.0 | — |
| Public CI green on candidate commit | **FAIL** / **NOT_RUN** | was red on `7a08c48` | repair required | Actions |

## Scripted vs live (hard rule)

- **ScriptedExecutor** tests may **PASS** only for planner/classifier/orchestration semantics.
- They **must not** satisfy any live adapter, report acceptance, replay acceptance, Action, or fixture acceptance claim.
- `sha256:scripted-test-digest` in any demo is **not** production evidence.

## Definition of Done

Unchanged from the original mission: no PASS without execution on the exact commit; public CI green; live Python path with digest, fetch state, evidence, replay; Action dogfood. See repair mission Phase G checklist.
