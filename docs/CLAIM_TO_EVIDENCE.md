# Claim-to-evidence matrix (repair track)

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

Historical tag `v0.1.0` is **rejected** — see [audits/v0.1.0-rejection.md](audits/v0.1.0-rejection.md).  
Repair commit proven on public CI: `808e6cee6368b7732e9811a280cc3ad81f569df5`  
Actions run: https://github.com/taipei49314/tomorrowci-lab/actions/runs/31076845770

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| fmt + clippy + workspace tests (public CI) | **PASS** | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` on run 31076845770 | exit 0 | Actions `rust` job |
| Release CLI build (public CI) | **PASS** | `cargo build -p tomorrowci-cli --release` | exit 0 | Actions `rust` / `live-python` |
| Scripted runner horizon classification | **PASS** (narrow) | `cargo test -p tomorrowci-runner --test m1_m2_pipeline` | planner/verdict only | test log |
| Python **live** Docker adapter (baseline + later fail) | **PASS** | `tomorrowci scan fixtures/python-runtime-break --config fixtures/python-runtime-break/.tomorrowci.yml` on GHA | baseline PASS; py310+ FAIL; horizon 3.10 | run `77f7f5ea7b80` |
| Digest-pinned image resolution | **PASS** | same live scan | digests on every scenario | `environment.json` |
| Fetch state preserved (venv on mount) | **PASS** | live scan fetch+test phases | baseline tests pass after pip | fetch/test evidence |
| Exact digest-pinned replay ×2 | **PASS** | `tomorrowci replay 77f7f5ea7b80 --scenario py310-locked` ×2 | both `replay: PASS`; same signature hash | Actions live-python; `replay-result.json` |
| HTML report from **live** run | **PASS** | generated with live scan | no scripted digest | `report.html` in evidence |
| XSS log escaping helpers | **PASS** (narrow) | `node --test packages/report-ui/test/*.test.js` + report crate tests | pass | CI |
| Action dogfood (`uses: ./action`) | **PASS** | workflow job `action-dogfood` | success | Actions |
| Action from consumer repository | **PASS** | workflow job `action-consumer` | success | Actions |
| Evidence artifact uploaded | **PASS** | artifact `tomorrowci-live-python-evidence` | zip SHA256 `dc62442d...` | Actions |
| Job summary present | **PASS** | Action appends `job-summary.md` | present | Actions summary |
| Node live adapter | **NOT_RUN** | — | out of repair scope | — |
| Rust live adapter | **NOT_RUN** | — | out of repair scope | — |
| Dependency-axis forecasting | **NOT_RUN** | incomplete fixtures | not acceptance | — |
| Real ddmin execution | **NOT_RUN** | label summary only | not acceptance | — |
| React/TypeScript interactive report | **NOT_RUN** | zero React app | later milestone | — |
| Remote GitHub URL scan | **NOT_RUN** | CLI rejects http(s) | honest | CLI |
| Container image publish | **NOT_RUN** | not built | — | — |
| Full multi-OS release + real SBOM | **NOT_RUN** | alpha does not claim complete M5 | — | — |
| Demo report via gen-demo | **NOT_RUN** (not acceptance) | scripted digests | example only | `examples/` |

## Live run identity

| Field | Value |
|-------|--------|
| Run id | `77f7f5ea7b80` |
| Commit | `808e6cee6368b7732e9811a280cc3ad81f569df5` |
| Baseline image | `python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b` |
| First fail | `py310-locked` / `python@sha256:34a2c9467a0231d8c29a5ecadc219733a9393b026882b44d91616b9dae6088b6` |
| Failure signature | `sha256:497fdbfe256b888b5434e458a115da03209e70bdd8bf250fecd76704e67a5ac9` |
