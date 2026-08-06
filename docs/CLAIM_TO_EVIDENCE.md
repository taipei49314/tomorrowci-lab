# Claim-to-evidence matrix (v0.1.1-alpha.2)

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | REJECTED product candidate |
| `v0.1.1-alpha.1` | REJECTED acceptance candidate / live-path demonstration |
| `v0.1.1-alpha.2` | Closure candidate — see gates below |

**Exact commit:** `bced9c0` (package `0.1.1-alpha.2`)  
**Public CI:** https://github.com/taipei49314/tomorrowci-lab/actions/runs/31080022232  
**Default branch:** `master` carries truthful README + audits.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| Default-branch truth | **PASS** | `master` merge of alpha2 docs | green | README, audits |
| encoding / fmt / clippy / tests | **PASS** | CI rust job 31080022232 | exit 0 | Actions |
| version identity `0.1.1-alpha.2` | **PASS** | `tomorrowci --version` | matches | CI |
| Live Python Docker scan | **PASS** | live-python job | horizon 3.10 | evidence artifact |
| `tomorrowci verify` | **PASS** | live + Action | verify: PASS | run checksums |
| Replay ×2 independent attempts | **PASS** | live-python replay step | both PASS | `replays/attempt-{1,2}/` |
| Action dogfood `uses: ./action` | **PASS** | action-dogfood | success | Actions |
| Consumer git repository Action | **PASS** | action-consumer (`git init` + commit) | success | Actions |
| bash -n release-dry-run.sh | **PASS** | rust job | exit 0 | CI |
| Node / Rust live | **NOT_RUN** | out of scope | — | — |
| Dependency / ddmin / React / remote / image | **NOT_RUN** | out of scope | — | — |
