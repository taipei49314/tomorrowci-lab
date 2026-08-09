# Claim-to-evidence matrix

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

Current source version `0.2.0-alpha.1` is an unreleased trust-core development
line. It does not supersede the bounded alpha.2 observations and is not a
release or external-qualification PASS. Its exact merged SHA and default CI
will be added only after the current changes pass review and merge.

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | REJECTED product candidate |
| `v0.1.0-grok-session` | REJECTED historical parallel candidate; annotated tag object `39011d3b`, peeled commit `7a08c488` |
| `v0.1.1-alpha.1` | REJECTED acceptance candidate / live-path demonstration |
| `v0.1.1-alpha.2` | Published measured lab prerelease — see bounded gates below |

## Alpha.2 identity layers

- Package/action candidate: `bced9c070bbb9a64c63301ec23b2610c2b79f011`,
  tested by public CI
  https://github.com/taipei49314/tomorrowci-lab/actions/runs/31080022232.
- Annotated tag object: `7fa0e274dc7e74c024da71fff022b18f0835aab8`.
- Tag peeled/source commit: `167b94f9ce5c0fe95b9105abb71d26386b4fe9e3`,
  built by release run
  https://github.com/taipei49314/tomorrowci-lab/actions/runs/31080456557.
- Current default truth commit: `1e23b40157e55e5763e3360b667d10a003b50ff9`,
  covered by default CI
  https://github.com/taipei49314/tomorrowci-lab/actions/runs/31299997719.

These values identify different layers and are not interchangeable. See the
full [qualification baseline](qualification/BASELINE.md) for the tag ledger
and release read-back.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| Default-branch truth | **PASS** | run 31299997719 at exact default SHA `1e23b401…` | green | README, audits, qualification baseline |
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
