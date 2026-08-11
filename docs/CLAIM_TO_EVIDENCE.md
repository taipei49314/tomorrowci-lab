# Claim-to-evidence matrix

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

Current source version `0.2.0-alpha.1` is an unreleased trust-core development
line. It does not supersede the bounded alpha.2 observations and is not a
release or external-qualification PASS. The bounded M2 implementation is tied
to exact master `456a36edb1e8547612cd13ee7a30be3479d33bab` and successful
CI run [31316809823](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823).

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
- Historical alpha.2 truth-reconciliation commit: `1e23b40157e55e5763e3360b667d10a003b50ff9`,
  covered by default CI
  https://github.com/taipei49314/tomorrowci-lab/actions/runs/31299997719.

These values identify different layers and are not interchangeable. See the
full [qualification baseline](qualification/BASELINE.md) for the tag ledger
and release read-back.

## Historical alpha.2 bounded gates

This table preserves the alpha.2 observation. Its `NOT_RUN` rows describe that
historical release and are not rewritten by later M2 source qualification.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| Historical default-branch truth snapshot | **PASS** | run 31299997719 at exact default SHA `1e23b401…` | green | README, audits, qualification baseline |
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

## M2 exact-master bounded gates

The current M2 PASS is limited to Linux Docker and the checked-in dependency
fixtures. Node/Rust M3 runtime qualification, Podman, the platform matrix, and
external adoption remain separate gates.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| M2 implementation baseline | **PASS** | master `456a36edb1e8547612cd13ee7a30be3479d33bab`; CI [31316809823](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823) | workflow success | source + Actions |
| Native content-addressed dependency probes | **PASS** | `m2-dependency-fixtures` job [93253469760](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823/job/93253469760) | pip/npm/cargo baseline, full candidate, minimal subset, and subtraction observations matched | `tomorrowci-m2-dependency-evidence` |
| Python dependency/ddmin | **PASS** | run `04054e94457a`; `verify`; `replay ... --scenario ddmin-breaking-api` x2 | observed minimal dependency change; current-v2 verify PASS, 140 files; both replays PASS | artifact 9039044133 |
| Node dependency/ddmin | **PASS** | run `c8781bdadb33`; `verify`; minimal replay x2 | observed minimal dependency change; current-v2 verify PASS, 140 files; both replays PASS | artifact 9039044133 |
| Rust dependency/ddmin | **PASS** | run `45c8b2fa6b57`; `verify`; minimal replay x2 | observed minimal dependency change; current-v2 verify PASS, 140 files; both replays PASS | artifact 9039044133 |
| Downloaded artifact read-back | **PASS** | `gh run download 31316809823` followed by current CLI verification of all three run IDs | all three bundles verify PASS; all nine scan/replay logs contain the expected run ID or replay PASS | artifact digest `sha256:402c5085be7890fa57b930f6ea9744b28d5e351b78ef0e78857ad365ac0fd2f3`; expires 2026-11-07 |
| M3 Node/Rust runtime within this M2 gate | **NOT_RUN** | outside this fixture-bounded M2 gate; separately qualified below on a later exact master | — | — |
| React / remote scan / container image publish | **NOT_RUN** | outside M2 scope | — | — |
| Independent external adopter or auditor | **BLOCKED** | repository-owned CI and operator read-back are not external evidence | external action required | — |

Full details and retention limits: [qualification/M2.md](qualification/M2.md).

## M3 exact-master bounded Linux Docker gates

The M3 PASS below is limited to the checked-in Node and Rust runtime fixtures
on Linux Docker. Podman and the wider platform matrix remain separate required
gates.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| M3 implementation baseline | **PASS** | master `a6af3076ed3286d42c5ed7a386cb6812d8b76c50`; CI [31447884019](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019) | 8/8 jobs success | source + Actions |
| Node runtime frontier | **PASS** | `live-node` job [93646194481](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019/job/93646194481); run `5c02e51bf30d`; `verify`; replay `node22-locked` x2 | Node 20 baseline PASS; Node 22/24 stable `RemovedRuntimeApi`; current-v2 107 files; both replays PASS | artifact 9085285817; digest `sha256:50737a0bd8c946f9fc156e7ce52e616739c378be4f199400888af5245e96c9d0` |
| Rust runtime/MSRV frontier | **PASS** | `live-rust` job [93646194483](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019/job/93646194483); run `10af99ea763c`; `verify`; replay `rust-174` x2 | Rust 1.83 baseline PASS; Rust 1.74 stable `MsrvError`; current-v2 76 files; both replays PASS | artifact 9085282933; digest `sha256:23a4b39c69386194adc1d6c649e482f9b5b7409a09cbca4405f2cce18910e648` |
| Fail-closed negative controls | **PASS** | `m3-negative-controls` job [93646499409](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019/job/93646499409); runs `331ffe2feac9`, `440458125b4f`, `6d18736f4e9b` | `BASELINE_INVALID`, `FLAKY`, and `BLOCKED`; no horizon; all current-v2 verify PASS | artifact 9085315934; digest `sha256:b21ed54a07e6b0031f3b01b2c35a68a1fb587691238238ed7f2f656c71c0487a` |
| Downloaded artifact read-back | **PASS** | download all three M3 artifacts; compare API/archive digests; exact-SHA CLI verification and semantic helper | five bundles verify PASS; four replay logs PASS; source SHA and dirty state match | artifacts expire 2026-11-09T00:59:41Z |
| Podman + Windows/macOS platform matrix | **NOT_RUN** | outside this Linux Docker gate | — | — |
| Independent external adopter or auditor | **BLOCKED** | repository-owned CI and operator read-back are not external evidence | external action required | — |

Full details and retention limits: [qualification/M3.md](qualification/M3.md).
