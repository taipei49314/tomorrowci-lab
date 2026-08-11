# Current qualification status

Recorded on 2026-08-11. This is the canonical run-bound status record for the
unreleased `0.2.0-alpha.1` line. Workflow or verifier implementation is not a
qualification result: a later execution changes a row only when its exact
source, run, artifacts, and repository-outside operator read-back are committed
here and in `backlog.json`.

## Accepted bounded observations

| Scope | Status | Exact evidence | Boundary |
|---|---|---|---|
| M2 dependency/ddmin Linux Docker | **PASS** | master `456a36edb1e8547612cd13ee7a30be3479d33bab`; [run 31316809823](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823); artifact `9039044133`, digest `sha256:402c5085be7890fa57b930f6ea9744b28d5e351b78ef0e78857ad365ac0fd2f3`; downloaded current-v2 verify/replay read-back | Checked-in pip/npm/cargo fixtures on Linux Docker only; not ecosystem-wide or external qualification |
| M3 Node/Rust Linux Docker | **PASS** | master `a6af3076ed3286d42c5ed7a386cb6812d8b76c50`; [run 31447884019](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019); artifacts `9085285817`, `9085282933`, `9085315934`; downloaded current-v2 verify/replay read-back | Repository fixtures on Linux Docker only; no Podman or platform claim |
| M4 interactive report engineering | **PASS** | [PR #5](https://github.com/taipei49314/tomorrowci-lab/pull/5), head `7c2534c7ec7a18bb18dc31a0864f7af5ae0807be`, merge `f6efabff0214ef02d2287ccb870a4e2a75c8e2f0`; exact-master [run 31451349743](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31451349743), `report-ui` job `93656185178` | Generated assets, types, unit behavior, Chromium accessibility/responsive/XSS/no-JS, and Rust renderer; bounded CI engineering slice |
| M4 exact-commit remote engineering | **PASS** | Same PR/merge/default CI; fail-closed exact-commit materializer, current-v2 remote identity, and offline full-writer/replay regression | Engineering contract only; the later live public-target result is recorded separately below |
| Deterministic release candidate | **PASS** | source `8ab64498add92360b92034333f056dc202396d24`; [run 31479363341](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31479363341) attempt 1, 16/16 jobs success; artifact `9096821821`, digest `sha256:be8c08aad565fe7a24d049f8fe8ce8d43ca2478b52554107b68e04667d17f5d6`, size `90570524`, expires `2026-11-09T09:48:27Z` | Candidate construction and operator read-back only; not release or platform support |
| Preregistered public exact-SHA targets on hosted Linux Docker/Podman | **PASS** | source `8ab64498add92360b92034333f056dc202396d24`; [run 31480491950](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31480491950) attempt 1; all six Python/Node/Rust × Docker/Podman jobs, observation read-back, and authoritative read-back succeeded; summary artifact `9097092837`, digest `sha256:155a68da092b97467b74185e0233cc727901ac51d58e180bbcd31ecd4030324e` | Exact three targets and hosted engine pair only; status `OBSERVED_PROJECT_OWNED_ONLY`, not ecosystem/platform support or independent authorization |

The downloaded candidate archive digest matched the Actions API. Exact-source
verification accepted `candidate-manifest.json` digest
`sha256:ebc29db4f02a646a50e1ed73be197bb48a997de105e717595178160b35c7fdb6`,
OCI archive digest
`sha256:609368b4b88304bcb69e08958ec9bb96cd286503f2822c0e5b22eb8a5149dbe5`,
detached provenance digest
`sha256:96554e8975935aef1a4ce07faca599b557598177ad100396e3562ebe6bca8b21`,
and OCI manifest digest
`sha256:f9243f15c06ae48a2a03f868f7444789d92b058807aac03eba3dab0fc51e8f04`.
All four archive hashes matched the frozen manifest; the extracted Windows CLI
passed version/trust and fail-closed BLOCKED-evidence verification, while the
Ubuntu candidate job passed OCI load, non-root identity, labels, trust,
socket-doctor readiness, SBOM, and fixed HIGH/CRITICAL vulnerability gates.

The manifest itself says `CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED`. No candidate
digest, SBOM result, repository-owned read-back, or local Docker smoke grants
publication authority.

## Implemented contracts and repository-owned results

| Contract | Implementation evidence | Current result |
|---|---|---|
| Independent authorization and annotated-tag eligibility verifiers | [PR #9](https://github.com/taipei49314/tomorrowci-lab/pull/9), merge `d8af4f839eddb73178a9fcf1f22b24382ee08bad`, exact-master [run 31458777043](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31458777043) success | **BLOCKED**: no genuine independent signer/evidence or consumed authorization exists |
| Result-blind public-target preregistration and repository-owned qualification workflow | [PR #10](https://github.com/taipei49314/tomorrowci-lab/pull/10), merge `6e41da287e004802213cfdfbbeb124ed26fa6ae0`, exact-master [run 31463351526](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31463351526) success; preregistration digest `sha256:1f9dee08d03f5f07b8c7f4396d6a0d3ee3aeb2b3071914e26d0a32f6e8b79ace` | **PASS (project-owned):** [run 31480491950](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31480491950) produced and reverified all six exact-target bundles; earlier runs `31467337605` and `31476579941` remain immutable failures |

## Blocking gates

- **BLOCKED — platform qualification:** hosted Linux Docker/Podman exact-target
  observations and reproducible archives do not qualify Windows Docker
  Desktop, macOS Docker Desktop/Colima, or a broader clean-machine matrix.
- **BLOCKED — independent authorization/adoption:** repository-owned CI and
  operator read-back are not independent external evidence.
- **BLOCKED — formal release:** no authorized annotated tag, protected
  single-consumption remote promotion, GitHub Release, OCI registry publish,
  or public download/pull read-back exists for `0.2.0-alpha.1`.
