# Current qualification status

Recorded on 2026-08-13. This is the canonical run-bound status record for the
project-operated `0.2.0-alpha.1` external-testing prerelease line. Workflow or
verifier implementation is not a qualification result: a later execution
changes a row only when its exact source, run, artifacts, and repository-outside
operator read-back are committed
here and in `backlog.json`.

## Accepted bounded observations

| Scope | Status | Exact evidence | Boundary |
|---|---|---|---|
| M2 dependency/ddmin Linux Docker | **PASS** | master `456a36edb1e8547612cd13ee7a30be3479d33bab`; [run 31316809823](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823); artifact `9039044133`, digest `sha256:402c5085be7890fa57b930f6ea9744b28d5e351b78ef0e78857ad365ac0fd2f3`; downloaded current-v2 verify/replay read-back | Checked-in pip/npm/cargo fixtures on Linux Docker only; not ecosystem-wide or external qualification |
| M3 Node/Rust Linux Docker | **PASS** | master `a6af3076ed3286d42c5ed7a386cb6812d8b76c50`; [run 31447884019](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31447884019); artifacts `9085285817`, `9085282933`, `9085315934`; downloaded current-v2 verify/replay read-back | Repository fixtures on Linux Docker only; no Podman or platform claim |
| M4 interactive report engineering | **PASS** | [PR #5](https://github.com/taipei49314/tomorrowci-lab/pull/5), head `7c2534c7ec7a18bb18dc31a0864f7af5ae0807be`, merge `f6efabff0214ef02d2287ccb870a4e2a75c8e2f0`; exact-master [run 31451349743](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31451349743), `report-ui` job `93656185178` | Generated assets, types, unit behavior, Chromium accessibility/responsive/XSS/no-JS, and Rust renderer; bounded CI engineering slice |
| M4 exact-commit remote engineering | **PASS** | Same PR/merge/default CI; fail-closed exact-commit materializer, current-v2 remote identity, and offline full-writer/replay regression | Engineering contract only; the later live public-target result is recorded separately below |
| Deterministic release candidate | **PASS** | source `f83d43235c4d03ea9a95fc048d3edbd582e8f438`; [run 31678894284](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31678894284) attempt 1, 16/16 jobs success; artifact `9172900020`, digest `sha256:5b8b474a05d37c3be88dd559200643ea2439b619ef500f566394c741a05fc2d1`, size `90570997`, expires `2026-11-11T07:42:41Z` | Candidate construction and operator read-back only; not formal promotion or platform support |
| Preregistered public exact-SHA targets on hosted Linux Docker/Podman | **PASS** | source `f83d43235c4d03ea9a95fc048d3edbd582e8f438`; [run 31679941755](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31679941755) attempt 1; all six Python/Node/Rust × Docker/Podman jobs, observation read-back, and authoritative read-back succeeded; summary artifact `9173146614`, digest `sha256:165aaff2716f4362952487d731c14c9aa9de4cae6bda21f3f6104834ea81b564` | Exact three targets and hosted engine pair only; status `OBSERVED_PROJECT_OWNED_ONLY`, not ecosystem/platform support or independent authorization |
| Project-operated GitHub prerelease | **PASS** (distribution only) | [`v0.2.0-alpha.1`](https://github.com/taipei49314/tomorrowci-lab/releases/tag/v0.2.0-alpha.1), release `369814204`, exact source `f83d43235c4d03ea9a95fc048d3edbd582e8f438`, immutable, 16 assets / `92161526` bytes; anonymous HTTPS API/digest/SHA256SUMS/archive/OCI/Windows-CLI read-back passed | External testing only; manifest remains unauthorized, no independent signer, no protected formal promotion, no GHCR image |

The downloaded candidate archive digest matched the Actions API. Exact-source
verification accepted `candidate-manifest.json` digest
`sha256:cefd88c6d79537f19088891c2f911b50c60b75e801a2ce53b3bd5c0aa57bcaf4`,
OCI archive digest
`sha256:a4a73e60aaa705d80884c165df24b570dba3abd80f980341859f776050d4877f`,
detached provenance digest
`sha256:47b926d3c3c8de4c2d878415c1efae20acd1246a718f640a5b19c8905381cd76`,
and OCI manifest digest
`sha256:a96e9e3a1486281902e5d43143362a29e5de4d1bf64f6ba438d50bd7cb9f45f2`.
All four archive hashes matched the frozen manifest; the extracted Windows CLI
passed version/trust and fail-closed BLOCKED-evidence verification, while the
Ubuntu candidate job passed OCI load, non-root identity, labels, trust,
socket-doctor readiness, SBOM, and fixed HIGH/CRITICAL vulnerability gates.

The manifest itself says `CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED`. Publishing
the exact bytes as a clearly labeled project-operated external-testing
prerelease did not change that status or grant formal promotion authority.

## Implemented contracts and repository-owned results

| Contract | Implementation evidence | Current result |
|---|---|---|
| Independent authorization and annotated-tag eligibility verifiers | [PR #9](https://github.com/taipei49314/tomorrowci-lab/pull/9), merge `d8af4f839eddb73178a9fcf1f22b24382ee08bad`, exact-master [run 31458777043](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31458777043) success | **BLOCKED**: no genuine independent signer/evidence or consumed authorization exists |
| Result-blind public-target preregistration and repository-owned qualification workflow | [PR #10](https://github.com/taipei49314/tomorrowci-lab/pull/10), merge `6e41da287e004802213cfdfbbeb124ed26fa6ae0`, exact-master [run 31463351526](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31463351526) success; preregistration digest `sha256:1f9dee08d03f5f07b8c7f4396d6a0d3ee3aeb2b3071914e26d0a32f6e8b79ace` | **PASS (project-owned):** [run 31679941755](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31679941755) produced and reverified all six exact-target bundles; earlier failed runs remain immutable history |

## Blocking gates

- **BLOCKED — platform qualification:** hosted Linux Docker/Podman exact-target
  observations and reproducible archives do not qualify Windows Docker
  Desktop, macOS Docker Desktop/Colima, or a broader clean-machine matrix.
- **BLOCKED — independent authorization/adoption:** repository-owned CI and
  operator read-back are not independent external evidence.
- **BLOCKED — formal release:** the project-operated lightweight tag and
  immutable GitHub prerelease provide public download read-back only. No
  authorized annotated tag, protected single-consumption promotion, genuine
  independent authorization, or OCI registry publication exists.
