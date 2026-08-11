# Threat model: Phase 1 trust core

This document describes the current-v2 evidence path being hardened in Phase 1. It is a statement of implemented trust boundaries, not a qualification claim for later milestones.

## Assets

- The original source repository, which a scan or replay must not mutate.
- The exact source snapshot, normalized configuration, adapter, tool, engine, and image identity associated with a run.
- Raw execution attempts, logs, failure signatures, derived verdicts, and the breakage frontier.
- The completeness and internal consistency of an evidence bundle.
- Host secrets, the host filesystem, and the container daemon.
- Policy decisions made by trusted consumers such as `report` and `compare`.

## Trust boundaries

| Zone | Treatment |
|------|-----------|
| TomorrowCI CLI, core, evidence verifier, and trusted-read gates | Trusted code; must fail closed on malformed or inconsistent evidence |
| Host OS and filesystem | Part of the local trusted computing base; paths are still checked for aliasing and containment |
| Docker/Podman engine | Trusted computing base for execution isolation, resource limits, and digest resolution |
| Original target repository | Untrusted input; copied before execution and checked for source-copy stability |
| Captured disposable workspace | Untrusted target bytes, but its exact regular-file inventory is integrity-bound by `workspace-manifest.json` |
| Registry images and fetched packages | Untrusted supply-chain input; an immutable digest identifies bytes but does not establish publisher trust |
| Logs, failure text, and report strings | Untrusted content; parsers and renderers must not treat it as code or raw HTML |
| CI hosting and external qualification | Outside the local evidence trust root until independently verified |

## Attacker goals

- Mutate the original repository or escape the disposable workspace.
- Escape the container, mount `docker.sock`, obtain host secrets, or abuse a privileged container.
- Substitute a mutable image, engine, adapter, configuration, or source identity after execution.
- Delete a failing scenario, add an unlisted file, alter a raw attempt, or edit a mirrored verdict into `PASS`.
- Exploit duplicate IDs, path traversal, symlinks, Windows junctions/reparse points, or cross-file disagreement.
- Poison replay history with gaps, partial attempts, collisions, or an unrecorded execution.
- Make `report` or `compare` consume tampered evidence.
- Inject active content through logs or other untrusted report fields.

## Current-v2 controls

### Filesystem and source containment

- Run IDs, scenario IDs, and manifest paths must be canonical relative components. Absolute paths, `..`, backslashes, drive-relative paths, duplicate separators, and non-portable components are rejected.
- Evidence traversal uses `symlink_metadata`-style no-follow checks. A symlink or Windows reparse point at the target or any existing ancestor is rejected; regular files and real directories are required.
- Joins are lexically contained beneath their declared root. Unknown directories, special files, and unrecognized evidence paths fail verification.
- Scans execute against a captured disposable workspace. The original source identity is sampled around the copy, and the copied regular-file inventory must match the source inventory before execution proceeds.
- Target code is never silently executed on the host when the container engine is unavailable; the run remains `BLOCKED`.

### Execution isolation

- Target containers are unprivileged, drop capabilities, set `no-new-privileges`, and do not receive `docker.sock` or arbitrary host environment forwarding.
- CPU, memory, PID, and time limits are explicit evidence-bound environment fields. Timeout cleanup targets the exact named container.
- Fetch and test are separate phases: only declared fetch work receives registry/package network access; the test phase uses `network = none`.
- Untrusted logs and failure text remain data. HTML rendering strips ANSI sequences and escapes strings before display.

### Exact inventory and semantic closure

- Current evidence uses a versioned `# tomorrowci-checksums-v2` header and canonical lowercase `sha256:<64 hex>` values.
- The run inventory is allowlisted and exact. It binds every run-level artifact and each scenario checksum manifest. Each scenario manifest recursively binds its allowlisted artifacts, attempt logs, and committed replay directories. Missing, extra, duplicate, malformed, or mutated entries fail verification.
- `workspace-manifest.json` independently binds the complete captured source-file inventory, except for explicitly ignored generated/cache directories.
- Cross-file checks require `run.json`, `repository.json`, `plan.json`, `frontier.json`, `verdicts.json`, scenario directories, `scenario.json`, and `result.json` to describe the same run and the same scenario set.
- Fetch and test commands are typed and phase-bound. Fetch execution uses the declared fetch network boundary; test commands require offline semantics. Phase timestamps, raw summaries, environment records, replay descriptors, logs, and failure signatures must agree.
- `test-attempts.json` is the classification authority. Attempts are contiguous typed records, and the verifier re-derives the verdict from exit/timeout outcomes. Mirrored verdict files cannot independently authorize `PASS`; not-run and execution-error states remain `BLOCKED` or `UNSUPPORTED` as defined by the typed status.

### Identity binding

For current-v2 evidence, verification binds:

- source URI/local identity, canonical Git object ID when available, dirty-tree state, and the recursive workspace snapshot;
- normalized configuration content to `config_hash` in both the run and identity record;
- for bounded remote scans, the canonical GitHub origin, requested and resolved
  40-hex commit, clean detached checkout, prohibited Git capabilities, source
  budgets, and captured workspace-manifest digest in `remote-source.json`;
- the exact detected manifest set and each manifest hash;
- tool version, detected ecosystem, adapter name, and adapter version;
- run start/finish timestamps;
- for every executed scenario, the container engine name/version and a canonical immutable image digest.

A mutable tag remains descriptive metadata. Replay and executed-result authority comes from the recorded digest and the other bound identity fields.

### Replay and trusted consumers

- Replay validates ancestors and fully verifies before creating its exclusive per-run operation lock, verifies again under the lock before resolving an image or executing target commands, and takes a stable verified manifest read. It makes a fresh disposable copy from the captured workspace, requires the recorded engine identity and immutable digest, and uses the failure normalizer for the recorded ecosystem.
- Replay attempt numbers are canonical, contiguous, and append-only. A staging directory reserves the next number before execution, preventing concurrent use of the same slot. A complete result/stdout/stderr set is atomically renamed into `replays/attempt-N`; failures are evidence too, not invisible executions.
- The latest replay alias, checksums, and full bundle are re-finalized and re-verified. Post-commit failure rolls the attempt and checksum state back. A replay result is reported as passing only after exit/timeout and normalized failure-signature agreement and successful post-verification.
- `report` and `compare` validate and pre-verify roots before creating exclusive operation locks, then use verification-gated stable reads. Report generation stages its output, permits only the selected report artifact to change, re-finalizes v2 inventories, and rolls back on failure. Compare verifies both inputs around manifest/config loading and confirms unchanged bytes before deriving a horizon or verified head-policy decision.

## Compatibility boundary

Headerless legacy checksum evidence is read-compatible only for the exact historical `0.1.1-alpha.2` tool/schema and its known omissions. Legacy compatibility does not authorize new legacy writes, re-finalization, promotion to current-v2, or release qualification. Removing the v2 header from current evidence is a downgrade attempt and fails the current tool/schema checks.

## What the checksums do not prove

The checksum graph provides integrity and tamper detection for an evidence bundle. It is not a signature, MAC, transparency-log proof, or independent attestation. An attacker who can rewrite the complete bundle can also recompute unsigned checksums; a digest identifies content but does not authenticate who produced or approved it. Release authority therefore requires a trust root outside the bundle.

Repository-owned authorization-verifier tests, public-target workflow runs,
candidate downloads, and operator read-back remain inside the project trust
boundary. Even when internally valid, none can substitute for a genuine
independent signer, a separately provisioned trust root, or protected
single-consumption remote promotion.

## Bounded M2 qualification observation

At exact master `456a36edb1e8547612cd13ee7a30be3479d33bab`, public CI run
[31316809823](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31316809823)
passed the checked-in Python, Node, and Rust dependency fixtures on Linux
Docker. The gate used native pip, npm, and cargo materialization, recorded exact
dependency content and resolved sets, observed the full two-change candidate,
tested each non-empty subset, selected `breaking-api` as the minimal failing
change, verified the evidence, and replayed that minimal scenario twice.

The downloaded artifact (ID `9039044133`, digest
`sha256:402c5085be7890fa57b930f6ea9744b28d5e351b78ef0e78857ad365ac0fd2f3`)
was read back with the current CLI: all three current-v2 bundles verified with
140 checked files and all six replay logs reported matching exits and failure
signatures. The artifact expires on 2026-11-07, so the immutable source and CI
identity remain part of the durable claim record.

This is a project-owned qualification observation, not an external
attestation. It neither authenticates the CI operator nor expands the result
to arbitrary registry packages, Podman, other host platforms, or the broader
M3 Node/Rust runtime matrix. See the [M2 record](../qualification/M2.md).

## Residual risk and unqualified scope

- Container-engine, kernel, and isolation defects remain in the trusted computing base.
- Malicious base images, compromised registries, dependency registries, and fetch-time network exfiltration remain supply-chain risks. Digest equality alone is not publisher or provenance verification.
- Local concurrent filesystem mutation and platform-specific alias behavior are reduced by pre/post verification and no-follow checks, but the host OS remains trusted.
- External independent qualification, signing authority, protected promotion,
  and published-output read-back remain outside this Phase-1 trust core.
- Dependency-axis/ddmin behavior beyond the exact M2 Linux Docker fixtures,
  M3 Node/Rust execution beyond the exact Linux Docker fixtures, public-remote
  Docker/Podman execution, the wider platform matrix, and formal release
  qualification are not established by these controls. The bounded M4 report
  and exact-commit materialization engineering tests do not expand those claims.

## Out of scope

- Formal verification of TomorrowCI or the container runtime.
- Multi-tenant SaaS isolation guarantees.
- Cryptographic identity or provenance claims without an external signer/trust root.
