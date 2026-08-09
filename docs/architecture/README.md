# Architecture: Phase 1 trust core

TomorrowCI's current-v2 path is a fail-closed pipeline from an untrusted repository to a verified evidence bundle. Reports, comparisons, and replays are consumers of verified evidence; they are not alternative sources of truth.

```text
detect + normalize config
  -> capture source identity and disposable workspace
  -> plan baseline and candidate scenarios
  -> resolve immutable image digest
  -> fetch with network / test without network
  -> record typed raw attempts
  -> derive verdicts and frontier
  -> finalize exact v2 inventories
  -> verify checksums, identity, and semantic closure
  -> authorize trusted reads
```

## Components and ownership

| Component | Owns | Must not own |
|-----------|------|--------------|
| CLI | Command routing and trusted-read gates for report/compare/replay | Independent verdict authority |
| Core | Typed configuration, plans, attempts, verdict rules, and frontier comparison | Filesystem trust or target execution |
| Adapters | Ecosystem detection, concrete candidates, environment specs, typed commands, and deterministic failure normalization | Host execution, evidence finalization, or promotion of blocked states |
| Runner | Lifecycle ordering, disposable workspace, network separation, retries, and raw attempt capture | Trusting terminal text as a verdict |
| Sandbox | Docker/Podman execution, limits, timeout cleanup, and digest-based image execution | Evidence policy |
| Evidence | Layout, exact checksum inventories, no-follow path checks, identity binding, and semantic verification | Cryptographic authenticity |
| Report | Escaped JSON/HTML/SARIF/summary projections of a verified manifest | Mutation of source evidence or verdict derivation |

## Execution lifecycle

1. Detection selects a supported Python, Node, or Rust adapter without guessing an unsupported package manager.
2. The runner records source location, canonical Git commit when available, dirty state, and hashes of detected manifests. It creates a disposable copy and an exact workspace manifest, then confirms that source identity and bytes stayed stable across capture.
3. The normalized config is content-hashed. The adapter emits concrete baseline/candidates, an environment description, and phase-labelled argv records.
4. The baseline must establish `BASELINE_PASS` before a future-breakage horizon can be authorized. A missing engine, unresolved digest, failed fetch, timeout, or construction error stays typed as `BLOCKED`, `UNSUPPORTED`, or `INCONCLUSIVE`.
5. The runner resolves the image tag to a canonical immutable digest and records engine name/version. Fetch runs with the declared network policy; tests run with network disabled.
6. Every test execution becomes a contiguous `TestAttemptRecord` containing exit, timeout, duration, and normalized failure data. Classification is derived from those typed attempts; `verdicts.json` is only a checked mirror.
7. All writers finish before current-v2 checksum finalization. Finalization and verification are required to succeed before the bundle is offered to trusted consumers.

## Current-v2 evidence invariants

### Exact recursive inventory

- The run checksum manifest covers the exact allowlisted run-level files and `scenarios/<id>/checksums.txt` for every scenario.
- Each scenario checksum manifest recursively covers the exact allowlisted scenario files, per-attempt logs, and committed replay attempts.
- The workspace manifest covers captured source regular files, subject only to documented generated/cache exclusions.
- Unknown files/directories, missing files, duplicate paths, malformed hashes, and inventory differences fail closed.

This is a two-level checksum graph. No `checksums.txt` hashes itself; the parent run manifest binds each scenario checksum manifest, which in turn binds the nested scenario content.

### No-follow containment

Identifiers and paths are canonical and relative. Filesystem reads/writes reject symlinks, Windows reparse points, and aliased ancestors, require regular files/real directories, and verify lexical containment under the selected run, scenario, or workspace root.

### Identity and semantic closure

Current-v2 requires a non-null run identity. The verifier binds source/commit/dirty state, normalized config hash, exact detected-manifest hashes, tool/adapter identity, timestamps, container engine/version, and immutable image digest. It also checks that run-level mirrors, scenario directories, commands, phase evidence, raw results, failure signatures, replay descriptors, typed attempts, derived verdicts, and frontier inputs agree.

## Replay architecture

Replay is a transactionally append-only extension of a verified bundle:

1. Validate ancestors and verify the whole run before creating any lock file; then acquire the run's exclusive operation lock, verify again, read the manifest, verify again, and confirm that the manifest bytes stayed stable.
2. Select the recorded scenario from the verified plan and make a fresh disposable copy from the captured workspace. The recorded snapshot and original repository are not execution targets.
3. Require the same engine name/version, immutable image digest, timeouts, environment, and commands.
4. Reserve the next canonical attempt number with a staging directory before executing.
5. Atomically commit a complete attempt directory. Handled fetch failures and execution errors become failed attempts; a partial, stale, or colliding staging state fails closed.
6. Update the latest-attempt mirror, re-finalize exact inventories, and perform full post-verification. If that transaction fails, remove the attempted append and restore the previous mirror/checksum state.
7. Return replay `PASS` only when exit/timeout and ecosystem-specific normalized signature match and post-verification succeeds.

Replay does not mutate the user's original repository or the recorded workspace snapshot. Target mutations are confined to the fresh disposable replay copy, which is removed after the operation.

## Trusted-read architecture

- `report` validates ancestors and pre-verifies before creating its lock, verifies again under the lock, loads and rechecks stable `run.json` bytes, renders to a temporary location, changes only the requested report artifact, re-finalizes v2 checksums, and post-verifies. Failure triggers rollback.
- `compare` validates and pre-verifies both roots before creating lock files, acquires both per-run locks in deterministic path order, verifies both base and head bundles again, loads each bound manifest/config, verifies again, and confirms unchanged bytes before computing the horizon delta or verified head policy gate. A malformed, unresolved, or tampered side yields no trusted gate.
- Readers must not bypass the verifier by reading `run.json`, `frontier.json`, or `verdicts.json` in isolation for a trust-sensitive decision.

## Compatibility and trust limits

Legacy headerless evidence is read-compatible only for the exact `0.1.1-alpha.2` schema. Current writers emit v2 only; legacy evidence cannot be relabelled as current, re-finalized as trusted v2, or used as release authorization.

SHA-256 inventories detect mutation and structural inconsistency but provide no signature or producer authenticity. Docker/Podman, the host OS, registry resolution, image/package provenance, and external release authority remain outside or below this evidence layer.

## Milestone status boundary

- Phase 1/M1: the current work hardens the measured Python vertical slice and the shared v2 trust core. Platform and external qualification are tracked separately.
- M2: dependency-axis and ddmin behavior is not qualified.
- M3: full live Node/Rust adapter execution is not qualified.
- M4: GitHub Action and polished UI are not qualified.
- M5: public release candidate/release authority is not qualified.

Code or fixtures for a later milestone do not change that status without real execution evidence and the required independent gate.
