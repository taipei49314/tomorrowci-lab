# Adapter authoring guide: current-v2 contract

Adapters translate an ecosystem into typed inputs for the runner. They do not execute target code on the host, write authoritative verdicts, or weaken the evidence verifier.

## Rust contract

Implement `tomorrowci_adapters::EcosystemAdapter`:

| Method | Responsibility |
|--------|----------------|
| `name` | Stable adapter identity; must agree with the detected ecosystem recorded in current-v2 evidence |
| `detect` | Return manifests, package manager, confidence, and support status without guessing an unsupported manager |
| `baseline` | Produce the concrete runtime and dependency baseline from repository/config inputs |
| `candidates` | Produce deterministic, ordered, concrete candidates; do not invent future APIs or availability |
| `materialize` | Describe the container environment, limits, workdir, and mutable image tag; the runner resolves and records the immutable digest |
| `commands` | Return phase-labelled `CommandSpec` values with argv, cwd, and network semantics |
| `normalize_failure` | Deterministically convert a typed `RawExecutionResult` into a `FailureSignature` |

## Trust rules

1. Unsupported package managers return `UNSUPPORTED` or `supported = false`; do not choose a nearby tool and continue.
2. Detection manifest paths must be canonical repository-relative paths. The runner requires the identity manifest set to equal the detected set and binds each hash to the captured workspace.
3. Adapters inspect the original repository only for detection/planning. Target commands run against the runner's disposable copy, never as an unrestricted host shell.
4. Keep `image_tag` descriptive and mutable. Do not place a digest in the tag field or manufacture a digest. The runner/engine resolves a canonical immutable digest and records the engine name/version.
5. Commands must state their phase and network need. Fetch commands use `phase = "fetch"` and `network = true`; test commands use `phase = "test"` and `network = false`. The verifier rejects phase mismatches and networked test commands, while phase evidence binds the actual fetch network boundary.
6. Keep argv deterministic and explicit. If an ecosystem requires a shell inside the container, the shell invocation itself must be an explicit argv record; no target command may fall back to host execution.
7. Failure normalization operates on captured raw exit/timeout/stdout/stderr. It must not discard the raw attempt, read mutable external state, or assign a verdict. The same ecosystem normalizer is used for replay comparison.
8. A baseline failure does not authorize future scenarios. Missing engine/digest, fetch failure, timeout, or execution construction failure remains typed and must never be promoted to `PASS`.

## Runner-owned behavior

Adapter implementations must rely on the runner/evidence layers for:

- stable source capture, original-repository protection, and recursive workspace inventory;
- configuration hashing and tool/adapter/engine/image identity records;
- image resolution, fetch/test network separation, timeouts, retries, and cleanup;
- contiguous typed attempt records and verdict derivation;
- exact recursive current-v2 inventories, no-follow/reparse containment, and cross-file verification;
- append-only transactional replay and verification-gated report/compare reads.

Do not duplicate these controls in an adapter or bypass them with adapter-specific evidence.

## Registration

Wire detection into `scan_local` in `crates/runner` in an unambiguous order. The recorded `RunIdentity.adapter_name` must match the selected ecosystem (`python`, `node`, or `rust`), and the adapter version must match the current tool contract. Update the README ecosystem table without claiming a later milestone is qualified.

## Required tests

- Detection success, unsupported-manager behavior, and canonical manifest paths.
- Baseline and deterministic candidate ordering from fixed config/repository inputs.
- Environment tag construction without a fabricated digest.
- Exact fetch/test `CommandSpec` phase and network fields.
- Deterministic normalization for representative raw failures and timeouts.
- Runner integration with an injected executor proving raw-attempt capture, typed verdict derivation, v2 finalization, and tamper rejection.
- Replay normalization for the adapter's ecosystem.

Unit or scripted-executor coverage is not live qualification. A support claim also requires real container execution on the declared platform and the repository's independent qualification gate.

## Current scope boundary

The shared contract contains Python, Node, and Rust paths, but Phase 1 does not by itself qualify M2 dependency-axis/ddmin behavior, M3 full live Node/Rust execution, M4 Action/UI behavior, or M5 release readiness. Preserve `BLOCKED`, `UNSUPPORTED`, and `NOT_RUN` labels until their actual evidence exists.
