# Changelog

All notable changes to TomorrowCI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Add content-addressed dependency manifests, exact resolved dependency sets,
  subset materialization, and observed minimal-change reduction for pip, npm,
  and cargo fixtures.
- Add a Linux Docker CI qualification gate that scans each dependency fixture,
  verifies its current-v2 evidence, and replays the minimal failing scenario
  twice with matching exit and normalized failure signature.

### Changed

- Start the `0.2.0-alpha.1` development line for the versioned strict evidence
  inventory and fail-closed replay trust core.
- Make no-engine scans emit complete, verifiable BLOCKED evidence rather than
  leaving a partial run.
- Derive CLI, package, archive, changelog, and SBOM identity from the Cargo
  workspace version; release tags must match it exactly.
- Pin external GitHub Actions to immutable commits and replace placeholder
  dependency versions with an exact Cargo.lock CycloneDX inventory.
- Disable and retire the historical dispatchable release workflow path; build
  read-only candidates from a new workflow path that does not exist on old
  published refs.
- Normalize Windows Docker Desktop bind paths and force-remove exactly named
  containers after timeout so a killed client cannot leave target work running.
- Record the bounded M2 PASS at exact master
  `456a36edb1e8547612cd13ee7a30be3479d33bab` in CI run
  `31316809823`; at that source identity M3 runtime, Podman, platform, and
  independent external qualification remained unclaimed.
- Qualify bounded Node and Rust runtime slices on Linux Docker at exact master
  `a6af3076ed3286d42c5ed7a386cb6812d8b76c50` in CI run `31447884019`,
  including current-v2 verification, replay x2, downloaded-artifact read-back,
  and fail-closed baseline-invalid/flaky/blocked controls. Podman and the wider
  platform matrix remain unclaimed.

### Security

- Reject malformed, duplicate, escaping, aliased, unlisted, missing, or
  mutated evidence entries, including scenario and replay content.
- Reserve replay attempts append-only and refuse target execution when the
  existing evidence bundle fails verification.

## [0.1.1-alpha.2] - 2026-08-06

### Changed

- Evidence integrity: image tag/digest separation, phase timestamps, scenario-local venvs
- `tomorrowci verify` checksum boundary including claims.json
- Independent replay attempt artifacts under `replays/attempt-N/`
- Action structured exit handling; consumer git repository dogfood
- Package version `0.1.1-alpha.2`; acceptance-gated release workflow with prerelease

### Notes

- `v0.1.1-alpha.1` preserved as rejected acceptance candidate
- `v0.1.0` preserved as rejected product candidate

## [0.1.0] - 2026-08-06

### Added

- Domain model, config schema, verdict and breakage-horizon authorization
- Budget-aware planner, failure reruns, flaky classification, ddmin axis reduction
- Ecosystem adapters: Python (pip), Node (npm), Rust (cargo)
- Docker/Podman sandbox executor with safe defaults (no host target execution)
- Evidence bundles with checksums, replay scripts, HTML/JSON/SARIF reports
- Scan metrics instruments and claim-to-evidence ledger
- Trust-behavior audit (`tomorrowci trust`)
- GitHub composite Action, job summary, base/head horizon compare + policy gate
- Fixtures: python-runtime-break, python-dependency-break, node-dependency-break, rust-msrv-break
- Release dry-run tooling and documentation suite for public v0.1

### Security

- Privileged containers and docker.sock mounts rejected by policy
- Fetch/test network phases separated; secrets scrubbed from container env
- HTML report escapes untrusted content; ANSI stripped from logs

### Known limitations

- Live container e2e requires a running Docker/Podman daemon
- yarn/pnpm, poetry, and remote GitHub clone scan are unsupported or incomplete
- SBOM/signing use cargo-based dry-run scripts; full SLSA provenance is documented as future work
