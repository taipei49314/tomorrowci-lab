# ADR 0004: authoritative version and the 0.2 prerelease line

Status: accepted on 2026-08-09

## Context

The published `v0.1.1-alpha.2` artifact is a bounded measured Python lab
slice. The next product scope adds a stricter evidence format and verifier,
dependency/ddmin execution, live Node and Rust paths, the interactive report,
remote scans, platform/engine qualification, and an OCI release candidate.
Those changes are not another packaging pass over alpha.2.

Historical workflows and scripts repeated alpha.2 or v0.1.0 literals and could
therefore build bytes whose filename, CLI version, tag, changelog, or SBOM
identity disagreed.

## Decision

- Development moves to the `0.2.0` prerelease line. The first trust-core
  integration is `0.2.0-alpha.1`.
- `workspace.package.version` in the root `Cargo.toml` is the authoritative
  version source. Workspace manifests and `Cargo.lock` must resolve to it.
- `scripts/version_contract.py` validates Cargo, changelog, and exact `v<version>`
  tag identity. CI and release packaging consume its output; no fallback
  version is allowed.
- A prerelease version in source is not a release or qualification claim. No
  `v0.2.0-alpha.1` tag or GitHub Release may be created until the release
  workflow's exact-SHA external authorization gate passes.
- Published historical tags and assets remain immutable.

## Consequences

Evidence schema/version compatibility must be explicit. Consumers can still
read the documented legacy alpha.2 subset, while current bundles are held to
the new strict inventory. Any future version bump changes the one authoritative
Cargo value and the changelog; tag, CLI, package, SBOM, and archive identity
are checked mechanically.
