# Release and support

## Versioning

Semantic versioning. Tag format: `v<SemVer>` (for example,
`v0.2.0-alpha.1`).

## Dry run (local)

```bash
# Unix
./scripts/release-dry-run.sh

# Windows PowerShell
./scripts/release-dry-run.ps1
```

Produces under `dist/`:

- CLI archives per target (as available on the host)
- `SHA256SUMS.txt`
- `sbom.cdx.json` (exact non-dev CLI dependency closure from locked Cargo metadata)
- `claim-to-evidence.md` snapshot
- `dry-run-results.md`

## GitHub Release workflow

`.github/workflows/candidate.yml` is currently a manual candidate-only dry run.
It does not accept tag pushes and has no GitHub Release or registry publish
step. This is deliberate while required platform, OCI, and external gates are
open:

1. Build Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64 binaries
2. Assert each runner architecture matches the archive label
3. Generate an exact locked CLI dependency SBOM and claim snapshot
4. Verify checksums over the complete candidate file set
5. Retain the result as a GitHub Actions candidate artifact only

If any required artifact is missing, the release job fails.

Tag promotion remains absent (and therefore fail-closed) until a detached,
independently attributable authorization can be verified against the frozen
candidate manifest and OCI digest. A tracked self-asserted JSON file is not an
external trust root and will not be accepted as one.

The historical `release.yml` workflow is retired and disabled. Candidate work
uses a new workflow path that did not exist at any published historical tag,
so `workflow_dispatch` cannot select old tag-controlled publishing code.

## Provenance

The current development line documents the path toward signed provenance:

- Build on GitHub Actions with the Rust toolchain pinned to exact version
  `1.97.1` and Action implementations pinned to immutable commits
- Emit checksums for archives, exact SBOM, and claim snapshot
- Future: cosign keyless signing for container images

No published version claims full SLSA Level 3.
