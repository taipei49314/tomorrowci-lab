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

- a deterministic CLI archive for the exact host target, reproduced from two
  clean release builds
- `SHA256SUMS.txt`
- `sbom.cdx.json` (exact non-dev CLI dependency closure from locked Cargo metadata)
- `claim-to-evidence.md` snapshot
- `dry-run-results.md`

## GitHub Release workflow

`.github/workflows/candidate.yml` is currently a manual candidate-only dry run.
It does not accept tag pushes and has no GitHub Release or registry publish
step. This is deliberate while required platform, OCI, and external gates are
open:

1. Accept dispatches only from `refs/heads/master` and bind the candidate to
   the exact checked-out `GITHUB_SHA` and workflow run
2. Build Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64 binaries
   twice from independent clean target directories
3. Assert each runner architecture matches the archive label, package with
   fixed paths/order/mtime/permissions, and require both archive hashes to match
4. Build a single-platform `linux/amd64` OCI layout twice with Buildx
   `v0.36.1` and the BuildKit `v0.31.2` image pinned by digest, embedded
   provenance disabled, `SOURCE_DATE_EPOCH=0`, and timestamp rewriting; require
   the complete OCI tar SHA-256 values and bytes to match
5. Bind the OCI manifest/config/layers, pinned base-image materials, exact
   Containerfile, max-mode Buildx metadata, source SHA, and workflow attempt in
   canonical detached `image-provenance.json`; then load the image and recheck
   CLI version/trust, numeric user `65532:65532`, OCI labels, and Docker-socket
   doctor readiness
6. Use the digest-pinned Trivy `0.73.0` image to generate a CycloneDX image SBOM
   and reject fixed HIGH or CRITICAL vulnerabilities with `--ignore-unfixed`
7. Generate an exact locked CLI dependency SBOM plus claim, support, and
   qualification-backlog snapshots
8. Freeze `candidate-manifest.json` with the exact source SHA, run URL, version,
   toolchain, payload sizes, and payload digests, including the OCI tar, build
   metadata, detached provenance, Containerfile, image SBOM, and vulnerability
   JSON; the manifest remains explicitly
   `CANDIDATE_ONLY_NOT_RELEASE_AUTHORIZED`
9. Scope every platform, OCI, and final artifact name to
   `GITHUB_RUN_ATTEMPT`, then
   verify canonical archive inventories and the exact final
   `SHA256SUMS.txt`/candidate inventory before retention; partial failed-job
   reruns cannot reuse an earlier attempt's bytes

If any required artifact is missing, the candidate-index job fails.

Authorized protected tag promotion remains absent (and therefore fail-closed)
until a detached, independently attributable authorization can be verified
against the frozen candidate manifest and OCI digest. A tracked self-asserted
JSON file is not an external trust root and will not be accepted as one.

Separately, the owner published
[`v0.2.0-alpha.1`](https://github.com/taipei49314/tomorrowci-lab/releases/tag/v0.2.0-alpha.1)
as an immutable project-operated prerelease for external testing. It contains
the exact candidate bytes from source `f83d43235c4d03ea9a95fc048d3edbd582e8f438`;
all 16 assets passed anonymous public digest and verifier read-back. This
relaxed distribution did not consume external authorization, did not run the
protected promotion workflow, and did not publish a GHCR image. It is not the
formal release described by the gates below.

The SHA-256 digest of `candidate-manifest.json` is the detached subject an
external auditor must authorize. Neither the manifest nor its checksums grant
promotion authority by themselves.

The offline verification contracts are implemented in
[`EXTERNAL_PROTOCOL.md`](qualification/EXTERNAL_PROTOCOL.md) and
[`TAG_PROMOTION_ATTESTATION.md`](qualification/TAG_PROMOTION_ATTESTATION.md).
They verify an independently signed authorization and bind an annotated tag to
the exact candidate bytes; they do not create signatures, tags, releases, or
registry publications. Repository-owned tests of these verifiers are not
external authorization. The three public qualification targets are frozen in
[`external-targets/preregistration-v1.json`](qualification/external-targets/preregistration-v1.json)
with status `NOT_RUN` and cannot be replaced based on their future result.

The historical `release.yml` workflow is retired and disabled. Candidate work
uses a new workflow path that did not exist at any published historical tag,
so `workflow_dispatch` cannot select old tag-controlled publishing code.

The protected promotion workflow also requires the exact platform run ID,
attempt, and canonical seven-artifact identity described in
[`PLATFORM_PROTOCOL.md`](qualification/PLATFORM_PROTOCOL.md). Its prepare and
protected write phases independently download the raw GitHub artifact ZIPs and
re-run the checked-in verifier before any possible mutation. This consumption
contract does not itself record a platform result or confer release authority;
the platform gates remain `NOT_RUN` until the dedicated-runner protocol has
actually completed.

## Provenance

The current development line documents the path toward signed provenance:

- Build on GitHub Actions with the Rust toolchain pinned to exact version
  `1.97.1` and Action implementations pinned to immutable commits
- Emit checksums for archives, exact SBOM, and claim snapshot
- Future: cosign keyless signing for container images

No published version claims full SLSA Level 3.
