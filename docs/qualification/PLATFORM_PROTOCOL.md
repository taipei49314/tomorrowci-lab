# Dedicated platform qualification protocol

This protocol makes the remaining Windows and macOS engine gates executable.
It does not record a result. `SUPPORT.md`, `STATUS.md`, and the qualification
backlog remain `NOT_RUN`/`BLOCKED` until a successful exact-source run and
repository-outside artifact read-back are recorded.

## Immutable inputs

Dispatch `.github/workflows/platform-qualification.yml` from `master` with the
five values emitted and independently read back from one successful
`release-candidate` run at that same exact `master` commit:

- candidate run ID and positive attempt;
- `sha256:` digest of `candidate-manifest.json`;
- candidate source commit (which must equal the workflow commit);
- detached OCI image-manifest digest.

The workflow first queries the Actions run and artifact APIs, downloads the raw
candidate ZIP, verifies its API size/digest, re-runs the candidate and OCI
verifiers, and requires the manifest to remain explicitly unauthorized. Each
private machine downloads and independently verifies the same attempt-scoped
artifact before executing its native candidate CLI. No source or binary is
rebuilt.

## Dedicated self-hosted runners

The repository currently has no self-hosted runners. These labels intentionally
leave the workflow queued until a dedicated ephemeral machine is registered:

| Platform ID | Required labels | Provider contract |
|---|---|---|
| `windows-x86_64-docker-desktop-linux` | `self-hosted`, `Windows`, `X64`, `tomorrowci-ephemeral`, `tomorrowci-docker-desktop-linux` | Docker context `desktop-linux`; server OS `linux`; Docker Desktop identity |
| `macos-x86_64-colima` | `self-hosted`, `macOS`, `X64`, `tomorrowci-ephemeral`, `tomorrowci-colima` | Docker context `colima`; x86_64 Linux VM |
| `macos-aarch64-colima` | `self-hosted`, `macOS`, `ARM64`, `tomorrowci-ephemeral`, `tomorrowci-colima` | Docker context `colima`; arm64 Linux VM |

The runner is a single-use qualification host. Before execution, Docker must
have no containers or named volumes, and the fixture must have no stale
`.tomorrowci` evidence directory. The same conditions are checked after
replay. Cached images do not grant identity: every scenario records the exact
resolved image digest. The workflow has only `actions: read` and
`contents: read`, persists no checkout credential, receives no repository
secret, and is never triggered by pull requests.

Before checkout or candidate download, the candidate-binding, private platform,
and repository-operated read-back jobs create
attempt/source/candidate-bound fail-only observations under `runner.temp` and
retain them with `if: always()`. Thus checkout, download, and Python startup
failures still produce a non-PASS artifact, and an upload never depends on a
later step having created its path.

## Executed acceptance

On every machine the matching archive is safely extracted, compared to the
candidate inventory, and used for the following unchanged checked-in fixture:

1. `trust` and engine-aware `doctor`;
2. Python 3.9 baseline and bounded stable candidates using the Docker-only
   `.tomorrowci-platform.yml`;
3. observed baseline pass and future runtime horizon;
4. current-v2 `verify`;
5. replay of the first failing scenario exactly twice;
6. final `verify`;
7. source byte inventory before/after equality and empty post-run engine state.

Candidate and read-back extraction directories are created only below a parent
that passed the plain-directory and ancestor-alias checks. In particular, no
macOS extraction relies on the process-default `$TMPDIR`, whose `/var` spelling
normally traverses the `/var` to `/private/var` alias.

Immediately after scan, the workflow re-captures the active Docker context,
context endpoint, provider status, server version, and engine info. The captured
`engine-version`, engine-info `ServerVersion`, and every result environment
`engine_version` must be identical. The identity is checked again after verify
and both replays. For Colima, the reported Docker socket must exactly equal the
active `colima` Docker context endpoint.

The record verifier binds native archive and binary bytes, candidate manifest,
OCI manifest, source/workflow run identity, runner OS/architecture, provider and
engine identity, source tree, full evidence tree, root checksums, observed
frontier, and two exact replay results. A failure uploads its raw logs and any
available run bundle with `if: always()`; it is never converted to a PASS
record.

Retention closes the verify-to-copy window: the verified source snapshot must
still equal the source immediately before copy, the source immediately after
copy, and the retained destination snapshot.

## Independent read-back and reruns

After all three private jobs succeed, fresh GitHub-hosted Windows, macOS Intel,
and macOS arm64 jobs download the retained artifact, extract the same native
candidate archive, run the current-v2 verifier, recompute the record, and
require exact canonical bytes. This is repository-operated read-back, not an
independent authorization.

GitHub re-runs use a new `run_attempt`. To avoid mixing attempt-scoped
artifacts, re-run all jobs rather than only a failed read-back job. Any tracked
fix changes `master`; therefore it invalidates the candidate and requires a new
candidate plus a new platform run.

GitHub-hosted macOS arm64 runners do not provide the nested virtualization
needed for this engine gate. A physical or otherwise supported self-hosted
runner is therefore an external infrastructure requirement, not a reason to
remove the support row.
