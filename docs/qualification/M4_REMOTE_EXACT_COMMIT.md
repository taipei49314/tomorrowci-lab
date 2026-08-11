# M4 bounded remote exact-commit scan contract

This development slice replaces the CLI's former unconditional remote
`NOT_RUN` error with a bounded materialization path. It does **not** by itself
qualify the full M4 remote row: public exact-commit Docker/Podman evidence and
default-branch artifact read-back remain required before the status can move
to `PASS`.

## Invocation

```text
tomorrowci scan https://github.com/<owner>/<repository> \
  --commit <40-lowercase-hex> [--config <path>]
```

Remote input accepts only the canonical HTTPS GitHub repository grammar. A
branch, tag, abbreviated object ID, uppercase object ID, URL credential,
query, fragment, port, redirect, or additional path is rejected. `--commit`
is rejected for local-path scans so a moving ref cannot become accidental
authority.

## Materialization boundary

- Git runs with system/global configuration disabled, prompting and credential
  helpers disabled, HTTP redirects disabled, hooks isolated, and LFS smudging
  disabled.
- Only the requested commit is shallow-fetched; the checkout is detached and
  its resolved `HEAD`, origin, and clean status are checked before and after
  scanning.
- Submodules, LFS metadata, symlinks/gitlinks, non-regular tree entries,
  non-UTF-8 or unsafe paths, and tracked paths excluded by the workspace
  inventory contract fail closed.
- The bound is 120 seconds, 10,000 files, 25 MiB per file, 100 MiB of checked
  out source, and 256 MiB of temporary clone storage.
- Target-controlled commands are never run by Git materialization. They retain
  the existing container-only runner boundary.

The Git checkout lives in a unique temporary directory. Evidence is written
under the caller's `.tomorrowci/runs/<run-id>` instead, including the frozen
`workspace/`. The temporary checkout is deleted after the scan, while verify
and replay continue to use the recorded workspace.

The recorded workspace remains free of `.git`. Each disposable scenario gets
index-only synthetic metadata derived from its verified workspace manifest and
the same exact file bytes. It supports `git ls-files` path enumeration only;
there are no commits, history, hooks, remotes, credentials, object files, or
ref files. Fixed runner-provided `GIT_*` variables disable global/system
configuration and bind `safe.directory=/work`; any additional runner-provided
`GIT_*` override fails verification.

## Evidence identity

Current-v2 remote bundles add `remote-source.json`. Schema v2 additionally
binds the synthetic index SHA-256, entry count, manifest digest, absent Git
capabilities, and exact environment. The verifier cross-checks
its canonical origin, requested/resolved commit, clean-tree state, prohibited
capabilities, budgets, file/byte inventory, and
`workspace-manifest.json` digest against `run.json` and the recorded workspace.
Changing the remote provenance and then recomputing checksums still fails the
semantic verifier.

Historical schema-v1 remote evidence remains available to the generic
read-only verifier. It is not accepted as new external qualification authority
and the amended runner refuses v1 replay; new qualification and replay require
schema v2.

## Offline regression

The runner test creates a local bare Git fixture, fetches its first exact
commit through the same materializer, advances the remote branch, runs the
full evidence writer with a test-only container executor, deletes the temporary
checkout, and then checks:

1. the recorded workspace still contains the first commit;
2. evidence is `current_v2` and verifies;
3. exact replay matches exit status and normalized failure signature; and
4. initial execution and exact replay install the same manifest-derived index;
5. a semantically forged index record or Git environment is rejected even
   after checksum re-finalization; and
6. schema v1 remains verify-only and cannot be downgraded into qualification or
   replay authority.

The local transport exists only inside the unit test. Production CLI grammar
and protocol policy remain HTTPS GitHub-only.
