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

## Evidence identity

Current-v2 remote bundles add `remote-source.json`. The verifier cross-checks
its canonical origin, requested/resolved commit, clean-tree state, prohibited
capabilities, budgets, file/byte inventory, and
`workspace-manifest.json` digest against `run.json` and the recorded workspace.
Changing the remote provenance and then recomputing checksums still fails the
semantic verifier.

## Offline regression

The runner test creates a local bare Git fixture, fetches its first exact
commit through the same materializer, advances the remote branch, runs the
full evidence writer with a test-only container executor, deletes the temporary
checkout, and then checks:

1. the recorded workspace still contains the first commit;
2. evidence is `current_v2` and verifies;
3. exact replay matches exit status and normalized failure signature; and
4. a semantically forged `remote-source.json` is rejected even after checksum
   re-finalization.

The local transport exists only inside the unit test. Production CLI grammar
and protocol policy remain HTTPS GitHub-only.
