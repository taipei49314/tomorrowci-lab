# Historical release workflow retirement

Recorded: 2026-08-09 (Asia/Taipei)

## Finding

Changing the default-branch contents of `.github/workflows/release.yml` did
not remove the historical publishing surface. GitHub `workflow_dispatch`
selects workflow code from the requested ref. Published historical refs still
contained a `release.yml` with `contents: write` and a `dry_run=false` path,
so leaving the workflow ID active would allow old tag-controlled code to run.

No unsafe dispatch was attempted.

## Containment

- GitHub workflow ID `328349175` (`release`) was changed from `active` to
  `disabled_manually` with `gh workflow disable release.yml`.
- The development branch removes the historical `release.yml` path.
- Candidate construction moves to `.github/workflows/candidate.yml`, a new
  path absent from every published historical tag.
- The candidate workflow has `contents: read`, no tag trigger, and no release
  or registry publishing step.

After merge, qualification must re-check that workflow ID `328349175` remains
disabled and that only the new candidate workflow is dispatchable. Formal tag,
GitHub Release, and registry promotion remain forbidden until the independent
external authorization contract is implemented and satisfied.
