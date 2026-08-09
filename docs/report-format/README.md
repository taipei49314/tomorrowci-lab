# Evidence and report format: current-v2

A report is a projection of a verified evidence bundle. The report file, `run.json`, or `verdicts.json` alone is not an authority for a trust-sensitive decision.

## Bundle layout

```text
.tomorrowci/runs/<run-id>/
  run.json                       # RunManifest and RunIdentity
  repository.json                # exact mirror of source snapshot identity
  config.normalized.json         # normalized config bound by content hash
  candidates.json
  plan.json                      # exact mirror of the run plan
  plan-decisions.json
  verdicts.json                  # checked mirror; not classification authority
  frontier.json                  # exact mirror of the run frontier
  workspace-manifest.json        # exact captured source-file size/hash inventory
  workspace/                     # disposable captured source, never the original repo
  metrics.json
  claims.json
  report.json
  report.html
  report.sarif.json              # optional
  job-summary.md
  summary.txt
  reduction.json                 # optional
  checksums.txt                  # current-v2 run inventory
  scenarios/<scenario-id>/
    scenario.json
    environment.json
    fetch-commands.json
    test-commands.json
    commands.json                # checked fetch+test mirror
    image-resolve-phase.json
    fetch-phase.json             # present when fetch ran
    fetch-result.json            # typed raw fetch summary when fetch ran
    fetch-stdout.log             # present when fetch produced raw output
    fetch-stderr.log             # present when fetch produced raw output
    test-phase.json              # present when test ran
    test-result.json             # typed raw final-test summary when test ran
    test-attempts.json           # classification authority
    stdout.attempt<N>.log        # present for each recorded test attempt
    stderr.attempt<N>.log        # present for each recorded test attempt
    stdout.log                   # exact final-attempt mirror, or empty if not run
    stderr.log                   # exact final-attempt mirror, or empty if not run
    failure-signature.json       # present when a typed failure exists
    result.json                  # derived result, checked against attempts
    replay.json                  # environment/commands/expected-result binding
    replay.sh
    replay.ps1
    replay-result.json           # optional latest committed replay mirror
    replays/attempt-<N>/
      result.json
      stdout.log
      stderr.log
    checksums.txt                # recursive scenario inventory
```

Files for a phase that did not execute are omitted only where the schema explicitly permits that state. Required current-v2 structural files remain present even for `BLOCKED`/not-run scenarios.

## Checksum manifests

Current writers emit:

```text
# tomorrowci-checksums-v2
sha256:<64 lowercase hex>  canonical/relative/path
```

The inventory is exact, not best-effort:

- The run manifest lists every recognized run file and every `scenarios/<id>/checksums.txt`, excluding only its own `checksums.txt`.
- A scenario manifest recursively lists every recognized scenario file, numbered attempt log, and `replays/attempt-N` file, excluding only its own `checksums.txt`.
- `workspace-manifest.json` separately lists every captured source regular file except documented generated/cache roots.
- Unknown/unlisted paths, missing listed paths, duplicates, malformed hashes, noncanonical paths, inventory gaps, or changed bytes fail verification.

All filesystem traversal is no-follow: symlinks, Windows reparse points, aliased ancestors, non-regular files, and paths outside the selected root are rejected.

## Identity and closure

For current-v2, `RunIdentity` binds source commit/dirty state, tool and adapter identity, normalized config hash, exact detected-manifest hashes, container engine/version, and matching run timestamps. Every executed scenario requires a canonical immutable image digest; the mutable image tag is descriptive only.

The verifier also enforces semantic closure:

- repository, plan, frontier, result, and verdict mirrors equal their `run.json` values;
- `report.json` exactly mirrors the verified run, metrics are recomputed from results, and a claim ledger cannot assert `PASS` beyond those results;
- planned scenario IDs, result IDs, and scenario directories form the same exact set;
- environment, fetch/test/combined commands, phase records, raw summaries, logs, replay descriptor, and failure signature agree;
- typed test attempts are contiguous and agree with the final raw result/logs;
- verdicts are re-derived from typed attempts, including baseline rules, rerun/flaky rules, and fail-closed not-run/execution-error states;
- replay attempts are canonical, contiguous, complete, environment-bound, and reflected by the latest replay alias.

## Typed attempts and derived verdicts

`test-attempts.json` records a `TestExecutionStatus` and an ordered list of `TestAttemptRecord` values. Each record contains attempt number, exit code, timeout, duration, and optional normalized failure signature.

`result.json`, `verdicts.json`, and `run.json.results` are derived mirrors. The verifier recomputes classification from the attempts and rejects a result that contradicts the final attempt or promotes not-run/execution-error evidence. Terminal text and report badges never classify a run.

## Trusted report generation

`tomorrowci report` treats the bundle as a transaction:

1. Validate ancestors and fully verify before creating any lock or other file.
2. Acquire an exclusive per-run operation lock and fully verify again.
3. Load the manifest, verify again, and confirm that the loaded `run.json` bytes did not change.
4. Render the requested JSON, HTML, SARIF, or job summary into a temporary directory.
5. Replace only that selected report artifact.
6. Reject any unrelated evidence mutation, re-finalize exact v2 inventories, and fully verify again.
7. Restore the prior report/checksum state if the transaction fails.

HTML is generated from the bound manifest, strips ANSI control sequences, escapes untrusted strings, supplies text/ARIA verdict labels, preserves keyboard focus, and respects reduced-motion preferences.

SARIF is an optional SARIF 2.1.0 projection for observed future failures. It does not add evidence or strengthen the evidence grade.

## Trusted comparison

`tomorrowci compare` validates and verifies both roots before creating lock files, then acquires exclusive locks for base and head in deterministic path order, verifies both bundles again, loads each bound manifest/config, verifies again, and confirms that each byte sequence stayed stable. Only then may it derive the frontier delta or evaluate the verified head policy. A checksum-valid but semantically inconsistent bundle, a tampered report, an unresolved result, or a missing scenario yields no trusted gate.

## Replay extension

Replay validates ancestors and fully verifies before creating its lock, verifies again under the lock, takes a stable verified manifest read, and makes a fresh disposable copy from the recorded workspace snapshot. It requires the recorded engine identity, digest, timeouts, environment, and commands; the original repository and recorded snapshot are not execution targets. Replay reserves the next canonical attempt number before execution, writes result/stdout/stderr to staging, and atomically commits a complete `replays/attempt-N` directory. Failed fetches and execution errors are recorded as failed attempts. The latest mirror and checksum graph are updated, then full post-verification is required before replay can report a match; a post-commit failure restores the previous append/mirror/checksum state.

## Legacy read compatibility

Headerless checksum evidence is accepted only for the exact historical `0.1.1-alpha.2` tool/schema and its known legacy omissions. This is read compatibility, not authority to:

- write new legacy evidence;
- silently upgrade or re-finalize it as current-v2;
- accept a stripped v2 header as a downgrade;
- use legacy evidence as release qualification.

## Integrity versus authenticity

SHA-256 inventories detect changed, missing, extra, and internally contradictory evidence. They are unsigned: they do not authenticate the producer, registry publisher, CI host, or approver. A party able to replace the complete bundle can recompute the checksums. Independent signing/attestation and an external release trust root are separate requirements.

The container engine, registry/image provenance, package registries, and external qualification remain residual trust dependencies. This format does not qualify M2 dependency/ddmin, M3 full Node/Rust execution, M4 Action/UI, or M5 public release behavior.
