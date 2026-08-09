# Qualification baseline

Recorded on 2026-08-09 (Asia/Taipei) before product-code changes on
`agent/alpha2-trust-core-generalization`.

## Live repository state

| Subject | Observed value |
|---|---|
| Repository | `taipei49314/tomorrowci-lab` |
| Default branch | `master` |
| Default/source SHA | `1e23b40157e55e5763e3360b667d10a003b50ff9` |
| Kickoff SHA | `1e23b40157e55e5763e3360b667d10a003b50ff9` (no drift) |
| Default CI | [run 31299997719](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31299997719), success at the exact default SHA |
| Open pull requests / issues | `0 / 0` |
| Local checkout | clean before qualification commands; full history and tags fetched |

The default run's `rust`, `live-python`, `action-dogfood`, and
`action-consumer` jobs all completed successfully. That run establishes the
published alpha.2 Python slice; it does not establish any row that remains
`NOT_RUN` in the claim ledger.

## Local source replay

The Windows checkout used Git `core.autocrlf=true`; Docker CLI was installed
but its daemon was unavailable, and Podman was not installed.

| Command | Exit/result |
|---|---|
| `python scripts/check-text-encoding.py` | **FAIL**: `scripts/release-dry-run.sh: CRLF forbidden in Unix shell scripts`; the repository had no `.gitattributes` contract |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace` | PASS: 45 passed, 0 failed, 0 ignored |
| `cargo build -p tomorrowci-cli --release` | PASS |
| `node --test packages/report-ui/test/*.test.js` | PASS: 3 passed |
| `bash -n scripts/release-dry-run.sh` | NOT_RUN: the installed `bash` was an unusable WSL shim without `/bin/bash` |
| `target/release/tomorrowci.exe --version` | PASS: `tomorrowci 0.1.1-alpha.2` |
| `target/release/tomorrowci.exe trust` | PASS; engine-honesty probe reported infrastructure-only BLOCKED |
| `target/release/tomorrowci.exe doctor` | structured BLOCKED for container execution; no silent host execution |

A negative-control scan without an engine returned `verdict: BLOCKED` and exit
2, as required, but left run `3c574e2b2969` incomplete. `verify` rejected that
run because ten required files were missing. Its workspace manifest also used
malformed `sha256:sha256:<hex>` values. Both findings are tracked as trust-core
defects rather than being counted as live acceptance.

Later in the session Docker Desktop became responsive. Windows live replay then
found two additional real portability defects rather than being promoted to a
PASS: run `0355631f270d` recorded Docker rejecting the canonical `\\?\C:` bind
path, and after that mount path was normalized, run `90e3ab378232` recorded a
300-second timeout while creating a Python venv on the Windows bind mount. Both
BLOCKED bundles pass the current v2 structural verifier, but neither authorizes
a horizon. The timed-out container was stopped and the sandbox now assigns an
exact container name and force-cleans it after a timeout. Windows Docker
Desktop qualification remains open pending a bounded state-volume design and
successful clean-machine replay.

## Trust-core branch validation before review

After the schema-2 trust-core changes, the complete local source gate passed:

- `cargo test --workspace`: 89 passed, 0 failed;
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS;
- `cargo fmt --all -- --check`, encoding, Action pin, version, release metadata,
  config-schema, historical-regression, exact-SBOM, Node helper, Bash syntax,
  PowerShell AST, and YAML parse gates: PASS;
- release CLI build and exact version `0.2.0-alpha.1`: PASS;
- `tomorrowci trust`: 8/8 PASS; `tomorrowci doctor`: READY with Docker 29.6.2.

The required live outcome is still not overstated. Windows Docker run
`f55ff9cd60a4` returned exit 2 / `BLOCKED` after the 300-second fetch timeout
while creating the bind-mounted Python venv. Its complete schema-2 bundle
passed `verify` (`39` files, `current_v2`). This confirms fail-closed evidence
finalization, not Python live qualification; the Linux Docker job remains the
required PR/default-CI acceptance.

## Historical tag and release identity

| Tag | Annotated tag object | Peeled commit | Disposition |
|---|---|---|---|
| `v0.1.0` | `febe7a3a37a97912bbe8c89e11d27c28c38d250e` | `7a08c4884761b70e9ae0e63012ee87fdc1e39348` | REJECTED historical product candidate |
| `v0.1.0-grok-session` | `39011d3bbc30ad943e5e81ef70017fd535942092` | `7a08c4884761b70e9ae0e63012ee87fdc1e39348` | REJECTED historical parallel candidate; GitHub still selects it as Latest because it is the newest non-prerelease |
| `v0.1.1-alpha.1` | `55a3e8e89b08cccfafcb64fd26fada4cd1f0fcea` | `63a19ac73ee066a4acfe5d747291e974dcb744c2` | REJECTED acceptance candidate; live Python observation retained |
| `v0.1.1-alpha.2` | `7fa0e274dc7e74c024da71fff022b18f0835aab8` | `167b94f9ce5c0fe95b9105abb71d26386b4fe9e3` | published measured lab prerelease |

On 2026-08-09, the `v0.1.0` and `v0.1.0-grok-session` GitHub release
titles and notes were corrected non-destructively to lead with `REJECTED` and
link the repository audit. The original notes, tags, and assets were retained.

The historical `release.yml` workflow ID `328349175` was also disabled after
an audit showed that dispatching an old tag ref could otherwise select its
former `contents: write` publishing code. No unsafe dispatch was performed;
candidate construction is moving to a new, read-only workflow path. See the
[workflow retirement record](../audits/2026-08-09-historical-release-workflow-retirement.md).

The alpha.2 identity layers are distinct and must not be collapsed:

- `bced9c070bbb9a64c63301ec23b2610c2b79f011` is the package/action
  candidate tested by successful CI run
  [31080022232](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31080022232).
- `167b94f9ce5c0fe95b9105abb71d26386b4fe9e3` is the child documentation
  commit selected by annotated tag `v0.1.1-alpha.2`; successful release run
  [31080456557](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31080456557)
  built and published from this tagged commit.
- `1e23b40157e55e5763e3360b667d10a003b50ff9` is the later default-branch
  truth-reconciliation commit and is covered by default CI run 31299997719.

## Alpha.2 clean download/read-back

All five published assets were downloaded into a new directory. The three
archive hashes matched `SHA256SUMS.txt`:

| Asset | SHA-256 / observation |
|---|---|
| `tomorrowci-v0.1.1-alpha.2-x86_64-apple-darwin.tar.gz` | `584b1a0c3ceaff4800b02f8e40b490e0a8f403672cbcc467784961a75deb56d6` |
| `tomorrowci-v0.1.1-alpha.2-x86_64-unknown-linux-gnu.tar.gz` | `7845b58aa1b90514c9871266f567fde12ae0622192fe447f821ed99c362aa16c` |
| `tomorrowci-v0.1.1-alpha.2-x86_64-pc-windows-msvc.zip` | `0d16f659ecb5ffe428ebdefeae67a094f2e3f8198a11e21964a70315ae827e69` |
| `SHA256SUMS.txt` | contains and verifies exactly the three platform archives |
| `sbom.cdx.json` | CycloneDX 1.5, application `0.1.1-alpha.2`, 104 components; all 104 dependency versions are the placeholder `locked` |

The Windows archive extracted cleanly. Its binary reported version
`0.1.1-alpha.2`, passed `trust`, and reported an honest no-engine BLOCKED state
from `doctor`. The placeholder SBOM versions mean this historical asset does
not satisfy the new exact-dependency release contract.

## Qualification boundary

No local no-engine result is counted as live acceptance. The machine-readable
open work is maintained in [`backlog.json`](backlog.json). A new tag or stable
release is forbidden until the exact merged default SHA, platform/engine
matrix, OCI candidate, external protocol, and independent external gate all
pass.
