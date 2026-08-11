# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI aims to find the earliest **concrete** future environment in which a
repository stops building or passing tests, isolate the smallest
breakage-inducing change, and emit **replayable evidence**. The currently
demonstrated public slices are the Python runtime path and a bounded Linux
Docker dependency-reduction path for pip, npm, and cargo; wider product
surfaces remain explicit qualification work.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**TomorrowCI is an experimental pre-alpha architecture. The measured
`v0.1.1-alpha.2` lab release is published; broader product qualification is
still in progress.**

Current source is the unreleased `0.2.0-alpha.1` trust-core development line.
Its M2 dependency/ddmin slice passed at exact master commit
`456a36edb1e8547612cd13ee7a30be3479d33bab`; that observation is not a
release, broad platform-support, or external-qualification claim.

The current live baseline, historical tag identities, clean-download checks,
and honest blockers are recorded in
[`docs/qualification/BASELINE.md`](docs/qualification/BASELINE.md). Open
qualification work is machine-readable in
[`docs/qualification/backlog.json`](docs/qualification/backlog.json).

| Area | Status | Notes |
|------|--------|--------|
| Live Python runtime vertical slice | **PASS** (demonstrated) | Real Docker path on public CI; see claim ledger |
| Live report (minimum static) | **in closure** | Real digests; Phase F links/tests in alpha.2 track |
| Action dogfood + consumer | **PASS** (alpha.2 demonstrated) | `uses: ./action`; public CI evidence in the claim ledger |
| Evidence integrity + exact replay | **PASS** (bounded alpha.2 scope) | `verify` plus two independent replay attempts passed |
| Release gate | **PASS** (alpha.2 scope) | Three platform archives, checksums, and CycloneDX SBOM published |
| Linux Docker dependency axis / observed ddmin | **PASS** (bounded M2 scope) | Native pip/npm/cargo fixtures; scan, verify, minimal replay x2, and downloaded-artifact read-back passed at exact master `456a36e...`; see [M2 qualification](docs/qualification/M2.md) |
| M3 Node/Rust runtime + Podman/platform expansion | **NOT_RUN** | The M2 dependency fixtures do not qualify these broader surfaces |
| React/TypeScript interactive report | **NOT_RUN** | Out of alpha.2 scope |
| Remote GitHub URL scan | **NOT_RUN** | Out of alpha.2 scope |
| Container image publish | **NOT_RUN** | Must not be implied by release |

### Tags (audit history)

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | **REJECTED** product candidate — scripted acceptance; red CI |
| `v0.1.0-grok-session` | **REJECTED** historical parallel candidate — same peeled commit as `v0.1.0`; GitHub release metadata corrected without moving the tag or assets |
| `v0.1.1-alpha.1` | **REJECTED acceptance candidate** / live-path demonstration — Python slice real; evidence envelope + release gate incomplete ([audit note](docs/audits/v0.1.1-alpha.1-rejection.md)) |
| `v0.1.1-alpha.2` | **PUBLISHED MEASURED LAB RELEASE** — Python live path, verify, replay ×2, Action dogfood, and release assets passed; Node/Rust live and the other `NOT_RUN` rows remain unclaimed |

Full matrix: [docs/CLAIM_TO_EVIDENCE.md](docs/CLAIM_TO_EVIDENCE.md). GitHub
currently selects the rejected `v0.1.0-grok-session` as “Latest” because it is
the newest historical non-prerelease; the title and notes now lead with its
rejected disposition so this metadata behavior is not an acceptance claim.

## Quick start

**Prerequisites:** Rust toolchain; **Docker or Podman daemon** for live scans.

```bash
git clone https://github.com/taipei49314/tomorrowci-lab
cd tomorrowci-lab
cargo build -p tomorrowci-cli --release

./target/release/tomorrowci doctor
./target/release/tomorrowci trust
./target/release/tomorrowci scan fixtures/python-runtime-break \
  --config fixtures/python-runtime-break/.tomorrowci.yml
./target/release/tomorrowci verify <run-id>
```

Without a container daemon, `scan` returns **BLOCKED** (not a silent host run).

## Tree immutability contract

**Target source files under the scanned path are not modified by scenario execution.**  
Evidence is written under `<scan-root>/.tomorrowci/runs/` (and is **excluded** from the immutability claim). Disposable workspace copies are used for container mounts.

## CLI

```bash
tomorrowci doctor
tomorrowci trust
tomorrowci scan <path> [--config .tomorrowci.yml]
tomorrowci verify <run-id>
tomorrowci show <run-id>
tomorrowci replay <run-id> --scenario <id>
tomorrowci explain <run-id>
tomorrowci report <run-id> --format html|json|sarif|summary
tomorrowci metrics <run-id>
tomorrowci compare --base <id> --head <id> [--gate]
tomorrowci init-action
```

## License

Apache-2.0 — see [LICENSE](LICENSE)
