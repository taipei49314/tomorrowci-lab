# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI finds the earliest **concrete** future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits **replayable evidence**.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**TomorrowCI is an experimental pre-alpha architecture under evidence-and-release closure.**

| Area | Status | Notes |
|------|--------|--------|
| Live Python runtime vertical slice | **PASS** (demonstrated) | Real Docker path on public CI; see claim ledger |
| Live report (minimum static) | **in closure** | Real digests; Phase F links/tests in alpha.2 track |
| Action dogfood + consumer | **PASS** (alpha.1 demonstrated; re-prove on final alpha.2 commit) | `uses: ./action` |
| Evidence integrity + exact replay | **in closure** | alpha.1 operational replay accepted; exact-manifest incomplete |
| Release gate | **in closure** | alpha.1 rejected for premature tag / weak release workflow |
| Node / Rust live adapters | **NOT_RUN** | Out of alpha.2 scope |
| Dependency axis / real ddmin | **NOT_RUN** | Out of alpha.2 scope |
| React/TypeScript interactive report | **NOT_RUN** | Out of alpha.2 scope |
| Remote GitHub URL scan | **NOT_RUN** | Out of alpha.2 scope |
| Container image publish | **NOT_RUN** | Must not be implied by release |

### Tags (audit history)

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | **REJECTED** product candidate — scripted acceptance; red CI |
| `v0.1.1-alpha.1` | **REJECTED acceptance candidate** / live-path demonstration — Python slice real; evidence envelope + release gate incomplete ([audit note](docs/audits/v0.1.1-alpha.1-rejection.md)) |
| `v0.1.1-alpha.2` | **NOT_CREATED** until every alpha.2 closure gate passes |

Full matrix: [docs/CLAIM_TO_EVIDENCE.md](docs/CLAIM_TO_EVIDENCE.md).

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
