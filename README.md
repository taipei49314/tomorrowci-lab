# TomorrowCI

> **Continuous Integration Against the Future.**

TomorrowCI finds the earliest **concrete** future environment in which a repository stops building or passing tests, isolates the smallest breakage-inducing change, and emits **replayable evidence**.

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**TomorrowCI is an experimental pre-alpha architecture under live-path validation.**

| Area | Status | Notes |
|------|--------|--------|
| M0 Repository contract | **partial** | Workspace, schema, docs exist; claims corrected after audit |
| M1 Python vertical slice | **in repair** | Live Docker path required; scripted tests ≠ acceptance |
| M2 Planner / deps / ddmin / flaky | **NOT_RUN** (live) | Scripted classifier only; real ddmin not acceptance |
| M3 Node + Rust adapters | **NOT_RUN** | Out of current repair scope |
| M4 Action + report + compare | **partial / FAIL dogfood** | Action must use `uses: ./action`; React UI **NOT_RUN** |
| M5 Release candidate | **rejected for v0.1.0** | Tag preserved; not a verified product release |

Tag **`v0.1.0`** is a **lab / pre-alpha candidate** whose **live container path was unverified**. Independent forensic audit: **REJECT**. See [docs/audits/v0.1.0-rejection.md](docs/audits/v0.1.0-rejection.md).

Repair branch target: `repair/real-python-vertical-slice` → candidate **`v0.1.1-alpha.1`** only after the alpha acceptance checklist passes.

Full matrix: [docs/CLAIM_TO_EVIDENCE.md](docs/CLAIM_TO_EVIDENCE.md).

## What it is / is not

| TomorrowCI | Not TomorrowCI |
|---|---|
| Tests against real runtime/dependency candidates | A dependency update PR bot |
| OBSERVED / SIMULATED / SCHEDULED_RISK / INCONCLUSIVE grades | Invented future APIs |
| Sandboxed execution (Docker/Podman) | Default host execution of untrusted code |
| Typed verdicts (`BLOCKED` ≠ `PASS`) | Collapsing everything into FAIL/PASS |
| Local-first, no telemetry, no cloud account | A SaaS-only scanner |

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
```

Without a container daemon, `scan` returns **BLOCKED** (not a silent host run).

Scripted demo HTML ( **not** acceptance evidence ):

```bash
cargo run -p tomorrowci-gen-demo
# open examples/reports/python-runtime-break/report.html
```

## CLI

```bash
tomorrowci doctor
tomorrowci trust
tomorrowci scan <path> [--config .tomorrowci.yml]
tomorrowci show <run-id>
tomorrowci replay <run-id> --scenario <id>
tomorrowci explain <run-id>
tomorrowci report <run-id> --format html|json|sarif|summary
tomorrowci metrics <run-id>
tomorrowci compare --base <id> --head <id> [--gate]
tomorrowci init-action
```

## Configuration

Schema: `packages/schema/tomorrowci-config.schema.json`  
Example: `fixtures/python-runtime-break/.tomorrowci.yml`

## Fixtures

| Fixture | Intent | Acceptance status |
|---------|--------|-------------------|
| `fixtures/python-runtime-break` | Stdlib break on newer Python | **repair acceptance target** (live Docker) |
| `fixtures/python-dependency-break` | Dependency-axis (incomplete / simulated) | **NOT_RUN** |
| `fixtures/node-dependency-break` | Node runtime API | **NOT_RUN** |
| `fixtures/rust-msrv-break` | Older rustc | **NOT_RUN** |

## GitHub Action

Composite action: [`action/action.yml`](action/action.yml)

Must be dogfooded via `uses: ./action` in public CI. Building the CLI from a **consumer** repository is supported by building from `${{ github.action_path }}/..` with an isolated target dir (or a release binary + checksum).

## Security

- Target code is **never** executed on the host by default
- No privileged containers; no docker.sock into the target
- Residual container escape risk: [docs/threat-model](docs/threat-model/README.md)
- Untrusted report HTML is escaped; see `SECURITY.md`

## Documentation

- [Claim-to-evidence](docs/CLAIM_TO_EVIDENCE.md)
- [v0.1.0 rejection audit notes](docs/audits/v0.1.0-rejection.md)
- [Architecture](docs/architecture/README.md)
- [Threat model](docs/threat-model/README.md)
- [Release](docs/RELEASE.md)
- [ADRs](docs/adr/)

## License

Apache-2.0 — see [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
