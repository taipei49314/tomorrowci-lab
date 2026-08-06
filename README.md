# TomorrowCI

> **Continuous Integration Against the Future.**

```text
No forecast without an executable scenario.
No breakage claim without replayable evidence.
```

## Product status (evidence-based)

**TomorrowCI is an experimental pre-alpha under verifier/provenance closure (Alpha.3).**

| Area | Status |
|------|--------|
| Live Python runtime vertical slice | **PASS** (demonstrated since alpha.1) |
| Public CI / Action dogfood / consumer git repo | **PASS** (demonstrated since alpha.2) |
| Multi-platform gated release pipeline | **PASS** (demonstrated since alpha.2) |
| Mutation-resistant evidence verifier | **in Alpha.3** |
| Exact replay authorization | **in Alpha.3** |
| Self-verifying release bundle + provenance | **in Alpha.3** |
| Node / Rust live / dependency / ddmin / React / remote / image | **NOT_RUN** |

### Tags (audit history)

| Tag | Disposition |
|-----|-------------|
| `v0.1.0` | REJECTED product candidate |
| `v0.1.1-alpha.1` | REJECTED acceptance / live-path demonstration |
| `v0.1.1-alpha.2` | REJECTED evidence-closure / successful release-pipeline demonstration ([audit](docs/audits/v0.1.1-alpha.2-rejection.md)) |
| `v0.1.1-alpha.3` | **NOT_CREATED** — RC1 rejected (semantic false-PASS); RC2 track `repair/alpha3-semantic-authority-rc2` |

Exact release facts (workflow run IDs, evidence hashes) are **not** hard-coded into source commits. They are emitted as `RELEASE_PROVENANCE.json` by the tag workflow.

## Quick start

```bash
cargo build -p tomorrowci-cli --release
./target/release/tomorrowci scan fixtures/python-runtime-break \
  --config fixtures/python-runtime-break/.tomorrowci.yml --json
./target/release/tomorrowci verify <run-id> --json
```

## License

Apache-2.0
