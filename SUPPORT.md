# Support policy

## Platform qualification status

| Platform | CLI evidence | Container execution evidence |
|----------|--------------|------------------------------|
| Linux x86_64 | Deterministic `0.2.0-alpha.1` candidate archive built twice; candidate-only read-back **PASS** | Docker: measured Python runtime, bounded M2 pip/npm/cargo dependency reduction, and bounded M3 Node/Rust runtime slices **PASS**; Podman **NOT_RUN** |
| macOS x86_64 | Deterministic candidate archive built twice; support qualification **BLOCKED** | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| macOS arm64 | Deterministic candidate archive built twice; support qualification **BLOCKED** | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| Windows x86_64 | Deterministic candidate archive built twice; downloaded CLI/doctor/trust/evidence read-back **PASS**; support qualification **BLOCKED** | Docker Desktop Linux-engine clean-machine path **NOT_RUN** |

Candidate construction is not platform support acceptance. A `NOT_RUN` or
`BLOCKED` row remains a required qualification gate; see the run-bound
[qualification status](docs/qualification/STATUS.md).

## Supported ecosystems

| Ecosystem | Package manager | Status |
|-----------|-----------------|--------|
| Python | pip | Runtime-axis Docker slice demonstrated; bounded M2 Linux Docker dependency/ddmin **PASS** at exact master `456a36e...` |
| Node.js | npm only | Bounded M2 dependency/ddmin and M3 Node 20→22/24 runtime Linux Docker slices **PASS**; Podman and broader platform qualification **NOT_RUN** |
| Rust | cargo | Bounded M2 dependency/ddmin and M3 declared-MSRV Rust 1.83→1.74 Linux Docker slices **PASS**; Podman and broader platform qualification **NOT_RUN** |

Unsupported managers must return `UNSUPPORTED` — never silent fallback. `uv`,
yarn, pnpm, poetry, and pipenv are not qualified first-class managers.

The M2/M3 PASS rows are limited to the repository-owned fixtures and immutable
images recorded in the [M2](docs/qualification/M2.md) and
[M3](docs/qualification/M3.md) records. The three public exact-SHA targets and
their Docker/Podman pairs are preregistered but **NOT_RUN**. None of these rows
is an ecosystem-wide compatibility or independent-adoption claim.

## What we do not support yet

- Public-remote Docker/Podman qualification for bounded exact-commit GitHub scans
- yarn / pnpm / poetry / pipenv as first-class managers
- Multi-tenant SaaS isolation guarantees
- Guaranteed production container breakout resistance

## Release support window

- **v0.1.x**: best-effort security fixes for 6 months after release
- Breaking changes require a minor/major bump and CHANGELOG entry

## Getting help

- GitHub Issues for bugs and feature requests
- Security issues: see `SECURITY.md`
