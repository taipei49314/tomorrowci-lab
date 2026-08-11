# Support policy

## Platform qualification status

| Platform | CLI evidence | Container execution evidence |
|----------|--------------|------------------------------|
| Linux x86_64 | Deterministic `0.2.0-alpha.1` candidate archive built twice; candidate-only read-back **PASS** | Docker fixture slices plus the exact-SHA Python/Node/Rust public targets on Docker and Podman **PASS** as bounded project-owned observations |
| macOS x86_64 | Deterministic candidate archive built twice; support qualification **BLOCKED** | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| macOS arm64 | Deterministic candidate archive built twice; support qualification **BLOCKED** | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| Windows x86_64 | Deterministic candidate archive built twice; downloaded CLI/doctor/trust/evidence read-back **PASS**; support qualification **BLOCKED** | Docker Desktop Linux-engine clean-machine path **NOT_RUN** |

Candidate construction is not platform support acceptance. A `NOT_RUN` or
`BLOCKED` row remains a required qualification gate; see the run-bound
[qualification status](docs/qualification/STATUS.md). The dedicated
[platform protocol](docs/qualification/PLATFORM_PROTOCOL.md) defines the
fail-closed self-hosted execution and hosted read-back needed to change those
rows; merging that workflow alone is not a qualification result.

## Supported ecosystems

| Ecosystem | Package manager | Status |
|-----------|-----------------|--------|
| Python | pip | Runtime-axis Docker slice and one preregistered exact-SHA public target on hosted Linux Docker/Podman **PASS**; not ecosystem-wide support |
| Node.js | npm only | Bounded M2/M3 Docker slices and the preregistered Helmet exact-SHA target on hosted Linux Docker/Podman **PASS**; not ecosystem-wide support |
| Rust | cargo | Bounded M2/M3 Docker slices and the preregistered human-panic exact-SHA target on hosted Linux Docker/Podman **PASS**; not ecosystem-wide support |

Unsupported managers must return `UNSUPPORTED` — never silent fallback. `uv`,
yarn, pnpm, poetry, and pipenv are not qualified first-class managers.

The fixture PASS rows are limited to the repository-owned fixtures and
immutable images recorded in the [M2](docs/qualification/M2.md) and
[M3](docs/qualification/M3.md) records. The three preregistered public exact-SHA
targets and all six Docker/Podman pairs passed project-owned run `31480491950`
with replay and downloaded current-v2 read-back. None of these rows is an
ecosystem-wide compatibility, platform-support, or independent-adoption claim.

## What we do not support yet

- Public-remote qualification beyond the three preregistered exact commits and hosted Linux engine pair
- yarn / pnpm / poetry / pipenv as first-class managers
- Multi-tenant SaaS isolation guarantees
- Guaranteed production container breakout resistance

## Release support window

- **v0.1.x**: best-effort security fixes for 6 months after release
- Breaking changes require a minor/major bump and CHANGELOG entry

## Getting help

- GitHub Issues for bugs and feature requests
- Security issues: see `SECURITY.md`
