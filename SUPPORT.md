# Support policy

## Platform qualification status

| Platform | CLI evidence | Container execution evidence |
|----------|--------------|------------------------------|
| Linux x86_64 | alpha.2 archive + public CI build | Docker: measured Python runtime, bounded M2 pip/npm/cargo dependency reduction, and bounded M3 Node/Rust runtime slices **PASS**; Podman **NOT_RUN** |
| macOS x86_64 | alpha.2 archive built on public CI | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| macOS arm64 | source-build support target retained; exact runner evidence **BLOCKED** | Docker Desktop / Colima clean-machine path **NOT_RUN** |
| Windows x86_64 | alpha.2 archive extracted and CLI/trust read back on 2026-08-09 | Docker Desktop Linux-engine clean-machine path **NOT_RUN** |

These rows retain the declared support scope. A `NOT_RUN` or `BLOCKED` row is
not support acceptance; it is a required qualification gate.

## Supported ecosystems

| Ecosystem | Package manager | Status |
|-----------|-----------------|--------|
| Python | pip | Runtime-axis Docker slice demonstrated; bounded M2 Linux Docker dependency/ddmin **PASS** at exact master `456a36e...` |
| Node.js | npm only | Bounded M2 dependency/ddmin and M3 Node 20→22/24 runtime Linux Docker slices **PASS**; Podman and broader platform qualification **NOT_RUN** |
| Rust | cargo | Bounded M2 dependency/ddmin and M3 declared-MSRV Rust 1.83→1.74 Linux Docker slices **PASS**; Podman and broader platform qualification **NOT_RUN** |

Unsupported managers must return `UNSUPPORTED` — never silent fallback. `uv`,
yarn, pnpm, poetry, and pipenv are not qualified first-class managers.

The M2 PASS is limited to the repository-owned fixtures and immutable images
recorded in [the M2 qualification record](docs/qualification/M2.md). It is not
an ecosystem-wide compatibility or independent-adoption claim.

## What we do not support yet

- Remote `scan https://github.com/...` full clone flow
- yarn / pnpm / poetry / pipenv as first-class managers
- Multi-tenant SaaS isolation guarantees
- Guaranteed production container breakout resistance

## Release support window

- **v0.1.x**: best-effort security fixes for 6 months after release
- Breaking changes require a minor/major bump and CHANGELOG entry

## Getting help

- GitHub Issues for bugs and feature requests
- Security issues: see `SECURITY.md`
