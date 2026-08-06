# Claim-to-evidence matrix (alpha.2 closure track)

Statuses: **PASS** / **FAIL** / **BLOCKED** / **NOT_RUN** only.

Historical tags preserved:

- `v0.1.0` — REJECTED product candidate
- `v0.1.1-alpha.1` — REJECTED acceptance candidate / live-path demonstration ([audit](audits/v0.1.1-alpha.1-rejection.md))

Update this table only after the **exact final alpha.2 commit** is green. Until then, treat alpha.2 gates as **NOT_RUN**.

| Claim | Status | Exact command / run | Exit / result | Artifact |
|---|---|---|---|---|
| Public truth on default branch | **NOT_RUN** | merge README + audits to `master` | pending | GitHub default branch |
| fmt/clippy/test + encoding | **NOT_RUN** | CI on final SHA | pending | Actions |
| Live Python scan | **NOT_RUN** | `tomorrowci scan fixtures/python-runtime-break …` | pending | run id on final SHA |
| `tomorrowci verify` | **NOT_RUN** | `tomorrowci verify <run-id>` | pending | verify JSON |
| Replay ×2 independent attempts | **NOT_RUN** | `replay` twice | pending | `replays/attempt-{1,2}/` |
| Action dogfood + consumer git repo | **NOT_RUN** | CI jobs | pending | Actions |
| Tag `v0.1.1-alpha.2` | **NOT_CREATED** | only after every gate PASS | — | — |
| Node / Rust live / ddmin / React / remote / image | **NOT_RUN** | out of scope | — | — |

Package version in source: **0.1.1-alpha.2**.
