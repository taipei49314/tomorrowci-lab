# External target execution contract

The original result-blind target preregistration remains byte-for-byte frozen
at `sha256:1f9dee08d03f5f07b8c7f4396d6a0d3ee3aeb2b3071914e26d0a32f6e8b79ace`.
Its `NOT_RUN` status means that the preregistration document is not result
authority; it is not a claim that nobody has attempted the targets.

Repository run
[31467337605](https://github.com/taipei49314/tomorrowci-lab/actions/runs/31467337605)
executed all six frozen target/engine pairs. Python and Rust succeeded on
Docker and Podman. Helmet failed its baseline on both engines because the exact
frozen `npm run test:node` command invokes `git ls-files`, while the disposable
exact-remote snapshot intentionally contained source bytes but no `.git`.
The immutable [failed observation](observations/2026-08-11-run-31467337605.json)
retains the run, jobs, available artifacts, and missing Node artifacts. It is a
failed observation, not accepted qualification.

The [infrastructure amendment](infrastructure-amendment-v1.json) does not
change any target ID, source commit, config digest, or test command. For every
exact-remote disposable scenario it derives a deterministic Git index from the
verified `workspace-manifest.json` and the same exact file bytes. The installed
metadata provides only `git ls-files` path enumeration. It has no commits,
history, hooks, remotes, credentials, object files, or ref files; file modes and
other Git-history semantics are not promised. The authoritative evidence
workspace still contains no `.git`.

`remote-source.json` schema v2 binds the synthetic-index digest, entry count,
workspace-manifest digest, absent capabilities, and the exact runner-provided
allowlist of `GIT_*` variables including `safe.directory=/work`. Replay rederives
and compares the same index before target execution. Generic CLI verification
retains read-only compatibility for historical schema-v1 bundles, but v1 is
not accepted by the repository external-qualification validator and cannot be
replayed by the amended runner. New qualification authority requires schema v2.

Every matrix job uploads a separately named `raw-external-observation-*`
artifact even when scan or a later verification/replay phase fails. Its
non-authoritative record binds the candidate and workflow identities, final
qualification-step phase/exit, scan exit, and byte-rederived transcript digest,
size, and run IDs; any partial `.tomorrowci` tree is copied into the same raw
artifact. The bounded six-artifact read-back summary reports step failures but
is diagnostic only. The canonical project-owned PASS summary remains gated on
six strictly validated `external-qualification-*` artifacts.
