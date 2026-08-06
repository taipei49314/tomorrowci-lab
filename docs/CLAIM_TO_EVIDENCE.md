# Claim-to-evidence (Alpha.3 track)

Statuses: PASS / FAIL / BLOCKED / NOT_RUN only.

| Tag | Disposition |
|-----|-------------|
| v0.1.0 | REJECTED product candidate |
| v0.1.1-alpha.1 | REJECTED acceptance / live-path demonstration |
| v0.1.1-alpha.2 | REJECTED evidence-closure / successful release-pipeline demonstration |
| v0.1.1-alpha.3 | NOT_CREATED until mutation suite + self-verifying bundle |

Exact workflow run IDs and evidence hashes are emitted as `RELEASE_PROVENANCE.json` by the tag workflow (not hard-coded into a source commit that must still be tested).

| Claim | Status |
|---|---|
| Live Python vertical slice | PASS (prior public CI; re-proven on each CI) |
| Mutation-resistant verify | in progress (adversarial suite in tree) |
| Exact replay authorization | in progress |
| Self-verifying release bundle | NOT_RUN until tag workflow |
| Node/Rust/dep/ddmin/React/remote/image | NOT_RUN |
