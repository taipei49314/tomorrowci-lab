# Evidence authority map (Alpha.3 RC2)

Every fact has exactly one canonical owner. Derived mirrors must byte/typed-equal the owner. Rehashing after coherent multi-file forgery must still fail semantic checks.

| Fact | Canonical owner | Derived mirrors (must match) |
|---|---|---|
| run_id | `run.json.run_id` | directory name, `evidence-index.run_id` |
| scenario identity | `run.json.plan.scenarios[]` | `scenarios/<id>/scenario.json`, directory names, `results[]` |
| environment | `scenarios/<id>/environment.json` | `run.json.results[].environment`, `replay.json` env fields |
| fetch/test commands | `scenarios/<id>/replay.json` (typed) | `fetch-commands.json`, `test-commands.json`, `commands.json`, result.commands |
| result/verdict/exit | `scenarios/<id>/result.json` | `run.json.results[]`, frontier when applicable |
| failure signature | `scenarios/<id>/failure-signature.json` | result.failure, frontier.failure_signature, replay expectation |
| config hash | bytes of `config.normalized.json` | `run.json.config_hash`, `identity.config_hash`, replay manifest |
| manifest/lock hashes | workspace file bytes | `identity.manifest_hashes` |
| source snapshot | `workspace/` + `workspace-manifest.json` | identity dirty/commit policy |
| replay attempt | `replays/attempt-N/result.json` + logs | report links, attestation notes |
| inventory | `evidence-index.json` | `checksums.txt` (index paths ∪ index file) |

## Forbidden authorities

- `scenarios/*/checksums.txt` — not written; if present → verify FAIL
- Attestation under `attestations/` — external to payload inventory; if present must pass attestation inventory rules
- Report HTML — derived; links must resolve to indexed payload (or typed attestation)

## Hash form

Only `sha256:` + 64 **lowercase** hex. Uppercase prefix/hex is non-canonical FAIL.
