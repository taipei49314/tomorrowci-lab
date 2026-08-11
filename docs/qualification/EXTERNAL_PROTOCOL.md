# Independent external authorization protocol

Status: **implemented verification contract; no genuine authorization recorded**.
This protocol does not publish, tag, promote, consume an authorization, or
manufacture external evidence. Fixture keys and fixture evidence are test-only.

## Trust boundary

The verifier requires these independently supplied inputs:

1. a preregistered canonical policy and its independently recorded SHA-256;
2. a canonical authorization JSON document;
3. an OpenSSH detached `sshsig` over those exact authorization bytes;
4. a one-key OpenSSH `allowed_signers` trust root provisioned separately;
5. the exact candidate manifest and detached OCI provenance; and
6. strict canonical external qualification evidence.

`scripts/external_authorization.py` reads every security input exactly once
into an immutable byte snapshot. Digests, JSON parsing, semantic validation,
and signature verification use those same bytes. The validated
`allowed_signers` and signature snapshots are copied into a private temporary
directory before `ssh-keygen`; the original paths are never passed to the
subprocess. This prevents digest-then-parse, parse-then-signature, and
trust-root path replacement races.

The authorization's auditor principal grants no trust by itself. The exact
principal must be present in the preregistered policy, authorization, and sole
unoptioned Ed25519 `allowed_signers` record. The allowed-signers byte digest
must equal the policy digest, and `ssh-keygen -Y verify` must succeed in the
fixed `tomorrowci-release-v1` namespace.

The repository owner and slug for the external run must differ
case-insensitively from the candidate repository. Real-world key custody,
auditor independence, and whether the external repository is genuinely
controlled by that auditor remain organizational trust decisions.

## Preregistration

Before inspecting a qualification result, freeze a reviewed policy and record
its `sha256:<64 lowercase hex>` digest through an independent channel. The
required `--expected-policy-sha256` is that trust anchor; recomputing it from a
replacement policy at verification time is self-assertion.

The policy freezes:

- candidate repository, exact 40-hex commit, `refs/heads/master`, SemVer,
  candidate run ID/attempt, candidate-manifest digest, detached OCI provenance
  digest, and OCI image-manifest digest;
- external repository, exact 40-hex workflow commit, workflow path, run
  ID/attempt, engine, artifact name, authorization ID, and auditor principal;
- the allowed-signers digest and fixed namespace; and
- a UTC-second validity interval of at most seven days.

The authorization repeats the candidate and external policy objects, derives
the exact workflow ref and run URL, records an authorization interval of at
most 24 hours within the policy interval, and binds the evidence digest, size,
engine/version, and candidate image digest.

The CLI does not accept a caller-selected verification time. It uses the
system UTC clock. Unit tests may inject an aware `datetime` only through the
Python function API.

## Canonical JSON

Policy, authorization, and evidence use UTF-8 JSON with sorted keys, no
insignificant whitespace, no duplicate keys or non-finite values, and one
final LF:

```python
json.dumps(value, ensure_ascii=False, allow_nan=False,
           separators=(",", ":"), sort_keys=True) + "\n"
```

Unknown fields and loose scalar types are rejected at every defined object.

### Strict evidence v1

Evidence kind is `tomorrowci.external-qualification-evidence.v1`; top-level
`status` is exactly `PASS`. Its exact schema contains:

- `artifact_name`, equal to the preregistered artifact;
- `candidate.image_digest`, equal to the frozen OCI manifest digest;
- `engine.name` (`docker` or `podman`) and a nonempty exact version;
- `external.repository`, exact commit, workflow path/ref, run ID/attempt,
  derived run URL, and `conclusion: success`; and
- `qualification.result: PASS` plus exact `PASS` results for
  `candidate_image_pull`, `live_core`, `live_dependency`, `live_runtime`, and
  `socket_doctor`.

The evidence's external run, engine/version, artifact, and image fields are
cross-checked against the signed authorization. Arbitrary archives, prose,
partial JSON, failed conclusions, missing checks, and a different run or image
fail closed.

This verifier does not make a GitHub network request. The auditor's signature
authenticates the strict evidence assertion; public exact-run API/read-back
validation remains a separate qualification audit gate.

## Candidate and OCI binding

The actual candidate manifest and detached OCI provenance snapshots must match
the policy digests. Their strict kind, status, source, version, run/attempt,
unauthorized promotion state, and OCI manifest identity are validated against
the policy. The tag-promotion verifier subsequently reruns the full candidate
archive and OCI verifiers over a controlled candidate snapshot.

## Verification capability and receipt

A successful function call returns an immutable in-process
`VerifiedAuthorization`. The tag verifier requires this capability and cannot
accept a naked digest or arbitrary authorization file.

The capability exposes two deliberately different views:

- `stable_identity()`, containing only authorization, signature, policy,
  trust, evidence, candidate, and external-run identity; and
- `receipt()`, which adds the system-clock `verified_at` observation made by
  that invocation.

Only the time-independent stable identity may be embedded in a promotion
qualification index. Rechecking the same still-valid authorization at a later
system time therefore produces a different CLI observation but the same
promotion identity and the same index bytes.

The standalone CLI prints canonical receipt information including the exact
authorization and signature digests, policy/trust/evidence digests, candidate
and external identity, namespace/principal, and system verification time. Its
status is:

```text
VERIFIED_ONLY_NOT_CONSUMED_OR_PUBLISH_AUTHORITY
```

The printed receipt, including `verified_at`, is an audit observation, not a
serialized capability and not publication authority.

```text
python scripts/external_authorization.py \
  --authorization external-authorization.json \
  --signature external-authorization.json.sig \
  --policy preregistered-policy.json \
  --expected-policy-sha256 sha256:POLICY_DIGEST \
  --allowed-signers independently-provisioned-allowed-signers \
  --candidate-manifest candidate-manifest.json \
  --oci-provenance image-provenance.json \
  --evidence external-qualification-evidence.json
```

## Replay and promotion state are not closed here

This verifier deliberately has no caller-supplied "consumed IDs" ledger. An
empty or rolled-back local JSON file cannot provide replay protection.

Formal release still needs a protected promotion transaction that atomically:

1. proves the remote tag and release do not already exist;
2. serializes concurrent promotion attempts;
3. creates a new, non-overwritable consumption record for this authorization;
4. promotes only the already-verified bytes, without rebuilding; and
5. downloads/pulls the published outputs and verifies them again.

Until that remote transaction exists and passes, replay prevention,
tag/release nonexistence, promotion concurrency, and publication remain
explicitly **not closed**.
