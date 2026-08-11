# Annotated-tag promotion qualification index

Status: implemented promotion-eligibility contract; **not publication
authority**.

`scripts/tag_promotion_attestation.py` verifies that one prospective annotated
version tag, one frozen release-candidate inventory, and one complete external
authorization verification refer to exactly the same source and bytes. It
cannot create or push a tag, publish a GitHub Release, upload assets, or push
an OCI image.

## No naked authorization digest

The tag verifier does not accept
`--trusted-external-authorization-sha256`. Its CLI requires the authorization,
SSH signature, preregistered policy and digest, independently provisioned
allowed-signers trust root, and strict evidence. It invokes the full external
verifier in the same process and passes the resulting immutable
`VerifiedAuthorization` capability directly into tag qualification.

Supplying arbitrary bytes plus their own digest, copying a digest out of an
index, or adding `authorized: true` cannot create that capability. A corrupted
signature, wrong policy anchor, replaced trust root, expired authorization, or
false evidence fails before the tag index is examined.

## Immutable candidate snapshot

Every immediate candidate asset is read once as a regular non-symlink file
into a byte snapshot. The candidate and OCI verifiers run over a private
materialization of those snapshots. The qualification index, asset inventory,
candidate-manifest digest, OCI provenance digest, and OCI manifest identity are
all derived from the same bytes.

The external capability's candidate repository, source commit, version,
run/attempt, candidate-manifest digest, OCI provenance digest, and OCI manifest
digest must match that snapshot exactly.

The index embeds only `VerifiedAuthorization.stable_identity()`. It never
embeds the invocation-specific `verified_at` observation. A later valid
system-clock verification of identical authorization inputs must therefore
verify the same index without rewriting it.

The index kind is
`tomorrowci.tag-promotion-qualification-index.v1`; its status is
`ELIGIBLE_ONLY_NOT_PUBLISH_AUTHORITY`. It is canonical UTF-8 JSON with sorted
keys, two-space indentation, and one final LF. Duplicate keys, non-finite
numbers, unknown fields through recomputation, loose JSON types, malformed
digests, unsafe filenames, missing/extra assets, symlinks, directories, empty
files, and byte drift fail closed.

The exact release asset inventory is the candidate payload plus
`candidate-manifest.json` and `SHA256SUMS.txt`, sorted by name.

## Annotated tag requirements

For candidate version `<version>`, the local repository must contain
`refs/tags/v<version>` as an annotated Git `tag` object. The index binds both
the tag object SHA and peeled commit. The ref's object SHA is captured first;
all type, header, target, and peel operations then use that immutable object
SHA, never the movable ref. The raw tag object must have exactly canonical
`object`, `type commit`, matching internal `tag`, and valid `tagger` headers.
Its direct target must equal `object_sha^{commit}`, and the ref must still name
the captured object at the end of inspection. The final check also requires
the ref to remain direct rather than becoming a symbolic alias to the same
object.

Every tag-identity Git plumbing command runs with `--no-replace-objects`.
Repository-local `refs/replace/*` therefore cannot substitute tag contents,
target type, or peel results while retaining the captured object ID.

After reading the raw tag body, the verifier reconstructs Git's exact object
framing (`b"tag " + decimal_length + b"\0" + raw_body`), recomputes its SHA-1,
and requires it to equal the captured 40-hex object ID before decoding or
parsing headers. A transient object-store substitution with the same target
but different tagger or message therefore cannot be mixed with the captured
identity.

A lightweight tag, tag-to-tag alias, mismatched internal tag name, ref swap,
wrong version, malformed header, different tag object, tag peeled to another
commit, or candidate source mismatch fails.

The verifier does not create or mutate the tag. A local passing tag fixture
does not authorize pushing that object.

## Verification

```text
python scripts/tag_promotion_attestation.py \
  --attestation tag-promotion-attestation.json \
  --git-repo . \
  --candidate-dir downloaded-candidate \
  --authorization external-authorization.json \
  --signature external-authorization.json.sig \
  --policy preregistered-policy.json \
  --expected-policy-sha256 sha256:POLICY_DIGEST \
  --allowed-signers independently-provisioned-allowed-signers \
  --evidence external-qualification-evidence.json
```

A pass proves only local promotion eligibility for exact bytes. The embedded
external receipt status remains
`VERIFIED_ONLY_NOT_CONSUMED_OR_PUBLISH_AUTHORITY`.

The regression suite includes a no-mock full path that constructs a canonical
OCI layout and provenance, creates and verifies the real candidate manifest,
performs real OpenSSH authorization, builds the tag index, verifies it again
at a later system time, and proves subsequent payload drift is rejected.

## Formal promotion remains open

No workflow in this contract performs an atomic remote promotion. Before a
release can be authorized, a separately reviewed protected workflow must close
all of these gates:

- remote tag and GitHub Release nonexistence;
- concurrency serialization and non-overwritable authorization consumption;
- repository release-version/CHANGELOG contract at the tagged commit;
- exact-byte GitHub Release upload and OCI push without rebuilding; and
- public release download and registry pull read-back.

Until then, this index must never be interpreted as permission to publish.
