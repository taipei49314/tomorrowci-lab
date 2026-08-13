# Release trust bootstrap (intentionally incomplete)

The protected promotion preflight fails closed until an independently reviewed
`allowed_signers` file and `external-policy-transport.json` are added here.
Dispatch inputs and the authorization bundle can never supply or override
either trust anchor.

Do not add fixture keys, policy digests, or policies here.  The transport
configuration must name one direct HTTPS authority and derive both policy and
signature URLs from the verified candidate commit and candidate-manifest
SHA-256.  The fetched policy must be separately SSH-signed by the pinned
auditor identity, bind those exact candidate bytes, be current, and have the
same pinned `allowed_signers` digest. Redirects, proxy credentials, cookies,
content encodings, duplicate JSON keys, oversized responses, and output
replacement are rejected. Prepare and write fetch and verify the exact policy
and signature again; their raw bytes and canonical receipt must match.

The external authority must be operated outside this repository and its
workflow-dispatch callers. It must publish candidate-specific policy plus
detached signature only after independent review. A repository maintainer
cannot turn an authorization-bundle policy into trusted policy. Until a real
authority, stable auditor key, and HTTPS endpoint are configured, the missing
tracked files stop promotion before any mutation. The publication job remains
permanently disabled even after genuine trust material is provisioned.

The transport file is canonical JSON with this schema (values shown are
placeholders and must not be committed):

```json
{"kind":"tomorrowci.external-policy-transport.v1","schema_version":1,"transport":{"maximum_bytes":1048576,"policy_url_template":"https://audit.example/policy/{candidate_commit}/{candidate_manifest_sha256_hex}.json","signature_url_template":"https://audit.example/policy/{candidate_commit}/{candidate_manifest_sha256_hex}.json.sig"},"trust":{"allowed_signers_sha256":"sha256:<pinned allowed_signers bytes>","auditor_principal":"auditor@example.invalid","namespace":"tomorrowci-release-v1"}}
```

When genuine trust material is eventually provisioned, promotion treats the
GitHub Actions candidate artifact ZIP as an exact-byte input: it verifies the
artifact API identity, size, and SHA-256 before strict extraction of the frozen
candidate inventory. The same raw-byte check and extraction are repeated after
the protected-environment approval. A downloader's extracted output is never a
substitute for those verified archive bytes.
