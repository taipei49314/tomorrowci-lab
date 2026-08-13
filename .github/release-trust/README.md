# Release trust bootstrap (intentionally incomplete)

The protected promotion preflight fails closed until an independently reviewed
`allowed_signers` file and an independently recorded
`expected-policy-sha256.txt` are added here. Dispatch inputs can never supply
or override either trust anchor.

Do not add fixture keys or derive the expected policy digest from the
authorization bundle. The publication job remains permanently disabled even
after genuine trust material is provisioned.

When genuine trust material is eventually provisioned, promotion treats the
GitHub Actions candidate artifact ZIP as an exact-byte input: it verifies the
artifact API identity, size, and SHA-256 before strict extraction of the frozen
candidate inventory. The same raw-byte check and extraction are repeated after
the protected-environment approval. A downloader's extracted output is never a
substitute for those verified archive bytes.
