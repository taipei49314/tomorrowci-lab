# Release trust bootstrap (intentionally incomplete)

The protected promotion preflight fails closed until an independently reviewed
`allowed_signers` file and an independently recorded
`expected-policy-sha256.txt` are added here. Dispatch inputs can never supply
or override either trust anchor.

Do not add fixture keys or derive the expected policy digest from the
authorization bundle. The publication job remains permanently disabled even
after genuine trust material is provisioned.
