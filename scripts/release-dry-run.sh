#!/usr/bin/env bash
# TomorrowCI release dry-run (Unix)
# The repository EOL contract keeps this script LF-only on every checkout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"
case "$DIST" in
  "$ROOT/dist") ;;
  *) echo "unsafe dist path: $DIST" >&2; exit 1 ;;
esac
rm -rf -- "$DIST"
mkdir -p "$DIST"

VERSION="$(python3 scripts/version_contract.py)"

echo "== build release CLI =="
cargo build -p tomorrowci-cli --release
BIN="$ROOT/target/release/tomorrowci"
test -x "$BIN"
ACTUAL_VERSION="$("$BIN" --version)"
test "$ACTUAL_VERSION" = "tomorrowci $VERSION"

STAGE="dist/tomorrowci-v${VERSION}-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/"
cp README.md LICENSE CHANGELOG.md "$STAGE/"
TAR="dist/$(basename "$STAGE").tar.gz"
tar -C dist -czf "$TAR" "$(basename "$STAGE")"
rm -rf -- "$STAGE"

echo "== exact SBOM + claim snapshot =="
python3 scripts/generate_sbom.py --output dist/sbom.cdx.json
cp docs/CLAIM_TO_EVIDENCE.md dist/claim-to-evidence.md

echo "== trust + tests =="
"$BIN" trust
cargo test --workspace --quiet

cat > dist/dry-run-results.md <<EOF
# Claim-to-evidence (release dry-run)

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace tests | PASS | cargo test --workspace | exit 0 | local |
| Trust audit | PASS | tomorrowci trust | overall Pass | stdout |
| Host CLI archive | PASS | tar | created | $(basename "$TAR") |
| SBOM document | PASS | exact Cargo.lock inventory | created | sbom.cdx.json |
EOF

echo "== final checksums =="
(
  cd dist
  rm -f SHA256SUMS.txt
  if command -v sha256sum >/dev/null; then
    find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name 'sbom.cdx.json' -o -name 'claim-to-evidence.md' -o -name 'dry-run-results.md' \) -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
    test "$(wc -l < SHA256SUMS.txt)" -eq 4
    sha256sum -c SHA256SUMS.txt
  else
    find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' -o -name 'sbom.cdx.json' -o -name 'claim-to-evidence.md' -o -name 'dry-run-results.md' \) -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS.txt
    test "$(wc -l < SHA256SUMS.txt)" -eq 4
    shasum -a 256 -c SHA256SUMS.txt
  fi
)

echo "Dry-run complete."
ls -la dist
