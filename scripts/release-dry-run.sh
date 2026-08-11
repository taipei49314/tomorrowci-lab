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
TARGET="$(rustc -vV | sed -n 's/^host: //p')"
case "$TARGET" in
  x86_64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
  *) echo "unsupported release dry-run host target: $TARGET" >&2; exit 1 ;;
esac
TCI_RELEASE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/tomorrowci-release.XXXXXX")"
cleanup_release_tmp() {
  case "$TCI_RELEASE_TMP" in
    "${TMPDIR:-/tmp}"/tomorrowci-release.*) rm -rf -- "$TCI_RELEASE_TMP" ;;
    *) echo "refusing unsafe temporary cleanup: $TCI_RELEASE_TMP" >&2 ;;
  esac
}
trap cleanup_release_tmp EXIT

echo "== two clean release builds + deterministic package =="
for slot in a b; do
  target_dir="$TCI_RELEASE_TMP/repro-$slot"
  CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0 CARGO_TARGET_DIR="$target_dir" \
    cargo build -p tomorrowci-cli --release --locked --target "$TARGET"
  python3 scripts/package_release.py create \
    --binary "$target_dir/$TARGET/release/tomorrowci" \
    --output-dir "$TCI_RELEASE_TMP/package-$slot" \
    --version "$VERSION" \
    --target "$TARGET"
done
ARCHIVE="tomorrowci-v${VERSION}-${TARGET}.tar.gz"
python3 - "$TCI_RELEASE_TMP/package-a/$ARCHIVE" "$TCI_RELEASE_TMP/package-b/$ARCHIVE" <<'PY'
import hashlib
import pathlib
import sys

digests = [hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest() for value in sys.argv[1:]]
if digests[0] != digests[1]:
    raise SystemExit(f"non-reproducible release archives: {digests[0]} != {digests[1]}")
PY
cp "$TCI_RELEASE_TMP/package-a/$ARCHIVE" "$DIST/$ARCHIVE"
BIN="$TCI_RELEASE_TMP/repro-a/$TARGET/release/tomorrowci"
test -x "$BIN"
ACTUAL_VERSION="$("$BIN" --version)"
test "$ACTUAL_VERSION" = "tomorrowci $VERSION"

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
| Host CLI archive | PASS | two clean builds + deterministic pack/hash compare | created | $ARCHIVE |
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
