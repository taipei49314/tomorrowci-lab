#!/usr/bin/env bash
# TomorrowCI release dry-run (Unix)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

VERSION="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])' 2>/dev/null || echo "0.1.1-alpha.2")"

echo "== build release CLI =="
cargo build -p tomorrowci-cli --release
BIN="$ROOT/target/release/tomorrowci"
test -x "$BIN"
"$BIN" --version | tee /tmp/tc-ver.txt
grep -F "$VERSION" /tmp/tc-ver.txt || grep -E '0\.1\.1' /tmp/tc-ver.txt

STAGE="dist/tomorrowci-${VERSION}-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/"
cp README.md LICENSE CHANGELOG.md "$STAGE/"
TAR="dist/$(basename "$STAGE").tar.gz"
tar -C dist -czf "$TAR" "$(basename "$STAGE")"

echo "== checksums (archives only) =="
(
  cd dist
  rm -f SHA256SUMS.txt
  if command -v sha256sum >/dev/null; then
    find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt
  else
    find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS.txt
  fi
  test -s SHA256SUMS.txt
)

echo "== SBOM from Cargo.lock =="
python3 - <<'PY'
import json, re
from pathlib import Path
lock = Path("Cargo.lock").read_text(encoding="utf-8")
# crude package names from [[package]] name = "..."
names = re.findall(r'name = "([^"]+)"', lock)
# first is often the root workspace member names; keep unique
seen = []
for n in names:
    if n not in seen:
        seen.append(n)
components = [{"type": "library", "name": n, "version": "locked"} for n in seen[:200]]
meta_ver = "0.1.1-alpha.2"
for line in Path("Cargo.toml").read_text(encoding="utf-8").splitlines():
    if line.strip().startswith("version ="):
        meta_ver = line.split("=",1)[1].strip().strip('"')
        break
sbom = {
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "tomorrowci",
      "version": meta_ver
    }
  },
  "components": components
}
Path("dist/sbom.cdx.json").write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
assert not Path("dist/sbom.cdx.json").read_bytes().startswith(b"\xef\xbb\xbf")
print("sbom components", len(components), "version", meta_ver)
PY

echo "== trust + tests =="
"$BIN" trust
cargo test --workspace --quiet

echo "Dry-run complete."
ls -la dist
