# TomorrowCI release dry-run (Windows)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = (python scripts/version_contract.py).Trim()
if ($LASTEXITCODE -ne 0) { throw "version contract failed" }

$Dist = Join-Path $Root "dist"
if (Test-Path $Dist) { Remove-Item -Recurse -Force $Dist }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

Write-Host "== build release CLI =="
cargo build -p tomorrowci-cli --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$Bin = Join-Path $Root "target\release\tomorrowci.exe"
if (-not (Test-Path $Bin)) { throw "missing $Bin" }

$ActualVersion = (& $Bin --version).Trim()
if ($LASTEXITCODE -ne 0 -or $ActualVersion -ne "tomorrowci $Version") {
  throw "CLI version mismatch: $ActualVersion"
}

$StageName = "tomorrowci-v$Version-x86_64-pc-windows-msvc"
$Stage = Join-Path $Dist $StageName
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
Copy-Item $Bin (Join-Path $Stage "tomorrowci.exe")
Copy-Item (Join-Path $Root "README.md") $Stage
Copy-Item (Join-Path $Root "LICENSE") $Stage
Copy-Item (Join-Path $Root "CHANGELOG.md") $Stage

$Zip = Join-Path $Dist "$StageName.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path $Stage -DestinationPath $Zip -Force
if (-not (Test-Path $Zip)) { throw "zip not created: $Zip" }
Remove-Item -Recurse -Force -LiteralPath $Stage

Write-Host "== exact SBOM + claim snapshot =="
$sbom = Join-Path $Dist "sbom.cdx.json"
python scripts/generate_sbom.py --output $sbom
if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed" }
$ClaimSnapshot = Join-Path $Dist "claim-to-evidence.md"
Copy-Item (Join-Path $Root "docs\CLAIM_TO_EVIDENCE.md") $ClaimSnapshot

Write-Host "== trust audit =="
& $Bin trust
if ($LASTEXITCODE -ne 0) { throw "trust failed" }

Write-Host "== unit tests =="
cargo test --workspace --quiet
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "== claim ledger =="
$claims = @"
# Claim-to-evidence (release dry-run)

| Claim | Status | Command | Result | Artifact |
|---|---|---|---|---|
| Rust workspace tests | PASS | cargo test --workspace | exit 0 | local |
| Trust audit | PASS | tomorrowci trust | overall Pass | stdout |
| Windows CLI archive | PASS | Compress-Archive | created | dist/$StageName.zip |
| Checksums | PASS | Get-FileHash SHA256 | created | dist/SHA256SUMS.txt |
| SBOM document | PASS | exact Cargo.lock inventory | created | dist/sbom.cdx.json |
| Live Docker e2e | NOT_RUN | not executed by local packaging dry-run | n/a | n/a |
"@
Set-Content -Path (Join-Path $Dist "dry-run-results.md") -Value $claims -Encoding utf8

Write-Host "== final checksums =="
$sums = Join-Path $Dist "SHA256SUMS.txt"
$lines = @()
Get-ChildItem -Path $Dist -File |
  Where-Object { $_.Extension -eq ".zip" -or $_.Name -in @("sbom.cdx.json", "claim-to-evidence.md", "dry-run-results.md") } |
  Sort-Object Name |
  ForEach-Object {
    $h = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLower()
    $lines += "$h  $($_.Name)"
  }
if ($lines.Count -ne 4) { throw "unexpected checksummed asset count: $($lines.Count)" }
$lines | Set-Content -Path $sums -Encoding ascii
foreach ($line in Get-Content -Encoding ascii -LiteralPath $sums) {
  if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "malformed checksum line: $line" }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Dist $matches[2])).Hash.ToLower()
  if ($actual -ne $matches[1]) { throw "checksum mismatch: $($matches[2])" }
}

Write-Host "Dry-run complete. Artifacts in $Dist"
Get-ChildItem $Dist | Format-Table Name, Length
