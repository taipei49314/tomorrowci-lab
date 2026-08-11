# TomorrowCI release dry-run (Windows)
$ErrorActionPreference = "Stop"
$Root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
Set-Location $Root

$Version = (python scripts/version_contract.py).Trim()
if ($LASTEXITCODE -ne 0) { throw "version contract failed" }

$Dist = [System.IO.Path]::GetFullPath((Join-Path $Root "dist"))
if ([System.IO.Path]::GetDirectoryName($Dist) -ne $Root -or
    [System.IO.Path]::GetFileName($Dist) -ne "dist") {
  throw "unsafe dist path: $Dist"
}
if (Test-Path -LiteralPath $Dist) {
  $DistItem = Get-Item -Force -LiteralPath $Dist
  if (($DistItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "refusing to remove reparse-point dist: $Dist"
  }
  Remove-Item -Recurse -Force -LiteralPath $Dist
}
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

$Target = "x86_64-pc-windows-msvc"
$TempBase = [System.IO.Path]::GetTempPath()
$ReleaseTemp = Join-Path $TempBase ("tomorrowci-release-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $ReleaseTemp | Out-Null
$HadCargoTarget = Test-Path Env:CARGO_TARGET_DIR
$PreviousCargoTarget = $env:CARGO_TARGET_DIR
$HadSourceDateEpoch = Test-Path Env:SOURCE_DATE_EPOCH
$PreviousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$HadCargoIncremental = Test-Path Env:CARGO_INCREMENTAL
$PreviousCargoIncremental = $env:CARGO_INCREMENTAL

try {
  Write-Host "== two clean release builds + deterministic package =="
  $env:CARGO_INCREMENTAL = "0"
  $env:SOURCE_DATE_EPOCH = "0"
  foreach ($Slot in @("a", "b")) {
  $TargetDir = Join-Path $ReleaseTemp "repro-$Slot"
  $env:CARGO_TARGET_DIR = $TargetDir
  cargo build -p tomorrowci-cli --release --locked --target $Target
  if ($LASTEXITCODE -ne 0) { throw "cargo build $Slot failed" }
  python scripts/package_release.py create `
    --binary (Join-Path $TargetDir "$Target\release\tomorrowci.exe") `
    --output-dir (Join-Path $ReleaseTemp "package-$Slot") `
    --version $Version `
    --target $Target
  if ($LASTEXITCODE -ne 0) { throw "package $Slot failed" }
  }

$ArchiveName = "tomorrowci-v$Version-$Target.zip"
$FirstArchive = Join-Path $ReleaseTemp "package-a\$ArchiveName"
$SecondArchive = Join-Path $ReleaseTemp "package-b\$ArchiveName"
$FirstHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FirstArchive).Hash
$SecondHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SecondArchive).Hash
if ($FirstHash -ne $SecondHash) {
  throw "non-reproducible release archives: $FirstHash != $SecondHash"
}
Copy-Item $FirstArchive (Join-Path $Dist $ArchiveName)

$Bin = Join-Path $ReleaseTemp "repro-a\$Target\release\tomorrowci.exe"
if (-not (Test-Path $Bin)) { throw "missing $Bin" }

$ActualVersion = (& $Bin --version).Trim()
if ($LASTEXITCODE -ne 0 -or $ActualVersion -ne "tomorrowci $Version") {
  throw "CLI version mismatch: $ActualVersion"
}

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
| Windows CLI archive | PASS | two clean builds + deterministic pack/hash compare | created | dist/$ArchiveName |
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
} finally {
  if ($HadCargoTarget) { $env:CARGO_TARGET_DIR = $PreviousCargoTarget } else { Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue }
  if ($HadSourceDateEpoch) { $env:SOURCE_DATE_EPOCH = $PreviousSourceDateEpoch } else { Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue }
  if ($HadCargoIncremental) { $env:CARGO_INCREMENTAL = $PreviousCargoIncremental } else { Remove-Item Env:CARGO_INCREMENTAL -ErrorAction SilentlyContinue }

  $ResolvedTemp = [System.IO.Path]::GetFullPath($ReleaseTemp)
  $ResolvedBase = [System.IO.Path]::GetFullPath($TempBase).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
  $TempName = [System.IO.Path]::GetFileName($ResolvedTemp)
  if ([System.IO.Path]::GetDirectoryName($ResolvedTemp).TrimEnd([System.IO.Path]::DirectorySeparatorChar) -ne $ResolvedBase -or
      $TempName -notmatch '^tomorrowci-release-[0-9a-f]{32}$') {
    throw "refusing unsafe temporary cleanup: $ResolvedTemp"
  }
  if (Test-Path -LiteralPath $ResolvedTemp) {
    $TempItem = Get-Item -Force -LiteralPath $ResolvedTemp
    if (($TempItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "refusing reparse-point temporary cleanup: $ResolvedTemp"
    }
    Remove-Item -Recurse -Force -LiteralPath $ResolvedTemp
  }
}
