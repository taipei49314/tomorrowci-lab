[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Binary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-Dumpbin {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $installPaths = @(
            & $vswhere -latest -products * `
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                -property installationPath
        )
        if ($LASTEXITCODE -ne 0) {
            throw "vswhere failed while resolving the MSVC toolchain"
        }
        $installPath = $installPaths |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne "" } |
            Select-Object -First 1
        if ($null -ne $installPath) {
            $versionFile = Join-Path $installPath `
                "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
            if (Test-Path -LiteralPath $versionFile -PathType Leaf) {
                $toolsVersion = (Get-Content -LiteralPath $versionFile -Raw).Trim()
                if ($toolsVersion -notmatch '^[0-9]+(?:\.[0-9]+)+$') {
                    throw "the default MSVC tools version is not canonical"
                }
                $candidate = Join-Path $installPath `
                    "VC\Tools\MSVC\$toolsVersion\bin\Hostx64\x64\dumpbin.exe"
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return (Resolve-Path -LiteralPath $candidate).Path
                }
            }
        }
    }

    $command = Get-Command dumpbin.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $command) {
        return (Resolve-Path -LiteralPath $command.Source).Path
    }
    throw "dumpbin.exe could not be resolved through vswhere or PATH"
}

$resolvedBinary = (Resolve-Path -LiteralPath $Binary -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $resolvedBinary -PathType Leaf)) {
    throw "Windows candidate binary is not a regular file"
}
$dumpbin = Resolve-Dumpbin
Write-Output "dumpbin_path: $dumpbin"

& python (Join-Path $PSScriptRoot "windows_runtime_gate.py") `
    --dumpbin $dumpbin `
    --binary $resolvedBinary
if ($LASTEXITCODE -ne 0) {
    throw "Windows PE runtime gate rejected the candidate"
}
