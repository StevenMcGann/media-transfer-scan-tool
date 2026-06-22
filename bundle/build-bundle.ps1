#Requires -Version 7.4
<#
.SYNOPSIS
    Build a self-contained offline bundle of media-transfer-scan-tool (PLAN §3.5/§3.6).

.DESCRIPTION
    Assembles a directory (and optional .zip) that runs the scanner on an
    air-gapped operator host with nothing pre-installed:

        <bundle>/
          Scan.cmd                  operator entry point
          bootstrap.ps1             5.1-safe launcher
          src/                      engine + lib + analyzers + helpers
          tools/pwsh/               vendored portable PowerShell 7.4 (Windows x64)
          tools/venv/               vendored scanner venv (bandit, pip-audit, ...)
          manifest.json             versions + build date + SHA-256 file seals

    The bootstrapper prefers tools/pwsh (authoritative) and, seeing tools/venv,
    runs the engine in offline mode against the vendored venv.

    Run this on a CONNECTED dev host; deliver the result to the operator host via
    the controlled read-only channel (see docs/test-environment.md).

.PARAMETER PwshZip
    Path to a pre-downloaded portable pwsh win-x64 .zip. If omitted (and not
    -SkipPwsh), the script downloads PowerShell $PwshVersion from GitHub releases.

.PARAMETER SkipPwsh / -SkipVenv
    Skip vendoring the runtime / building the venv. For testing the bundle layout
    without the heavy download/install. A production bundle uses neither.
#>
[CmdletBinding()]
param(
    [string]$OutputDir   = (Join-Path $PSScriptRoot 'out'),
    [string]$Version     = '0.1.0-dev',
    [string]$PwshVersion = '7.4.6',          # PS 7.4 LTS line (PLAN §3.6)
    [string]$PwshZip     = '',
    [string]$BuiltUtc    = '',               # ISO timestamp; defaults to now if empty
    [switch]$SkipPwsh,
    [switch]$SkipVenv,
    [switch]$Zip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path $PSScriptRoot -Parent
$SCANNER_PACKAGES = @(
    @{ Id = 'bandit';         Min = '1.7.0' }
    @{ Id = 'pip-audit';      Min = '2.0.0' }
    @{ Id = 'detect-secrets'; Min = '1.4.0' }
    @{ Id = 'pefile';         Min = '2023.2.7' }
    @{ Id = 'pyelftools';     Min = '0.29' }
    @{ Id = 'shellcheck-py';  Min = '0.9.0' }
    @{ Id = 'oletools';       Min = '0.60' }
)

# Reuse the proven provisioning functions for the venv build.
. (Join-Path $RepoRoot 'src/lib/Logging.ps1')
. (Join-Path $RepoRoot 'src/lib/Provisioning.ps1')
$script:Quiet = $false

function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }

function Get-SealedFileHashes {
    <#
        SHA-256 every file the bootstrapper verifies at launch (issue #8): all of
        src/ (engine + lib + analyzers + helpers) plus the entry scripts, keyed by
        POSIX-relative path. Excludes the manifest itself and the heavy, volatile
        vendored runtime/venv — sealing those is the signing follow-up. Sorted for
        a deterministic, reproducible manifest.
    #>
    param([Parameter(Mandatory)][string]$BundleDir)
    # Resolve to an absolute path FIRST: Get-ChildItem returns absolute .FullName
    # values, so a relative $BundleDir (e.g. -OutputDir 'out') would make the
    # Substring below strip the wrong prefix length and emit bogus fileHashes keys
    # — the bundle would then fail its own bootstrap integrity check. Resolve-Path
    # (not [IO.Path]::GetFullPath) so this honours the PowerShell location the rest
    # of the build used; GetFullPath would resolve against the process cwd, which
    # Set-Location/Push-Location does not update.
    $BundleDir = (Resolve-Path -LiteralPath $BundleDir).Path.TrimEnd('\', '/')
    $hashes  = [ordered]@{}
    $targets = New-Object System.Collections.Generic.List[string]
    $srcDir  = Join-Path $BundleDir 'src'
    if (Test-Path -LiteralPath $srcDir) {
        Get-ChildItem -LiteralPath $srcDir -Recurse -File | ForEach-Object { $targets.Add($_.FullName) }
    }
    foreach ($f in 'bootstrap.ps1', 'Scan.cmd') {
        $p = Join-Path $BundleDir $f
        if (Test-Path -LiteralPath $p) { $targets.Add($p) }
    }
    foreach ($t in ($targets | Sort-Object)) {
        # $t is absolute (Get-ChildItem .FullName / Join-Path of an absolute base)
        # and shares the resolved $BundleDir prefix exactly, so strip directly.
        $rel = ($t.Substring($BundleDir.Length).TrimStart('\', '/')) -replace '\\', '/'
        $hashes[$rel] = (Get-FileHash -LiteralPath $t -Algorithm SHA256).Hash
    }
    return $hashes
}

$bundleName = "media-transfer-scan-tool-$Version"
$bundleDir  = Join-Path $OutputDir $bundleName
$toolVersions = [ordered]@{}

Write-Step "Staging bundle at: $bundleDir"
if (Test-Path $bundleDir) { Remove-Item $bundleDir -Recurse -Force }
New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $bundleDir 'tools') -Force | Out-Null

# ── 1. Source + entry points ─────────────────────────────────────────────────
Write-Step 'Copying engine source and entry points'
Copy-Item (Join-Path $RepoRoot 'src') (Join-Path $bundleDir 'src') -Recurse -Force
# Don't ship a dev venv if one exists beside the engine.
Remove-Item (Join-Path $bundleDir 'src/.scan-venv') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $bundleDir 'src/logs')       -Recurse -Force -ErrorAction SilentlyContinue
foreach ($f in 'bootstrap.ps1', 'Scan.cmd', 'README.md', 'LICENSE') {
    Copy-Item (Join-Path $RepoRoot $f) (Join-Path $bundleDir $f) -Force
}

# ── 2. Vendored PowerShell 7 runtime ─────────────────────────────────────────
$pwshDir = Join-Path $bundleDir 'tools/pwsh'
if ($SkipPwsh) {
    Write-Warning 'SKIP: portable pwsh not vendored (-SkipPwsh). Bundle is NOT operator-ready.'
} else {
    New-Item -ItemType Directory -Path $pwshDir -Force | Out-Null
    $zip = $PwshZip
    if (-not $zip) {
        $url = "https://github.com/PowerShell/PowerShell/releases/download/v$PwshVersion/PowerShell-$PwshVersion-win-x64.zip"
        $zip = Join-Path $OutputDir "pwsh-$PwshVersion-win-x64.zip"
        Write-Step "Downloading portable pwsh $PwshVersion"
        Invoke-WebRequest -Uri $url -OutFile $zip
    }
    Write-Step "Expanding portable pwsh into tools/pwsh"
    Expand-Archive -LiteralPath $zip -DestinationPath $pwshDir -Force
    if (-not (Test-Path (Join-Path $pwshDir 'pwsh.exe'))) { throw 'pwsh.exe not found after expand.' }
    $toolVersions['pwsh'] = $PwshVersion
}

# ── 3. Vendored scanner venv ─────────────────────────────────────────────────
$venvDir = Join-Path $bundleDir 'tools/venv'
if ($SkipVenv) {
    Write-Warning 'SKIP: scanner venv not built (-SkipVenv). Bundle is NOT operator-ready.'
} else {
    $py = Find-Python
    if (-not $py) { throw 'Python 3 required to build the scanner venv.' }
    Write-Step "Building scanner venv at tools/venv"
    $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $venvDir
    Update-PipBootstrap -PythonExe $venv.Python
    foreach ($pkg in $SCANNER_PACKAGES) {
        $v = Install-PipPackage -PythonExe $venv.Python -Package $pkg.Id -MinVersion $pkg.Min
        $toolVersions[$pkg.Id] = $v
    }
}

# ── 4. Manifest ──────────────────────────────────────────────────────────────
if (-not $BuiltUtc) { $BuiltUtc = (Get-Date).ToUniversalTime().ToString('o') }
$manifest = [ordered]@{
    bundleVersion = $Version
    builtUtc      = $BuiltUtc
    schemaVersion = '0.1.0'
    runtime       = 'powershell-7.4-lts-win-x64'
    toolVersions  = $toolVersions
    advisoryDb    = @{ note = 'live (online) until vendored CVE/OSV cache is added'; date = $null }
    hashAlgorithm = 'SHA256'
    fileHashes    = (Get-SealedFileHashes -BundleDir $bundleDir)
    complete      = (-not $SkipPwsh -and -not $SkipVenv)
}
$manifestPath = Join-Path $bundleDir 'manifest.json'
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Step "Wrote manifest.json (complete=$($manifest.complete))"

# ── 5. Optional zip ──────────────────────────────────────────────────────────
if ($Zip) {
    $zipOut = Join-Path $OutputDir "$bundleName.zip"
    Write-Step "Zipping bundle -> $zipOut"
    if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
    Compress-Archive -Path $bundleDir -DestinationPath $zipOut
}

Write-Host ""
Write-Host "Bundle staged: $bundleDir" -ForegroundColor Green
if (-not $manifest.complete) {
    Write-Host "NOTE: this is a PARTIAL bundle (skip flags used) — not operator-ready." -ForegroundColor Yellow
}
