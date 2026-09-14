#Requires -Version 7.4
<#
.SYNOPSIS
    Build a self-contained offline bundle of media-transfer-scan-tool.

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

    The bootstrapper prefers tools/pwsh (authoritative) and points the engine at
    tools/venv. Mode remains explicit: online by default, or offline only when
    the operator passes -Mode offline.

    Run this on a CONNECTED dev host; deliver the result to the operator host via
    the controlled read-only channel (see docs/test-environment.md).

.PARAMETER PwshZip
    Path to a pre-downloaded portable pwsh win-x64 .zip. If omitted (and not
    -SkipPwsh), the script downloads PowerShell $PwshVersion from GitHub releases.

.PARAMETER PythonZip
    Path to a pre-downloaded official Python embeddable win-amd64 .zip. If
    omitted (and not -SkipVenv), the script downloads Python $PythonVersion.

.PARAMETER SkipPwsh / -SkipVenv / -SkipKev
    Skip vendoring the runtime / building the venv / downloading the CISA KEV
    catalog. For testing the bundle layout without the heavy download/install,
    and for skeleton builds on a host with no network. A production bundle uses
    none of them: each one leaves manifest.complete = false.
#>
[CmdletBinding()]
param(
    [string]$OutputDir   = (Join-Path $PSScriptRoot 'out'),
    [string]$Version     = '0.17.0',
    [string]$PwshVersion = '7.4.20',         # pinned PS 7.4 LTS patch
    [string]$PwshZip     = '',
    [string]$PythonVersion = '3.12.10',
    [string]$PythonZip   = '',
    [string]$BuiltUtc    = '',               # ISO timestamp; defaults to now if empty
    [string]$KevCatalogPath = '',            # pre-downloaded CISA KEV catalog; downloaded when empty
    [switch]$SkipPwsh,
    [switch]$SkipVenv,
    [switch]$SkipKev,
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

# Reuse the proven provisioning functions for the venv build, and the engine's own
# KEV loader so a vendored catalog is validated by exactly the code that will read
# it at scan time (issue #41). Kev.ps1 depends on helpers in Osv.ps1.
. (Join-Path $RepoRoot 'src/lib/Logging.ps1')
. (Join-Path $RepoRoot 'src/lib/Provisioning.ps1')
. (Join-Path $RepoRoot 'src/lib/Osv.ps1')
. (Join-Path $RepoRoot 'src/lib/Kev.ps1')
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
    # .ProviderPath, not .Path: on a UNC output dir .Path carries the
    # 'Microsoft.PowerShell.Core\FileSystem::' provider prefix, which would again
    # skew the Substring length below.
    $BundleDir = (Resolve-Path -LiteralPath $BundleDir).ProviderPath.TrimEnd('\', '/')
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
    # tools/kev IS sealed (unlike the volatile runtime/venv): it is one small,
    # stable data file that drives a security decision, so tampering with it must
    # be as detectable as tampering with the engine (issue #41).
    $kevDir = Join-Path $BundleDir 'tools/kev'
    if (Test-Path -LiteralPath $kevDir) {
        Get-ChildItem -LiteralPath $kevDir -Recurse -File | ForEach-Object { $targets.Add($_.FullName) }
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
# Python helpers can leave host-generated bytecode behind during development or
# tests.  Never seal or ship those machine-local cache artifacts.
$copiedSrc = Join-Path $bundleDir 'src'
Get-ChildItem -LiteralPath $copiedSrc -Recurse -File -Force |
    Where-Object { $_.Extension -in '.pyc', '.pyo' } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
Get-ChildItem -LiteralPath $copiedSrc -Recurse -Directory -Force |
    Where-Object { $_.Name -eq '__pycache__' } |
    Sort-Object { $_.FullName.Length } -Descending |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
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
    # PowerShell variable names are case-insensitive. Do not call this `$zip`:
    # that would alias the [switch]$Zip parameter and assigning a path string
    # would fail before a production `-Zip` build could create its artifact.
    $runtimeZip = $PwshZip
    if (-not $runtimeZip) {
        $url = "https://github.com/PowerShell/PowerShell/releases/download/v$PwshVersion/PowerShell-$PwshVersion-win-x64.zip"
        $runtimeZip = Join-Path $OutputDir "pwsh-$PwshVersion-win-x64.zip"
        Write-Step "Downloading portable pwsh $PwshVersion"
        Invoke-WebRequest -Uri $url -OutFile $runtimeZip
    }
    Write-Step "Expanding portable pwsh into tools/pwsh"
    Expand-Archive -LiteralPath $runtimeZip -DestinationPath $pwshDir -Force
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
    $pipPins = (Get-DependencyPins).pip   # exact versions, shared with online provisioning (F3)
    foreach ($pkg in $SCANNER_PACKAGES) {
        $v = Install-PipPackage -PythonExe $venv.Python -Package $pkg.Id -MinVersion $pkg.Min -Version ($pipPins[$pkg.Id] ?? '')
        $toolVersions[$pkg.Id] = $v
    }

    # A Windows venv is not self-contained: its python.exe resolves the base
    # installation recorded in pyvenv.cfg, and pip console launchers embed the
    # build-time interpreter path. Add the official embeddable runtime and point
    # it at the already-built venv's site-packages through its relocatable ._pth
    # file. Runtime analyzers invoke Python modules directly, avoiding absolute
    # paths embedded in pip-generated launchers.
    $buildPythonVersion = (& $venv.Python -c 'import platform; print(platform.python_version())').Trim()
    if ($buildPythonVersion -ne $PythonVersion) {
        throw "Build Python $buildPythonVersion does not match bundled Python $PythonVersion. Use a matching build interpreter."
    }
    $pythonDir = Join-Path $bundleDir 'tools/python'
    New-Item -ItemType Directory -Path $pythonDir -Force | Out-Null
    $runtimePythonZip = $PythonZip
    if (-not $runtimePythonZip) {
        $pythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
        $runtimePythonZip = Join-Path $OutputDir "python-$PythonVersion-embed-amd64.zip"
        Write-Step "Downloading Python embeddable runtime $PythonVersion"
        Invoke-WebRequest -Uri $pythonUrl -OutFile $runtimePythonZip
    }
    Write-Step "Expanding Python embeddable runtime into tools/python"
    Expand-Archive -LiteralPath $runtimePythonZip -DestinationPath $pythonDir -Force
    $pythonExe = Join-Path $pythonDir 'python.exe'
    $pthFile = Get-ChildItem -LiteralPath $pythonDir -Filter 'python*._pth' -File | Select-Object -First 1
    if (-not (Test-Path -LiteralPath $pythonExe) -or -not $pthFile) {
        throw 'Official Python embeddable runtime is missing python.exe or its ._pth file.'
    }
    $pythonVersionObject = [version]$PythonVersion
    @("python$($pythonVersionObject.Major)$($pythonVersionObject.Minor).zip", '.', '..\venv\Lib\site-packages', 'import site') |
        Set-Content -LiteralPath $pthFile.FullName -Encoding ascii
    $runtimeCheck = & $pythonExe -c 'import bandit, pip_audit, detect_secrets, oletools, pefile, elftools; print("ok")'
    if ($LASTEXITCODE -ne 0 -or ([string]$runtimeCheck).Trim() -ne 'ok') {
        throw 'Bundled Python runtime cannot import the pinned scanner packages.'
    }
    $toolVersions['python'] = $PythonVersion
}

# ── 3c. CISA KEV catalog (issue #41) ─────────────────────────────────────────
# Vendored rather than cached at runtime: the bundle already seals every shipped
# file, so an air-gapped host gets a tamper-evident catalog with no cache
# location, staleness bookkeeping, or atomic-write machinery. US Government
# public domain, so redistribution is fine.
if ($SkipKev) {
    Write-Warning 'SKIP: CISA KEV catalog not vendored (-SkipKev). Bundle is NOT operator-ready; offline scans will report KEV-CATALOG-UNAVAILABLE.'
} else {
    $kevDir = Join-Path $bundleDir 'tools/kev'
    New-Item -ItemType Directory -Path $kevDir -Force | Out-Null
    $kevOut = Join-Path $kevDir 'known_exploited_vulnerabilities.json'
    if ($KevCatalogPath) {
        Write-Step "Vendoring KEV catalog from $KevCatalogPath"
        Copy-Item -LiteralPath $KevCatalogPath -Destination $kevOut -Force
    } else {
        # Try every configured source, not just the first (PR #47 review): the
        # mirror exists precisely because a release host's proxy may allow
        # raw.githubusercontent.com but not www.cisa.gov, and a build that gave
        # up on the first source would fail before producing any bundle.
        $kevErrors = @()
        foreach ($kevUrl in $script:KevDefaultSources) {
            try {
                Write-Step "Downloading CISA KEV catalog from $kevUrl"
                Invoke-KevDownload -Url $kevUrl -OutFile $kevOut -TimeoutSec 60
                $kevErrors = @()
                break
            } catch {
                Write-Warning "KEV source failed ($kevUrl): $($_.Exception.Message)"
                $kevErrors += "$kevUrl : $($_.Exception.Message)"
            }
        }
        if ($kevErrors.Count -gt 0) {
            throw "Could not download the CISA KEV catalog from any source. Tried: $($kevErrors -join '; '). Supply -KevCatalogPath, or -SkipKev for a non-operator-ready build."
        }
    }
    # Validate with the engine's own loader BEFORE sealing: a proxy login page or
    # a schema change must fail the build, never ship as "the catalog".
    $kevCat = Read-KevCatalogFile -Path $kevOut -SourceLabel 'vendored bundle copy'
    $toolVersions['kevCatalog'] = $kevCat.Version
    Write-Step "Vendored KEV catalog $($kevCat.Version) ($($kevCat.Count) CVEs, released $($kevCat.DateReleased))"
}

# ── 4. Manifest ──────────────────────────────────────────────────────────────
if (-not $BuiltUtc) { $BuiltUtc = (Get-Date).ToUniversalTime().ToString('o') }
$manifest = [ordered]@{
    bundleVersion = $Version
    builtUtc      = $BuiltUtc
    schemaVersion = '0.1.0'
    runtime       = 'powershell-7.4-lts-win-x64'
    toolVersions  = $toolVersions
    advisoryDb    = @{
        note              = 'OSV advisories are live (online only); the CISA KEV catalog is vendored under tools/kev'
        date              = $null
        kevCatalogVersion = $(if ($toolVersions.Contains('kevCatalog')) { $toolVersions['kevCatalog'] } else { $null })
    }
    hashAlgorithm = 'SHA256'
    fileHashes    = (Get-SealedFileHashes -BundleDir $bundleDir)
    # -SkipKev counts too (PR #47 review): a bundle without the vendored catalog
    # cannot deliver the KEV coverage an operator-ready bundle promises, so it
    # must not advertise itself as complete.
    complete      = (-not $SkipPwsh -and -not $SkipVenv -and -not $SkipKev)
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
