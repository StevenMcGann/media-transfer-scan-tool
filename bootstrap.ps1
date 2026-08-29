<#
.SYNOPSIS
    media-transfer-scan-tool launcher -- resolves PowerShell 7.4+ and re-launches
    the engine under it. Runs under Windows PowerShell 5.1 (or pwsh).

.DESCRIPTION
    The engine (src/Invoke-MediaTransferScan.ps1) is PowerShell 7.4+ only. This
    bootstrapper is the operator entry point and is deliberately written in the
    5.1-compatible PowerShell subset (no ?., ??, ternary, -AsArray, etc.) so it
    runs on a stock Windows host where only Windows PowerShell 5.1 is present.

    Runtime resolution order:
      1. Bundled pwsh (tools\pwsh\pwsh.exe) -- AUTHORITATIVE. Preferred even when
         the host also has PS 7, for version determinism + supply-chain integrity.
      2. Host PATH pwsh >= 7.4 -- only when no bundled copy exists (dev/online).
      3. Neither -> fail loudly with a clear message (never downgrade to 5.1).

    The engine is launched with -NoProfile so no host $PROFILE / module shadowing
    leaks into the run. If a vendored venv (tools\venv) is present, the engine is
    pointed at it via -VenvDir (reusing the bundled tools); the scan mode is left
    to the engine default (online) or whatever the operator passes, so an online
    host still gets live CVE feeds. Air-gapped use passes -Mode offline.

    NOTE: the engine invocation and `exit` happen at SCRIPT scope, not inside a
    function. Running `& $pwsh ...` inside a function would capture the engine's
    stdout into the function's pipeline output and corrupt the returned exit code.

.NOTES
    All arguments are forwarded verbatim to the engine.
    Example:  .\bootstrap.ps1 -Path D:\incoming\submission -Profile full
#>
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)] $EngineArgs)

$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

$MinPwsh        = [version]'7.4'
$ExitBadRuntime = 4   # distinct from engine exit codes (0/2/3/10)
$ExitIntegrity  = 5   # bundle integrity (manifest SHA-256) check failed

function Get-PwshVersion {
    param([string]$Exe)
    try {
        $out = & $Exe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        if ($out) { return [version]([string]$out).Trim() }
    } catch {
        Write-Verbose "PowerShell version probe failed for '$Exe': $_"
    }
    return $null
}

function Resolve-EngineRuntime {
    <#
        Return the path to a usable pwsh >= 7.4, or $null. Bundled wins over PATH.
    #>
    param(
        [string]$BundledPwsh,
        [bool]$AllowPath = $true
    )
    if ($BundledPwsh -and (Test-Path -LiteralPath $BundledPwsh)) {
        $v = Get-PwshVersion -Exe $BundledPwsh
        if ($v -and $v -ge $MinPwsh) { return $BundledPwsh }
        Write-Warning "Bundled pwsh at '$BundledPwsh' is unusable or below $MinPwsh."
    }
    if ($AllowPath) {
        $cmd = Get-Command pwsh -ErrorAction SilentlyContinue
        if ($cmd) {
            $v = Get-PwshVersion -Exe $cmd.Source
            if ($v -and $v -ge $MinPwsh) { return $cmd.Source }
        }
    }
    return $null
}

function Resolve-EnginePath {
    # Engine lives at src\ in both a dev checkout and a built bundle.
    param([string]$Root)
    $candidates = @(
        (Join-Path $Root 'src\Invoke-MediaTransferScan.ps1'),
        (Join-Path $Root 'Invoke-MediaTransferScan.ps1')
    )
    foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
    return $null
}

function Test-BundleIntegrity {
    <#
        Verify the scanner's sealed files against manifest.json 'fileHashes'
        (SHA-256) BEFORE the engine is launched. This is the offline bundle's
        tamper check: a modified engine/analyzer or a swapped helper is refused
        rather than executed under -ExecutionPolicy Bypass.

        Returns $true when the bundle is intact, OR when it is unsealed -- no
        manifest.json (a dev checkout) or a manifest without fileHashes (an older
        bundle) -- in which case it warns and proceeds for backward compatibility.
        Returns $false only on real tamper: a sealed file is missing or its hash
        differs. 5.1-compatible (Get-FileHash / ConvertFrom-Json only).

        NOTE: bootstrap.ps1 cannot meaningfully vouch for itself -- an attacker
        editing the engine would also strip this check. Sealing the manifest with
        a signature (so the bootstrapper itself is anchored) is the issue #8
        follow-up; this verifies the engine/analyzer code an in-place tamper hits.
    #>
    param([string]$Root)

    $manifestPath = Join-Path $Root 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Host "Integrity: no manifest.json (unsealed dev checkout) -- skipping verification." -ForegroundColor DarkGray
        return $true
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "ERROR: manifest.json is unreadable or corrupt: $_" -ForegroundColor Red
        return $false
    }
    if (($manifest.PSObject.Properties.Name -notcontains 'fileHashes') -or
        (-not $manifest.fileHashes) -or
        (@($manifest.fileHashes.PSObject.Properties).Count -eq 0)) {
        Write-Warning 'manifest.json has no fileHashes -- bundle is unsealed; integrity not verified.'
        return $true
    }

    $bad   = New-Object System.Collections.Generic.List[string]
    $count = 0
    foreach ($prop in $manifest.fileHashes.PSObject.Properties) {
        $count++
        $rel      = $prop.Name
        $expected = ([string]$prop.Value).ToUpperInvariant()
        $local    = Join-Path $Root ($rel -replace '/', '\')
        if (-not (Test-Path -LiteralPath $local)) { $bad.Add("missing : $rel"); continue }
        $actual = (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -ne $expected) { $bad.Add("modified: $rel") }
    }

    if ($bad.Count -gt 0) {
        Write-Host ""
        Write-Host "ERROR: bundle integrity check FAILED -- $($bad.Count) of $count sealed file(s) do not match manifest.json:" -ForegroundColor Red
        foreach ($b in ($bad | Select-Object -First 12)) { Write-Host "    $b" -ForegroundColor Red }
        if ($bad.Count -gt 12) { Write-Host "    ... and $($bad.Count - 12) more." -ForegroundColor Red }
        Write-Host "  The bundle may be corrupt or tampered with. Re-deliver it from a trusted source." -ForegroundColor Yellow
        return $false
    }
    Write-Host "Integrity: verified $count sealed file(s) against manifest.json." -ForegroundColor DarkGray
    return $true
}

function Get-EngineLaunchArgs {
    <#
        Build the pwsh argument array (pure -- unit testable). Prepends host args
        (-NoProfile, -ExecutionPolicy Bypass, -File <engine>), points the engine at
        the bundle's vendored venv when present, then forwards operator args.

        NOTE: we pass -VenvDir but deliberately do NOT force -Mode offline. On an
        online host the bundle should still use live advisory feeds (pip-audit /
        OSV) for full CVE coverage while reusing the vendored tools. An air-gapped
        deployment selects offline explicitly via `-Mode offline` (forwarded here),
        which the operator/bundle config supplies.
    #>
    param([string]$Engine, [string]$BundledVenv, $ForwardArgs)
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add('-NoProfile')
    $a.Add('-ExecutionPolicy'); $a.Add('Bypass')
    $a.Add('-File');            $a.Add($Engine)
    if ($BundledVenv -and (Test-Path -LiteralPath $BundledVenv)) {
        $a.Add('-VenvDir'); $a.Add($BundledVenv)   # use vendored tools; mode left to default/operator
    }
    if ($ForwardArgs) { foreach ($x in $ForwardArgs) { $a.Add([string]$x) } }
    return $a.ToArray()
}

# -- Guarded main (script scope -- see .DESCRIPTION note about exit codes) -----
if ($MyInvocation.InvocationName -ne '.') {
    $engine = Resolve-EnginePath -Root $Here
    if (-not $engine) {
        Write-Host "ERROR: engine not found (looked for src\Invoke-MediaTransferScan.ps1)." -ForegroundColor Red
        exit $ExitBadRuntime
    }

    # Verify the bundle has not been tampered with before running it under
    # -ExecutionPolicy Bypass. Unsealed dev checkouts warn and proceed.
    if (-not (Test-BundleIntegrity -Root $Here)) {
        exit $ExitIntegrity
    }

    $pwsh = Resolve-EngineRuntime -BundledPwsh (Join-Path $Here 'tools\pwsh\pwsh.exe') -AllowPath $true
    if (-not $pwsh) {
        Write-Host ""
        Write-Host "ERROR: PowerShell 7.4+ is required and was not found." -ForegroundColor Red
        Write-Host "  - No bundled runtime at: $(Join-Path $Here 'tools\pwsh\pwsh.exe')" -ForegroundColor Yellow
        Write-Host "  - No pwsh >= 7.4 on PATH." -ForegroundColor Yellow
        Write-Host "  Install PowerShell 7.4+ (https://aka.ms/powershell) or use the offline bundle." -ForegroundColor Yellow
        exit $ExitBadRuntime
    }
    Write-Host "Using PowerShell runtime: $pwsh" -ForegroundColor DarkGray

    $launchArgs = Get-EngineLaunchArgs -Engine $engine `
        -BundledVenv (Join-Path $Here 'tools\venv') -ForwardArgs $EngineArgs

    # Invoke at script scope; engine stdout flows to the host, $LASTEXITCODE is clean.
    & $pwsh $launchArgs
    exit $LASTEXITCODE
}
