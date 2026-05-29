<#
.SYNOPSIS
    media-transfer-scan-tool launcher — resolves PowerShell 7.4+ and re-launches
    the engine under it. Runs under Windows PowerShell 5.1 (or pwsh).

.DESCRIPTION
    The engine (src/Invoke-MediaTransferScan.ps1) is PowerShell 7.4+ only. This
    bootstrapper is the operator entry point and is deliberately written in the
    5.1-compatible PowerShell subset (no ?., ??, ternary, -AsArray, etc.) so it
    runs on a stock Windows host where only Windows PowerShell 5.1 is present.

    Runtime resolution order (PLAN §3.6):
      1. Bundled pwsh (tools\pwsh\pwsh.exe) — AUTHORITATIVE. Preferred even when
         the host also has PS 7, for version determinism + supply-chain integrity.
      2. Host PATH pwsh >= 7.4 — only when no bundled copy exists (dev/online).
      3. Neither -> fail loudly with a clear message (never downgrade to 5.1).

    The engine is launched with -NoProfile so no host $PROFILE / module shadowing
    leaks into the run. If a vendored venv (tools\venv) is present, the engine is
    pointed at it in offline mode.

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

function Get-PwshVersion {
    param([string]$Exe)
    try {
        $out = & $Exe -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
        if ($out) { return [version]([string]$out).Trim() }
    } catch { }
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

function Get-EngineLaunchArgs {
    <#
        Build the pwsh argument array (pure — unit testable). Prepends host args
        (-NoProfile, -ExecutionPolicy Bypass, -File <engine>), adds offline +
        vendored-venv args when a bundle venv exists, then forwards operator args.
    #>
    param([string]$Engine, [string]$BundledVenv, $ForwardArgs)
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add('-NoProfile')
    $a.Add('-ExecutionPolicy'); $a.Add('Bypass')
    $a.Add('-File');            $a.Add($Engine)
    if ($BundledVenv -and (Test-Path -LiteralPath $BundledVenv)) {
        $a.Add('-Mode');    $a.Add('offline')
        $a.Add('-VenvDir'); $a.Add($BundledVenv)
    }
    if ($ForwardArgs) { foreach ($x in $ForwardArgs) { $a.Add([string]$x) } }
    return $a.ToArray()
}

# ── Guarded main (script scope — see .DESCRIPTION note about exit codes) ─────
if ($MyInvocation.InvocationName -ne '.') {
    $engine = Resolve-EnginePath -Root $Here
    if (-not $engine) {
        Write-Host "ERROR: engine not found (looked for src\Invoke-MediaTransferScan.ps1)." -ForegroundColor Red
        exit $ExitBadRuntime
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
