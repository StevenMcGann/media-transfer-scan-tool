#Requires -Version 7.4
<#
.SYNOPSIS
    media-transfer-scan-tool - static security scanner for media-transfer review.
.DESCRIPTION
    Engine entry point (PLAN §3.1): discover -> classify -> dispatch -> render.
    Renders one finding model as canonical JSON + HTML + slim TXT.
    All analysis is STATIC. PowerShell 7.4+ only.
.PARAMETER Path
    Folder of artifacts to scan.
.PARAMETER Profile
    'core' (default; high-signal analyzers) or 'full' (adds the opt-in `deep` tier).
.PARAMETER EnableAnalyzers / -DisableAnalyzers
    Per-run overrides by analyzer name.
.PARAMETER Quiet
    Suppress human/log console output (machine/automation use).
.PARAMETER OutputFormat
    'all' (default) or 'json' to also echo the JSON report path/content for capture.
.NOTES
    Version : 0.1.0 (scaffold)
#>
[CmdletBinding()]
param(
    [string]$Path,
    [ValidateSet('core', 'full')][string]$Profile = 'core',
    [string[]]$EnableAnalyzers = @(),
    [string[]]$DisableAnalyzers = @(),
    [ValidateSet('online', 'offline')][string]$Mode = 'online',
    [switch]$Quiet,
    [ValidateSet('all', 'json')][string]$OutputFormat = 'all'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Load engine ------------------------------------------------------------
$here = $PSScriptRoot
foreach ($lib in 'Logging', 'Findings', 'Classify', 'Registry', 'Report', 'Engine') {
    . (Join-Path $here "lib/$lib.ps1")
}

# Exit codes (PLAN §3.9 automation contract).
$script:ExitClean   = 0
$script:ExitFindings = 10
$script:ExitError   = 2
$script:ExitBadInput = 3

function Invoke-Main {
    param([string]$Path, [string]$Profile, [string[]]$EnableAnalyzers,
          [string[]]$DisableAnalyzers, [string]$Mode, [bool]$Quiet, [string]$OutputFormat)

    $script:Quiet = $Quiet

    if (-not $Path) {
        Write-Log -Level ERROR -Message 'No -Path supplied.'
        return $script:ExitBadInput
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Write-Log -Level ERROR -Message "Path not found or not a folder: $Path"
        return $script:ExitBadInput
    }

    $scanRoot   = (Resolve-Path -LiteralPath $Path).Path
    $reportsDir = Join-Path $scanRoot '.reports'
    Initialize-Log -LogDir (Join-Path $here 'logs') | Out-Null

    Write-Log -Message "media-transfer-scan-tool v0.1.0 (scaffold) - scanning: $scanRoot"

    try {
        $result = Invoke-Scan -Path $scanRoot -Profile $Profile `
            -EnableAnalyzers $EnableAnalyzers -DisableAnalyzers $DisableAnalyzers `
            -Mode $Mode -AnalyzerDir (Join-Path $here 'analyzers') -ReportsDir $reportsDir
    } catch {
        Write-Log -Level ERROR -Message "Scan failed: $_"
        return $script:ExitError
    }

    $reports = Write-Reports -ScanResult $result -ReportsDir $reportsDir
    Write-Log -Message "Reports written to: $reportsDir"
    Show-Status "Overall risk: $($reports.Model.OverallRisk)  |  HTML: $($reports.Html)"

    if ($OutputFormat -eq 'json') { Write-Output $reports.Json }

    return ($reports.Model.OverallRisk -eq 'CLEAN') ? $script:ExitClean : $script:ExitFindings
}

# Guarded main: when dot-sourced (Pester), InvocationName is '.' and we skip running.
if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-Main -Path $Path -Profile $Profile -EnableAnalyzers $EnableAnalyzers `
        -DisableAnalyzers $DisableAnalyzers -Mode $Mode -Quiet:$Quiet.IsPresent -OutputFormat $OutputFormat
    exit $code
}
