#Requires -Version 7.4
<#
.SYNOPSIS
    media-transfer-scan-tool - static security scanner for media-transfer review.
.DESCRIPTION
    Engine entry point: discover -> classify -> dispatch -> render.
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
.PARAMETER AutoInstall
    Compatibility switch. Online mode provisions missing pinned tools without
    prompting; offline mode never installs them.
.PARAMETER OutputFormat
    'all' (default) or 'json' to also echo the JSON report path for capture.
.PARAMETER KevCatalogPath
    Operator-supplied CISA KEV catalog JSON. Wins over any download; required for
    KEV coverage on an air-gapped host without a vendored catalog.
.PARAMETER KevCatalogUrl
    Pin KEV retrieval to one URL (an internal mirror) instead of the default
    cisa.gov -> cisagov/kev-data order. Online mode only.
.NOTES
    Version : 0.15.0
#>
[CmdletBinding()]
param(
    [string]$Path,
    [ValidateSet('core', 'full')][string]$Profile = 'core',
    [string[]]$EnableAnalyzers = @(),
    [string[]]$DisableAnalyzers = @(),
    [ValidateSet('online', 'offline')][string]$Mode = 'online',
    [switch]$AutoInstall,
    [string]$VenvDir = '',   # override scanner venv location (offline bundle points at its vendored venv)
    [switch]$Quiet,
    [ValidateSet('all', 'json')][string]$OutputFormat = 'all',
    [string]$KevCatalogPath = '',
    [string]$KevCatalogUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Single source of truth for the tool version (keep in sync with the .NOTES block,
# CHANGELOG, and the git tag). Report schemaVersion is tracked separately in Report.ps1.
$script:ToolVersion = '0.15.0'

# --- Load engine ------------------------------------------------------------
$here = $PSScriptRoot
foreach ($lib in 'Logging', 'Findings', 'Process', 'Classify', 'Registry', 'Provisioning', 'Expand-Archive', 'Notebook', 'Osv', 'Kev', 'DependencyMetadata', 'Report', 'Engine') {
    . (Join-Path $here "lib/$lib.ps1")
}

# Exit codes (documented in docs/contract.md).
$script:ExitClean   = 0
$script:ExitFindings = 10
$script:ExitError   = 2
$script:ExitBadInput = 3

function Invoke-Main {
    param([string]$Path, [string]$Profile, [string[]]$EnableAnalyzers,
          [string[]]$DisableAnalyzers, [string]$Mode, [bool]$AutoInstall,
          [string]$VenvDir, [bool]$Quiet, [string]$OutputFormat,
          [string]$KevCatalogPath = '', [string]$KevCatalogUrl = '')

    $script:Quiet = $Quiet

    if (-not $Path) {
        Write-Log -Level ERROR -Message 'No -Path supplied.'
        return $script:ExitBadInput
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        Write-Log -Level ERROR -Message "Path not found or not a folder: $Path"
        return $script:ExitBadInput
    }

    $scanRoot   = (Resolve-Path -LiteralPath $Path).ProviderPath
    $reportsDir = Join-Path $scanRoot '.reports'
    Initialize-Log -LogDir (Join-Path $here 'logs') | Out-Null

    Write-Log -Message "media-transfer-scan-tool v$($script:ToolVersion) - scanning: $scanRoot"

    # ── Registry + provisioning (before scan so Context.Tools is populated) ──
    $registry = Import-AnalyzerRegistry -AnalyzerDir (Join-Path $here 'analyzers')
    $sel      = Resolve-EnabledAnalyzers -Registry $registry -Profile $Profile `
                    -EnableAnalyzers $EnableAnalyzers -DisableAnalyzers $DisableAnalyzers

    # Venv: caller override (offline bundle's vendored venv) or default beside the engine.
    $effectiveVenv = if ($VenvDir) { $VenvDir } else { Join-Path $here '.scan-venv' }

    $provision = $null
    $analyzersNeedingTools = @($sel.Enabled | Where-Object { $_.RequiredTools.Count -gt 0 })
    if ($analyzersNeedingTools.Count -gt 0) {
        Show-Status 'Provisioning scanner tools...'
        try {
            $provision = Invoke-Provisioning `
                -EnabledAnalyzers $sel.Enabled `
                -VenvDir          $effectiveVenv `
                -Mode             $Mode `
                -AutoInstall:     $AutoInstall
        } catch {
            Write-Log -Level ERROR -Message "Provisioning failed: $_"
            return $script:ExitError
        }
    }

    # ── CISA KEV catalog (issue #41) ────────────────────────────────────────
    # Resolved once per scan, and only when the analyzer that consumes it runs.
    # Never fatal: Get-KevCatalog returns $null and OsvScan reports the gap.
    $kevCatalog = $null
    if (@($sel.Enabled | Where-Object { $_.Name -eq 'OsvScan' }).Count -gt 0) {
        $kevCatalog = Get-KevCatalog -Mode $Mode -CatalogPath $KevCatalogPath -CatalogUrl $KevCatalogUrl `
            -VendoredPath (Join-Path (Split-Path $here -Parent) $script:KevVendoredRel)
    }

    try {
        $result = Invoke-Scan -Path $scanRoot -Profile $Profile `
            -EnableAnalyzers $EnableAnalyzers -DisableAnalyzers $DisableAnalyzers `
            -Mode $Mode -AnalyzerDir (Join-Path $here 'analyzers') -ReportsDir $reportsDir `
            -HelperDir (Join-Path $here 'helpers') -ProvisionResult $provision -KevCatalog $kevCatalog
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
        -DisableAnalyzers $DisableAnalyzers -Mode $Mode -AutoInstall:$AutoInstall.IsPresent `
        -VenvDir $VenvDir -Quiet:$Quiet.IsPresent -OutputFormat $OutputFormat `
        -KevCatalogPath $KevCatalogPath -KevCatalogUrl $KevCatalogUrl
    exit $code
}
