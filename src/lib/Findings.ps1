#Requires -Version 7.4
<#
    Findings.ps1 - normalized finding schema (PLAN §3.3) + risk roll-up.
#>

# Severity ordering, highest first. Used for risk roll-up and report sorting.
$script:SeverityRank = [ordered]@{
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1
}

$script:ValidCategories = @(
    'secrets', 'risky-code', 'vuln-dependency', 'native-binary',
    'deserialization', 'macro', 'active-content', 'disguised-file',
    'archive-hazard', 'parser'
)

function New-Finding {
    <#
        Factory for a single normalized finding. Every analyzer returns these.
    #>
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$Category,
        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$Severity = 'INFO',
        [ValidateSet('HIGH', 'MEDIUM', 'LOW')]
        [string]$Confidence = 'MEDIUM',
        [string]$UnitType = '',
        [string]$File = '',
        [Nullable[int]]$Line = $null,
        [Parameter(Mandatory)][string]$Issue,
        [string]$TestID = '',
        [string]$Recommendation = ''
    )
    [PSCustomObject]@{
        Tool           = $Tool
        Category       = $Category
        Severity       = $Severity
        Confidence     = $Confidence
        UnitType       = $UnitType
        File           = $File
        Line           = $Line
        Issue          = $Issue
        TestID         = $TestID
        Recommendation = $Recommendation
    }
}

function Get-RiskLevel {
    <#
        Roll a set of findings up to a single overall risk band = the highest
        severity present. Returns 'CLEAN' when there are no actionable findings.
    #>
    param([object[]]$Findings)
    $actionable = @($Findings | Where-Object { $_ -and $_.Severity -ne 'INFO' })
    if ($actionable.Count -eq 0) { return 'CLEAN' }
    $top = $actionable | Sort-Object { $script:SeverityRank[$_.Severity] } -Descending | Select-Object -First 1
    return $top.Severity
}
