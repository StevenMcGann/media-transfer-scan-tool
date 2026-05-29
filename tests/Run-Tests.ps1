#Requires -Version 7.4
<#
    Run the Pester 5 suite. Usage:  pwsh ./tests/Run-Tests.ps1
#>
param([switch]$CI)

Set-StrictMode -Version Latest

# Pester 5 is cross-edition. If it isn't on pwsh 7's module path, fall back to
# the Windows PowerShell user/global module locations (dev convenience only;
# the offline bundle will vendor its own copy).
$pesterPath = $null
$mod = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 } |
       Sort-Object Version -Descending | Select-Object -First 1
if ($mod) {
    $pesterPath = $mod.Path
} else {
    foreach ($base in @(
        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\Pester",
        "$env:ProgramFiles\WindowsPowerShell\Modules\Pester")) {
        $cand = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Where-Object { [version]($_.Name) -ge [version]'5.0' } |
                Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
        if ($cand) { $pesterPath = Join-Path $cand.FullName 'Pester.psd1'; break }
    }
}
if (-not $pesterPath) { throw 'Pester 5+ not found. Install with: Install-Module Pester -Scope CurrentUser' }
Import-Module $pesterPath -MinimumVersion 5.0 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Output.Verbosity = 'Detailed'
if ($CI) {
    $config.Run.Exit = $true
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $PSScriptRoot 'test-results.xml'
}
Invoke-Pester -Configuration $config
