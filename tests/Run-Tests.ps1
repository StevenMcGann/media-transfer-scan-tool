#Requires -Version 7.4
<#
    Run the Pester 5 suite. Usage:  pwsh ./tests/Run-Tests.ps1
#>
param([switch]$CI)

Set-StrictMode -Version Latest

# The suite targets Pester 5.7.1. Pester 6 has behavioral changes that are not
# part of the tested contract. If Pester 5 isn't on pwsh 7's module path, fall
# back to Windows PowerShell user/global module locations.
$pesterPath = $null
$mod = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -eq 5 } |
       Sort-Object Version -Descending | Select-Object -First 1
if ($mod) {
    $pesterPath = $mod.Path
} else {
    foreach ($base in @(
        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\Pester",
        "$env:ProgramFiles\WindowsPowerShell\Modules\Pester")) {
        $cand = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Where-Object { ([version]($_.Name)).Major -eq 5 } |
                Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
        if ($cand) { $pesterPath = Join-Path $cand.FullName 'Pester.psd1'; break }
    }
}
if (-not $pesterPath) { throw 'Pester 5.7.1 not found. Install with: Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser' }
Import-Module $pesterPath -RequiredVersion 5.7.1 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
if ($CI) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $PSScriptRoot 'test-results.xml'
}
Invoke-Pester -Configuration $config
