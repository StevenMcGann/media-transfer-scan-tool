#Requires -Version 7.4
<#
    Pester 5 tests for the PSScriptAnalyzer analyzer (v0.5).
    Layers 2 (custom rules) + 3 (Authenticode) run with no provisioning.
    Layer 1 (PSScriptAnalyzer module) is exercised in the Online describe block.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:PsDir     = Join-Path $PSScriptRoot 'fixtures/corpus/powershell'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-ps-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:PsCount($Result, $Name, [scriptblock]$Pred) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings | Where-Object $Pred).Count
    }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'PowerShell custom rules + signature (no provisioning)' {
    BeforeAll {
        $script:R = Invoke-Scan -Path $script:PsDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }

    It 'classifies .ps1 as powershell' {
        ($R.Units | Where-Object { $_.Name -eq 'clean.ps1' }).Type | Should -Be 'powershell'
    }
    It 'flags IEX + DownloadString cradle (PS-IEX)' {
        PsCount $R 'downloader.ps1' { $_.TestID -eq 'PS-IEX' } | Should -BeGreaterThan 0
        PsCount $R 'downloader.ps1' { $_.TestID -eq 'PS-DOWNLOAD' } | Should -BeGreaterThan 0
    }
    It 'flags -EncodedCommand and hidden window' {
        PsCount $R 'encoded.ps1' { $_.TestID -eq 'PS-ENCODED-COMMAND' } | Should -BeGreaterThan 0
        PsCount $R 'encoded.ps1' { $_.TestID -eq 'PS-HIDDEN-WINDOW' } | Should -BeGreaterThan 0
    }
    It 'flags AMSI tampering and base64 decode' {
        PsCount $R 'amsi.ps1' { $_.TestID -eq 'PS-AMSI-TAMPER' } | Should -BeGreaterThan 0
        PsCount $R 'amsi.ps1' { $_.TestID -eq 'PS-BASE64-DECODE' } | Should -BeGreaterThan 0
    }
    It 'flags Defender tampering' {
        PsCount $R 'defender.ps1' { $_.TestID -eq 'PS-DEFENDER-TAMPER' } | Should -BeGreaterThan 0
    }
    It 'records an Authenticode signature status for each script' {
        PsCount $R 'clean.ps1' { $_.Tool -eq 'Authenticode' } | Should -BeGreaterThan 0
    }
    It 'produces no risky-code findings for a clean script' {
        PsCount $R 'clean.ps1' { $_.Category -eq 'risky-code' } | Should -Be 0
    }
}

Describe 'PowerShell — PSScriptAnalyzer module' -Tag 'Online' {
    It 'PSScriptAnalyzer flags the IEX downloader and needs no Python venv' {
        # Provisioning a psmodule-only analyzer must NOT require Python.
        $reg = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile core `
                   -EnableAnalyzers @() -DisableAnalyzers @('PipAudit','BinaryInspection','OleVbaScan','ShellCheck','FileHash')
        $prov = Invoke-Provisioning -EnabledAnalyzers $sel.Enabled `
            -VenvDir (Join-Path $env:TEMP "mts-ps-venv-$(Get-Random)") -Mode online
        $prov.Venv | Should -BeNullOrEmpty   # no pip tools -> no venv created
        $prov.Tools['PSScriptAnalyzer'].Available | Should -BeTrue

        $result = Invoke-Scan -Path $script:PsDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -ProvisionResult $prov
        # PSScriptAnalyzer flags Invoke-Expression (PSAvoidUsingInvokeExpression) etc.
        @($result.Units | ForEach-Object { $_.Findings } |
          Where-Object { $_.Tool -eq 'PSScriptAnalyzer' -and $_.TestID -like 'PS*' }).Count |
            Should -BeGreaterThan 0
    }
}
