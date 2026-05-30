#Requires -Version 7.4
<#
    Pester 5 tests for the PickleOpcodeScan analyzer (v0.7).
    Uses the stdlib helper via system Python — no provisioning, no network.
    Verifies the static-only invariant: a malicious pickle is detected without
    ever being unpickled.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:ModelDir  = Join-Path $PSScriptRoot 'fixtures/corpus/model'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-model-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:ModelCount($Result, $Name, [scriptblock]$Pred) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings | Where-Object $Pred).Count
    }
    $script:R = Invoke-Scan -Path $script:ModelDir -Profile core `
        -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Pickle opcode triage' {
    It 'flags a malicious pickle via REDUCE (CRITICAL) without unpickling it' {
        ModelCount $R 'malicious.pkl' { $_.TestID -eq 'PICKLE-REDUCE' -and $_.Severity -eq 'CRITICAL' } |
            Should -BeGreaterThan 0
    }
    It 'identifies the dangerous os/nt import in the malicious pickle' {
        ModelCount $R 'malicious.pkl' { $_.TestID -eq 'PICKLE-DANGEROUS-IMPORT' } | Should -BeGreaterThan 0
    }
    It 'produces no deserialization findings for a benign pickle' {
        ModelCount $R 'safe.pkl' { $_.Category -eq 'deserialization' } | Should -Be 0
    }
}

Describe 'Model format recognition' {
    It 'recognizes safetensors as a safe-by-design format' {
        ModelCount $R 'model.safetensors' { $_.TestID -eq 'MODEL-SAFE-FORMAT' } | Should -BeGreaterThan 0
    }
    It 'classifies a ZIP-based .pt as a model (not a generic archive)' {
        ($R.Units | Where-Object { $_.Name -eq 'model.pt' }).Type | Should -Be 'model'
    }
    It 'finds the malicious pickle embedded inside a PyTorch .pt zip' {
        ModelCount $R 'model.pt' { $_.TestID -eq 'PICKLE-REDUCE' } | Should -BeGreaterThan 0
    }
}
