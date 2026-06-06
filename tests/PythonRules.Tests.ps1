#Requires -Version 7.4
<#
    Pester 5 tests for the PythonRules analyzer (core middle-tier).
    Uses the stdlib AST helper scan_python.py via system Python — no provisioning,
    no network. Verifies high-signal detection AND AST precision (no false hits on
    trigger words inside strings/comments).
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:PyDir     = Join-Path $PSScriptRoot 'fixtures/corpus/python_rules'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-pyrules-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:PyCount($Result, $Name, [scriptblock]$Pred) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings | Where-Object $Pred).Count
    }

    $script:HasPython = [bool](Find-Python)
    $script:R = Invoke-Scan -Path $script:PyDir -Profile core `
        -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'PythonRules — high-signal detection (AST helper)' {
    BeforeEach { if (-not $script:HasPython) { Set-ItResult -Skipped -Because 'Python not found' } }

    It 'classifies loose .py as python' {
        ($R.Units | Where-Object { $_.Name -eq 'pyr_malicious.py' }).Type | Should -Be 'python'
    }
    It 'flags eval() as PY-EVAL (HIGH)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-EVAL' -and $_.Severity -eq 'HIGH' } | Should -BeGreaterThan 0
    }
    It 'flags os.system() as PY-OS-SYSTEM (HIGH)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-OS-SYSTEM' } | Should -BeGreaterThan 0
    }
    It 'flags subprocess shell=True as PY-SUBPROCESS-SHELL (HIGH)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-SUBPROCESS-SHELL' } | Should -BeGreaterThan 0
    }
    It 'flags pickle load as PY-PICKLE-LOAD (deserialization)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-PICKLE-LOAD' -and $_.Category -eq 'deserialization' } | Should -BeGreaterThan 0
    }
    It 'raises the download-and-run combination (PY-DOWNLOAD-EXEC)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-DOWNLOAD-EXEC' } | Should -BeGreaterThan 0
    }
    It 'raises the decode-then-exec combination (PY-DECODE-EXEC)' {
        PyCount $R 'pyr_malicious.py' { $_.TestID -eq 'PY-DECODE-EXEC' } | Should -BeGreaterThan 0
    }
}

Describe 'PythonRules — precision (no false positives)' {
    BeforeEach { if (-not $script:HasPython) { Set-ItResult -Skipped -Because 'Python not found' } }

    It 'does not flag safe subprocess use in a clean file' {
        PyCount $R 'pyr_clean.py' { $_.Category -in @('risky-code','deserialization','obfuscation','network') } | Should -Be 0
    }
    It 'does not flag trigger words that appear only in strings/comments' {
        PyCount $R 'pyr_strings.py' { $_.Category -in @('risky-code','deserialization','obfuscation','network') } | Should -Be 0
    }
}
