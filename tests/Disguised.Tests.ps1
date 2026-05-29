#Requires -Version 7.4
<#
    Pester 5 tests for v0.2 disguised-script detection — content-signature
    classification (signal #3) of scripts hidden in innocent extensions with no
    shebang, plus the false-positive guard on plain prose.
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')   # loads Classify + engine
    $script:Quiet = $true
    $script:Dis   = Join-Path $PSScriptRoot 'fixtures/corpus/disguised'

    function script:Classify([string]$Name) {
        New-Unit -File (Get-Item (Join-Path $script:Dis $Name)) -ScanRoot $script:Dis
    }
}

Describe 'Content-signature detection (no shebang)' {
    It 'detects PowerShell hidden in a .txt' {
        $r = Classify 'readme.txt'
        $r.Unit.DetectedType | Should -Be 'powershell'
        @($r.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' }).Count | Should -Be 1
        ($r.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' })[0].Severity | Should -Be 'HIGH'
    }
    It 'detects bash hidden in a .log' {
        $r = Classify 'output.log'
        $r.Unit.DetectedType | Should -Be 'shell'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
    It 'detects Python hidden in a .dat' {
        $r = Classify 'data.dat'
        $r.Unit.DetectedType | Should -Be 'python'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
    It 'detects a batch script hidden in a .txt' {
        $r = Classify 'notes2.txt'
        $r.Unit.DetectedType | Should -Be 'batch'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'False-positive guard' {
    It 'does NOT flag plain English prose as a disguised script' {
        $r = Classify 'memo.txt'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -Be 0
        $r.Unit.DetectedType | Should -Be 'unsupported'
    }
}

Describe 'Get-ContentSignature — unit behavior' {
    It 'returns null for binary content (NUL bytes)' {
        $bin = Join-Path $env:TEMP "mts-bin-$(Get-Random).dat"
        [System.IO.File]::WriteAllBytes($bin, [byte[]](0,1,2,3,0,255,10,0))
        Get-ContentSignature -Path $bin | Should -BeNullOrEmpty
        Remove-Item $bin -Force
    }
    It 'requires >= 2 distinct signature hits (single keyword is not enough)' {
        $f = Join-Path $env:TEMP "mts-weak-$(Get-Random).txt"
        'The report will print() the totals.' | Set-Content $f -Encoding utf8
        Get-ContentSignature -Path $f | Should -BeNullOrEmpty
        Remove-Item $f -Force
    }
}

Describe 'Engine — disguised scripts routed and flagged end to end' {
    It 'flags all four disguised scripts and clears the prose control under core' {
        $out = Join-Path $env:TEMP "mts-dis-out-$(Get-Random)"
        $result = Invoke-Scan -Path $script:Dis -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $out -Mode offline
        $disguised = @($result.Units | ForEach-Object { $_.Findings } |
                       Where-Object { $_.Category -eq 'disguised-file' })
        $disguised.Count | Should -Be 4
        ($result.Units | Where-Object { $_.Name -eq 'memo.txt' }).Type | Should -Be 'unsupported'
        Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}
