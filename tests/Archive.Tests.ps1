#Requires -Version 7.4
<#
    Pester 5 tests for v0.8 archive hardening (Expand-Archive.ps1):
    zip-slip hard block, decompression-bomb cap, symlink detection,
    nested-archive detection. No provisioning / network needed.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:ArcDir    = Join-Path $PSScriptRoot 'fixtures/corpus/archive'

    function script:Extract([string]$Zip) {
        $stage = Join-Path $env:TEMP "mts-arc-$(Get-Random)"
        $r = Expand-SubmissionArchive -InputFile (Join-Path $script:ArcDir $Zip) -OutputDir $stage
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $r
    }
    function script:HasFinding($Result, $TestID) {
        @($Result.Findings | Where-Object { $_.TestID -eq $TestID }).Count -gt 0
    }
}

Describe 'Archive hardening — decompression bomb' {
    It 'HARD-blocks a decompression bomb (not extracted) and flags MTS-EXTRACT-BOMB' {
        $r = Extract 'bomb.zip'
        $r.Success | Should -BeFalse
        HasFinding $r 'MTS-EXTRACT-BOMB' | Should -BeTrue
    }
}

Describe 'Archive hardening — zip-slip' {
    It 'HARD-blocks a path-traversal archive and flags MTS-EXTRACT-TRAVERSAL' {
        $r = Extract 'traversal.zip'
        $r.Success | Should -BeFalse
        HasFinding $r 'MTS-EXTRACT-TRAVERSAL' | Should -BeTrue
    }
}

Describe 'Archive hardening — symlink + nested (flag, do not block)' {
    It 'flags a symlink entry (MTS-EXTRACT-SYMLINK) and still extracts' {
        $r = Extract 'symlink.zip'
        HasFinding $r 'MTS-EXTRACT-SYMLINK' | Should -BeTrue
        $r.Success | Should -BeTrue
    }
    It 'flags a nested archive (MTS-EXTRACT-NESTED) and still extracts' {
        $r = Extract 'nested.zip'
        HasFinding $r 'MTS-EXTRACT-NESTED' | Should -BeTrue
        $r.Success | Should -BeTrue
    }
}

Describe 'Archive hardening — clean baseline' {
    It 'extracts a clean zip with no archive-hazard findings' {
        $r = Extract 'clean.zip'
        $r.Success | Should -BeTrue
        @($r.Findings | Where-Object { $_.Category -eq 'archive-hazard' }).Count | Should -Be 0
    }
}

Describe 'Archive hardening — engine integration' {
    It 'surfaces the bomb hazard finding through a full engine scan' {
        $out = Join-Path $env:TEMP "mts-arc-eng-$(Get-Random)"
        $result = Invoke-Scan -Path $script:ArcDir -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $out -Mode offline
        $bomb = $result.Units | Where-Object { $_.Name -eq 'bomb.zip' }
        @($bomb.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-BOMB' }).Count | Should -BeGreaterThan 0
        Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}
