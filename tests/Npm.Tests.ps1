#Requires -Version 7.4
<#
    Pester 5 tests for the NpmScan analyzer (v0.6).
    Core (lifecycle scripts, JS patterns, tarball) runs offline, no provisioning.
    The OSV dependency-audit layer moved to OsvScan.ps1 (issue #32) — see
    tests/OsvScan.Tests.ps1 for the npm/PyPI/NuGet dependency-audit coverage.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:NpmDir    = Join-Path $PSScriptRoot 'fixtures/corpus/npm'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-npm-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:ScanDir($Sub) {
        Invoke-Scan -Path (Join-Path $script:NpmDir $Sub) -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }
    function script:CountAll($Result, [scriptblock]$Pred) {
        @($Result.Units | ForEach-Object { $_.Findings } | Where-Object $Pred).Count
    }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'npm — package.json lifecycle scripts' {
    It 'flags a postinstall lifecycle script (HIGH)' {
        $r = ScanDir 'malicious'
        $f = @($r.Units | ForEach-Object { $_.Findings } | Where-Object { $_.TestID -eq 'NPM-LIFECYCLE-SCRIPT' })
        $f.Count | Should -BeGreaterThan 0
        ($f | Where-Object { $_.Severity -eq 'HIGH' }).Count | Should -BeGreaterThan 0
    }
    It 'flags the bin shim declaration' {
        CountAll (ScanDir 'malicious') { $_.TestID -eq 'NPM-BIN-SHIM' } | Should -BeGreaterThan 0
    }
    It 'produces no lifecycle/active-content findings for a clean package.json' {
        CountAll (ScanDir 'clean') { $_.Category -eq 'active-content' } | Should -Be 0
    }
}

Describe 'npm — JavaScript risky patterns' {
    It 'flags child_process and eval in a malicious .js' {
        $r = ScanDir 'js'
        $evil = $r.Units | Where-Object { $_.Name -eq 'evil.js' }
        @($evil.Findings | Where-Object { $_.TestID -eq 'NPM-JS-CHILD-PROCESS' }).Count | Should -BeGreaterThan 0
        @($evil.Findings | Where-Object { $_.TestID -eq 'NPM-JS-EVAL' }).Count | Should -BeGreaterThan 0
    }
    It 'produces no risky-code findings for a clean .js' {
        $r = ScanDir 'js'
        $clean = $r.Units | Where-Object { $_.Name -eq 'clean.js' }
        @($clean.Findings | Where-Object { $_.Category -eq 'risky-code' }).Count | Should -Be 0
    }
}

Describe 'npm — tarball extraction' {
    It 'extracts a .tgz and flags the postinstall hook inside package/package.json' {
        CountAll (ScanDir 'tarball') { $_.TestID -eq 'NPM-LIFECYCLE-SCRIPT' } | Should -BeGreaterThan 0
    }
}
