#Requires -Version 7.4
<#
    Pester 5 tests for the v0.1 engine scaffold. Dot-sources the entry script
    (guarded main is skipped under dot-sourcing) to load engine functions.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    $script:Entry     = Join-Path $Root 'src/Invoke-MediaTransferScan.ps1'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Fixture   = Join-Path $PSScriptRoot 'fixtures/sample'
    . $script:Entry            # loads engine; main is skipped (InvocationName '.')
    $script:Quiet = $true      # silence console logging during tests
    $script:Out   = Join-Path $env:TEMP "mts-test-$(Get-Random)"
}

AfterAll {
    if ($script:Out -and (Test-Path $script:Out)) { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Classification' {
    It 'detects a Python script disguised as .txt and flags it' {
        $result = Invoke-Scan -Path $Fixture -Profile core -AnalyzerDir $Analyzers -ReportsDir $Out
        $notes = $result.Units | Where-Object { $_.Name -eq 'notes.txt' }
        $notes.Type | Should -Be 'python'
        ($notes.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Analyzer registry + tiers' {
    It 'runs FileHash (core) on every unit and excludes Bandit (deep) under core profile' {
        $result = Invoke-Scan -Path $Fixture -Profile core -AnalyzerDir $Analyzers -ReportsDir $Out
        $result.EnabledAnalyzers   | Should -Contain 'FileHash'
        $result.DisabledAnalyzers  | Should -Contain 'Bandit'
        foreach ($u in $result.Units) {
            ($u.Findings | Where-Object { $_.Tool -eq 'FileHash' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'includes Bandit under -Profile full' {
        $result = Invoke-Scan -Path $Fixture -Profile full -AnalyzerDir $Analyzers -ReportsDir $Out
        $result.EnabledAnalyzers | Should -Contain 'Bandit'
    }

    It 'honors -DisableAnalyzers by name' {
        $result = Invoke-Scan -Path $Fixture -Profile core -DisableAnalyzers 'FileHash' -AnalyzerDir $Analyzers -ReportsDir $Out
        $result.EnabledAnalyzers | Should -Not -Contain 'FileHash'
    }
}

Describe 'Reporting' {
    It 'writes JSON, HTML, and TXT reports' {
        $result  = Invoke-Scan -Path $Fixture -Profile core -AnalyzerDir $Analyzers -ReportsDir $Out
        $reports = Write-Reports -ScanResult $result -ReportsDir $Out
        Test-Path $reports.Json | Should -BeTrue
        Test-Path $reports.Html | Should -BeTrue
        Test-Path $reports.Txt  | Should -BeTrue
    }

    It 'JSON carries a schemaVersion' {
        $result  = Invoke-Scan -Path $Fixture -Profile core -AnalyzerDir $Analyzers -ReportsDir $Out
        $reports = Write-Reports -ScanResult $result -ReportsDir $Out
        (Get-Content $reports.Json -Raw | ConvertFrom-Json).SchemaVersion | Should -Not -BeNullOrEmpty
    }

    It 'HTML sets a Content-Security-Policy and never emits unescaped injected markup' {
        # Build a scan result whose finding carries a hostile string.
        $evil = '<script>alert(1)</script>'
        $fake = [PSCustomObject]@{
            ScanRoot = 'X'; StartTime = (Get-Date); EndTime = (Get-Date); Profile = 'core'; Mode = 'online'
            EnabledAnalyzers = @('FileHash'); DisabledAnalyzers = @()
            Units = @([PSCustomObject]@{ Name = 'x'; Type = 'python'; Path = 'x'; Findings = @(
                (New-Finding -Tool 'T' -Category 'risky-code' -Severity 'HIGH' -UnitType 'python' -File $evil -Issue $evil)
            )})
        }
        $reports = Write-Reports -ScanResult $fake -ReportsDir $Out
        $html = Get-Content $reports.Html -Raw
        $html | Should -Match 'Content-Security-Policy'
        $html | Should -Not -Match '<script>alert\(1\)</script>'
        $html | Should -Match '&lt;script&gt;'
    }
}
