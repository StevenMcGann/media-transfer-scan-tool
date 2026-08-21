#Requires -Version 7.4
<#
    Pester 5 tests for the Bandit and DetectSecrets analyzers (deep tier).
    Real-scan tests provision bandit + detect-secrets into a venv (Online tag)
    and run the engine under -Profile full over loose .py source fixtures.
#>

BeforeAll {
    $script:Root    = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    $script:Quiet   = $true
    $script:PySrc   = Join-Path $PSScriptRoot 'fixtures/corpus/pysource'
    $script:Out     = Join-Path $env:TEMP "mts-bs-test-$(Get-Random)"
    $script:VenvDir = Join-Path $env:TEMP "mts-bs-venv-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
}

AfterAll {
    Remove-Item $script:Out     -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $script:VenvDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Bandit / DetectSecrets — tier defaults' {
    It 'both are deep-tier, default-off (excluded under core profile)' {
        $reg = Import-AnalyzerRegistry -AnalyzerDir (Join-Path $Root 'src/analyzers')
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile core
        $sel.DisabledNames | Should -Contain 'Bandit'
        $sel.DisabledNames | Should -Contain 'DetectSecrets'
    }
    It 'both included under -Profile full' {
        $reg = Import-AnalyzerRegistry -AnalyzerDir (Join-Path $Root 'src/analyzers')
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile full
        @($sel.Enabled | ForEach-Object { $_.Name }) | Should -Contain 'Bandit'
        @($sel.Enabled | ForEach-Object { $_.Name }) | Should -Contain 'DetectSecrets'
    }
}

Describe 'Bandit / DetectSecrets — real scan' -Tag 'Online' {

    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:VenvDir
        Update-PipBootstrap -PythonExe $venv.Python
        Install-PipPackage -PythonExe $venv.Python -Package 'bandit'         -MinVersion '1.7.0'
        Install-PipPackage -PythonExe $venv.Python -Package 'detect-secrets' -MinVersion '1.4.0'

        $script:Prov = [PSCustomObject]@{
            Venv  = $venv
            Tools = @{
                'bandit'         = [PSCustomObject]@{ Name='bandit';         Available=$true; ScriptsDir=$venv.Scripts; Version='x' }
                'detect-secrets' = [PSCustomObject]@{ Name='detect-secrets'; Available=$true; ScriptsDir=$venv.Scripts; Version='x' }
            }
        }

        # Installed is not the same as runnable: Application Control / Smart App
        # Control blocks unsigned, no-reputation console shims, and the decision is
        # per-binary, so bandit.exe can be blocked while detect-secrets.exe runs.
        # Probe each one so a blocked tool skips loudly instead of failing as a
        # phantom regression. See tests/TestTools.ps1.
        $script:BanditProbe  = Test-ExternalToolRunnable -ExePath (Join-Path $venv.Scripts 'bandit.exe')
        $script:SecretsProbe = Test-ExternalToolRunnable -ExePath (Join-Path $venv.Scripts 'detect-secrets.exe')
    }

    It 'Bandit flags risky.py (eval / subprocess shell) under -Profile full' {
        Assert-DeepToolOrSkip -Tool 'bandit' -Probe $script:BanditProbe
        $result = Invoke-Scan -Path $script:PySrc -Profile full `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -ProvisionResult $script:Prov
        $risky = $result.Units | Where-Object { $_.Name -eq 'risky.py' }
        $bandit = @($risky.Findings | Where-Object { $_.Tool -eq 'Bandit' -and $_.Category -eq 'risky-code' })
        $bandit.Count | Should -BeGreaterThan 0
    }

    It 'Bandit produces no risky-code findings for clean.py' {
        Assert-DeepToolOrSkip -Tool 'bandit' -Probe $script:BanditProbe
        $result = Invoke-Scan -Path $script:PySrc -Profile full `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -ProvisionResult $script:Prov
        $clean = $result.Units | Where-Object { $_.Name -eq 'clean.py' }
        @($clean.Findings | Where-Object { $_.Tool -eq 'Bandit' -and $_.Category -eq 'risky-code' }).Count |
            Should -Be 0
    }

    It 'DetectSecrets flags secrets.py' {
        Assert-DeepToolOrSkip -Tool 'detect-secrets' -Probe $script:SecretsProbe
        $result = Invoke-Scan -Path $script:PySrc -Profile full `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -ProvisionResult $script:Prov
        $sec = $result.Units | Where-Object { $_.Name -eq 'secrets.py' }
        @($sec.Findings | Where-Object { $_.Tool -eq 'DetectSecrets' -and $_.Category -eq 'secrets' }).Count |
            Should -BeGreaterThan 0
    }

    It 'core profile runs neither analyzer (they stay opt-in)' {
        $result = Invoke-Scan -Path $script:PySrc -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -ProvisionResult $script:Prov
        $all = @($result.Units | ForEach-Object { $_.Findings })
        @($all | Where-Object { $_.Tool -in @('Bandit','DetectSecrets') }).Count | Should -Be 0
        $result.DisabledAnalyzers | Should -Contain 'Bandit'
    }
}
