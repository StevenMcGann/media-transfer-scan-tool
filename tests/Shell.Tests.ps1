#Requires -Version 7.4
<#
    Pester 5 tests for the ShellCheck analyzer (v0.4).
    Layer 2 (risky-pattern rules) runs with no provisioning — always.
    Layer 1 (ShellCheck binary) is exercised in the Online describe block.
#>

BeforeAll {
    $script:Root     = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    $script:Quiet    = $true
    $script:ShellDir = Join-Path $PSScriptRoot 'fixtures/corpus/shell'
    $script:Out      = Join-Path $env:TEMP "mts-shell-out-$(Get-Random)"
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:ShellCount($Result, $Name, [scriptblock]$Pred) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings |
          Where-Object $Pred).Count
    }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'ShellCheck — risky-pattern rules (no ShellCheck binary needed)' {
    BeforeAll {
        # Run offline with ShellCheck unavailable — only the custom rules fire.
        $script:PatternResult = Invoke-Scan -Path $script:ShellDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }

    It 'classifies .sh files as shell type' {
        ($PatternResult.Units | Where-Object { $_.Name -eq 'clean.sh' }).Type | Should -Be 'shell'
    }
    It 'flags curl | bash as SHELL-REMOTE-EXEC (HIGH)' {
        ShellCount $PatternResult 'remote_exec.sh' { $_.TestID -eq 'SHELL-REMOTE-EXEC' } |
            Should -BeGreaterThan 0
    }
    It 'flags base64 -d | bash as SHELL-B64-EXEC (HIGH)' {
        ShellCount $PatternResult 'b64_exec.sh' { $_.TestID -eq 'SHELL-B64-EXEC' } |
            Should -BeGreaterThan 0
    }
    It 'flags eval with expansion as SHELL-EVAL (HIGH)' {
        ShellCount $PatternResult 'eval_expand.sh' { $_.TestID -eq 'SHELL-EVAL' } |
            Should -BeGreaterThan 0
    }
    It 'flags chmod 777 as SHELL-CHMOD-777 (MEDIUM)' {
        ShellCount $PatternResult 'chmod777.sh' { $_.TestID -eq 'SHELL-CHMOD-777' } |
            Should -BeGreaterThan 0
    }
    It 'flags a hardcoded IP as SHELL-HARDCODED-IP (LOW)' {
        ShellCount $PatternResult 'hardcoded_ip.sh' { $_.TestID -eq 'SHELL-HARDCODED-IP' } |
            Should -BeGreaterThan 0
    }
    It 'produces no risky-code findings for a clean script' {
        ShellCount $PatternResult 'clean.sh' { $_.Category -eq 'risky-code' } |
            Should -Be 0
    }
}

Describe 'ShellCheck — binary analysis' -Tag 'Online' {
    # Provision inline in each It block — BeforeAll scoping for venv setup has
    # proven unreliable across Pester sessions (same issue seen in Extraction.Tests).
    # The extra seconds are worth it to avoid silent-nil provisioning.

    It 'ShellCheck finds shell bugs in sc_bugs.sh (unquoted var + backtick)' {
        # sc_bugs.sh has real shell code defects ShellCheck reliably flags:
        # SC2086 (unquoted $var in echo) + SC2006 (backtick substitution).
        # The risky-pattern scripts are syntactically VALID shell, so ShellCheck
        # exits 0 on them — those patterns are intentionally caught by Layer 2.
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $venvPath = Join-Path $env:TEMP "mts-sc-online-$(Get-Random)"
        try {
            $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $venvPath
            Update-PipBootstrap -PythonExe $venv.Python
            Install-PipPackage -PythonExe $venv.Python -Package 'shellcheck-py' -MinVersion '0.9.0' | Out-Null
            # Installed != runnable — see tests/TestTools.ps1.
            Assert-DeepToolOrSkip -Tool 'shellcheck' -Probe (
                Test-ExternalToolRunnable -ExePath (Join-Path $venv.Scripts 'shellcheck.exe'))
            $prov = [PSCustomObject]@{
                Venv  = $venv
                Tools = @{ 'shellcheck-py' = [PSCustomObject]@{
                    Name='shellcheck-py'; Available=$true; ScriptsDir=$venv.Scripts
                    Version=(Get-InstalledPipVersion -PythonExe $venv.Python -PackageName 'shellcheck-py')
                }}
            }
            $result = Invoke-Scan -Path $script:ShellDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -ProvisionResult $prov
            $bugs = $result.Units | Where-Object { $_.Name -eq 'sc_bugs.sh' }
            @($bugs.Findings | Where-Object { $_.TestID -match '^SC\d+' }).Count |
                Should -BeGreaterThan 0
        } finally {
            Remove-Item $venvPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'clean.sh produces no SC error-level (HIGH) findings' {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $venvPath = Join-Path $env:TEMP "mts-sc-clean-$(Get-Random)"
        try {
            $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $venvPath
            Update-PipBootstrap -PythonExe $venv.Python
            Install-PipPackage -PythonExe $venv.Python -Package 'shellcheck-py' -MinVersion '0.9.0' | Out-Null
            # Installed != runnable — see tests/TestTools.ps1.
            Assert-DeepToolOrSkip -Tool 'shellcheck' -Probe (
                Test-ExternalToolRunnable -ExePath (Join-Path $venv.Scripts 'shellcheck.exe'))
            $prov = [PSCustomObject]@{
                Venv  = $venv
                Tools = @{ 'shellcheck-py' = [PSCustomObject]@{
                    Name='shellcheck-py'; Available=$true; ScriptsDir=$venv.Scripts
                    Version=(Get-InstalledPipVersion -PythonExe $venv.Python -PackageName 'shellcheck-py')
                }}
            }
            $result = Invoke-Scan -Path $script:ShellDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -ProvisionResult $prov
            @(($result.Units | Where-Object { $_.Name -eq 'clean.sh' }).Findings |
              Where-Object { $_.TestID -match '^SC\d+' -and $_.Severity -eq 'HIGH' }).Count |
                Should -Be 0
        } finally {
            Remove-Item $venvPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
