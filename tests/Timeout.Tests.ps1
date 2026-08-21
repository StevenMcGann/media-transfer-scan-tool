#Requires -Version 7.4
<#
    F2 / issue #9 — external-tool timeout enforcement.
    Invoke-BoundedProcess must bound runtime and kill the process tree on expiry,
    and an analyzer whose tool hangs must emit MTS-ANALYZER-TIMEOUT and let the
    scan continue instead of stalling the batch.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:Py        = (Find-Python)
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
}

Describe 'Deep-tier tool gate (tests/TestTools.ps1)' {
    <#
        This guard only fires on a host whose Application Control policy blocks a
        tool binary, so on a healthy host it would never be exercised — and an
        unexercised skip path is worthless. These tests drive it directly.
    #>
    It 'reports a stub binary that cannot execute as not runnable' {
        $dir = Join-Path $env:TEMP "mts-gate-$(Get-Random)"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $stub = Join-Path $dir 'bandit.exe'
            Set-Content -LiteralPath $stub -Value '' -NoNewline
            $probe = Test-ExternalToolRunnable -ExePath $stub
            $probe.Runnable | Should -BeFalse
            $probe.Reason   | Should -Not -BeNullOrEmpty
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'throws instead of skipping when MTS_REQUIRE_DEEP_TOOLS is set' {
        $saved = $env:MTS_REQUIRE_DEEP_TOOLS
        try {
            $env:MTS_REQUIRE_DEEP_TOOLS = '1'
            $probe = [PSCustomObject]@{ Runnable = $false; Reason = 'blocked by policy' }
            { Assert-DeepToolOrSkip -Tool 'bandit' -Probe $probe } |
                Should -Throw -ExpectedMessage '*MTS_REQUIRE_DEEP_TOOLS*'
        } finally { $env:MTS_REQUIRE_DEEP_TOOLS = $saved }
    }
    It 'passes straight through when the tool is runnable' {
        $probe = [PSCustomObject]@{ Runnable = $true; Reason = '' }
        { Assert-DeepToolOrSkip -Tool 'bandit' -Probe $probe } | Should -Not -Throw
    }
}

Describe 'Invoke-BoundedProcess' {
    BeforeEach { if (-not $script:Py) { Set-ItResult -Skipped -Because 'Python not found' } }

    It 'returns stdout and exit code for a fast command' {
        $r = Invoke-BoundedProcess -FilePath $script:Py -Arguments @('-c', 'print("hi")') -TimeoutSeconds 10
        $r.TimedOut | Should -BeFalse
        $r.ExitCode | Should -Be 0
        $r.StdOut.Trim() | Should -Be 'hi'
    }
    It 'preserves a non-zero exit code' {
        $r = Invoke-BoundedProcess -FilePath $script:Py -Arguments @('-c', 'import sys; sys.exit(3)') -TimeoutSeconds 10
        $r.TimedOut | Should -BeFalse
        $r.ExitCode | Should -Be 3
    }
    It 'reports Started=$true for a process that launches' {
        $r = Invoke-BoundedProcess -FilePath $script:Py -Arguments @('-c', 'pass') -TimeoutSeconds 10
        $r.Started | Should -BeTrue
        $r.StartError | Should -BeNullOrEmpty
    }
    It 'returns Started=$false instead of throwing when the process cannot launch' {
        # The real-world trigger is an Application Control / Smart App Control
        # policy blocking an unsigned tool binary; a missing path exercises the
        # same code path deterministically.
        $missing = Join-Path $env:TEMP "mts-does-not-exist-$(Get-Random).exe"
        $r = Invoke-BoundedProcess -FilePath $missing -Arguments @('--version') -TimeoutSeconds 10
        $r.Started    | Should -BeFalse
        $r.StartError | Should -Not -BeNullOrEmpty
        $r.TimedOut   | Should -BeFalse
        $r.ExitCode   | Should -BeNullOrEmpty
    }
    It 'separates stdout from stderr' {
        $r = Invoke-BoundedProcess -FilePath $script:Py -Arguments @('-c', 'import sys; sys.stderr.write("err"); print("out")') -TimeoutSeconds 10
        $r.StdOut.Trim() | Should -Be 'out'
        $r.StdErr        | Should -Match 'err'
    }
    It 'times out and kills a hanging process well before it would finish' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r  = Invoke-BoundedProcess -FilePath $script:Py -Arguments @('-c', 'import time; time.sleep(30)') -TimeoutSeconds 2
        $sw.Stop()
        $r.TimedOut | Should -BeTrue
        $r.ExitCode | Should -BeNullOrEmpty
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 15   # killed, not run to completion (~30s)
    }
}

Describe 'New-TimeoutFinding' {
    It 'is a HIGH-severity MTS-ANALYZER-TIMEOUT finding' {
        $f = New-TimeoutFinding -Tool 'Bandit' -UnitType 'python' -File 'x.py' -TimeoutSeconds 5
        $f.TestID   | Should -Be 'MTS-ANALYZER-TIMEOUT'
        $f.Severity | Should -Be 'HIGH'
        $f.Tool     | Should -Be 'Bandit'
    }
}

Describe 'New-ToolBlockedFinding' {
    It 'is a HIGH-severity MTS-TOOL-BLOCKED finding' {
        $f = New-ToolBlockedFinding -Tool 'Bandit' -UnitType 'python' -File 'x.py' -Reason 'blocked by policy'
        $f.TestID   | Should -Be 'MTS-TOOL-BLOCKED'
        $f.Severity | Should -Be 'HIGH'
        $f.Category | Should -Be 'parser'
        $f.Tool     | Should -Be 'Bandit'
    }
    It 'says the unit was not analyzed and carries the underlying reason' {
        $f = New-ToolBlockedFinding -Tool 'Bandit' -UnitType 'python' -File 'x.py' `
                -Reason 'An Application Control policy has blocked this file.'
        # The whole point is that a blocked tool cannot read as "ran, found nothing".
        $f.Issue | Should -Match 'NOT analyzed'
        $f.Issue | Should -Match 'Application Control'
    }
}

Describe 'Analyzer integration — a blocked tool is reported, not silent' {
    It 'emits MTS-TOOL-BLOCKED (HIGH) when the tool binary cannot be started' {
        $dir = Join-Path $env:TEMP "mts-blocked-$(Get-Random)"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'x.py') -Value 'import os'
        $out = Join-Path $env:TEMP "mts-blocked-out-$(Get-Random)"
        try {
            # Point the analyzer at a ScriptsDir whose bandit.exe exists but cannot
            # run — a zero-byte file reproduces the "could not start" result the
            # way an Application Control block does in the field.
            $fakeScripts = Join-Path $dir 'Scripts'
            New-Item -ItemType Directory -Path $fakeScripts -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $fakeScripts 'bandit.exe') -Value '' -NoNewline

            $prov = [PSCustomObject]@{
                Venv  = $null
                Tools = @{ 'bandit' = [PSCustomObject]@{
                    Name='bandit'; Available=$true; ScriptsDir=$fakeScripts; Version='x' } }
            }
            $r = Invoke-Scan -Path $dir -Profile full -AnalyzerDir $script:Analyzers `
                    -ReportsDir $out -Mode offline -ProvisionResult $prov
            $blocked = @($r.Units | ForEach-Object { $_.Findings } |
                         Where-Object { $_.TestID -eq 'MTS-TOOL-BLOCKED' -and $_.Tool -eq 'Bandit' })
            $blocked.Count       | Should -BeGreaterThan 0
            $blocked[0].Severity | Should -Be 'HIGH'
        } finally {
            Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Analyzer timeout integration (PythonRules + hanging helper)' {
    BeforeEach { if (-not $script:Py) { Set-ItResult -Skipped -Because 'Python not found' } }

    It 'emits MTS-ANALYZER-TIMEOUT when the helper hangs, and does not throw' {
        $helperDir = Join-Path $env:TEMP "mts-to-helper-$(Get-Random)"
        New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
        # A scan_python.py that ignores its args and just hangs.
        Set-Content -LiteralPath (Join-Path $helperDir 'scan_python.py') `
            -Value @('import time', 'time.sleep(30)') -Encoding utf8
        $srcPy = Join-Path $env:TEMP "mts-to-src-$(Get-Random).py"
        Set-Content -LiteralPath $srcPy -Value 'x = 1' -Encoding utf8
        try {
            $unit = [PSCustomObject]@{ Path = $srcPy; RelativePath = 'evil.py'; StagingPath = $null; Type = 'python' }
            $ctx  = [PSCustomObject]@{ Venv = [PSCustomObject]@{ Python = $script:Py }; HelperDir = $helperDir; TimeoutSeconds = 1 }
            $pr   = & (Join-Path $script:Analyzers 'PythonRules.ps1')
            $out  = & $pr.Invoke $unit $ctx
            @($out | Where-Object { $_.TestID -eq 'MTS-ANALYZER-TIMEOUT' }).Count | Should -BeGreaterThan 0
        } finally {
            Remove-Item $helperDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $srcPy -Force -ErrorAction SilentlyContinue
        }
    }
}
