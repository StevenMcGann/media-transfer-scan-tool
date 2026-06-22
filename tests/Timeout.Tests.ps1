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
