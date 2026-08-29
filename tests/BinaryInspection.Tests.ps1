#Requires -Version 7.4
<#
    Pester 5 tests for the BinaryInspection analyzer.
    The real-inspection tests provision pefile/pyelftools into a venv (tagged
    Online) and run the engine end-to-end against native wheel fixtures.
#>

BeforeAll {
    $script:Root    = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet   = $true
    $script:Native  = Join-Path $PSScriptRoot 'fixtures/corpus/native'
    $script:Out     = Join-Path $env:TEMP "mts-bin-test-$(Get-Random)"
    $script:VenvDir = Join-Path $env:TEMP "mts-bin-venv-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:New-BinContext {
        param([hashtable]$Tools = @{}, $Venv = $null)
        [PSCustomObject]@{
            Tools = $Tools; Venv = $Venv; Mode = 'online'; WorkDir = $env:TEMP
            ReportsDir = $script:Out
            HelperDir  = (Join-Path $script:Root 'src/helpers')
            TimeoutSeconds = 300; AdvisoryDbDate = $null
        }
    }
}

AfterAll {
    Remove-Item $script:Out     -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $script:VenvDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'BinaryInspection — unavailable path' {
    It 'returns INFO coverage-gap when tools are unavailable but binaries are present' {
        $desc = & (Join-Path $Root 'src/analyzers/BinaryInspection.ps1')
        # Stage a native binary by extracting a fixture
        $stage = Join-Path $env:TEMP "mts-bin-unavail-$(Get-Random)"
        [void](Expand-SubmissionArchive `
            -InputFile (Join-Path $script:Native 'native_clean_pkg-1.0-py3-none-any.whl') `
            -OutputDir $stage)
        $unit = [PSCustomObject]@{
            Type='python'; Name='native_clean_pkg-1.0-py3-none-any.whl'
            Path='x'; RelativePath='native_clean_pkg-1.0-py3-none-any.whl'; StagingPath=$stage
        }
        $findings = @(& $desc.Invoke $unit (New-BinContext -Tools @{}))
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        ($findings | Where-Object { $_.TestID -eq 'MTS-BININSPECT-UNAVAIL' }).Count | Should -Be 1
    }

    It 'returns empty for a unit with no native binaries' {
        $desc = & (Join-Path $Root 'src/analyzers/BinaryInspection.ps1')
        $stage = Join-Path $env:TEMP "mts-bin-empty-$(Get-Random)"
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        'print("hi")' | Set-Content (Join-Path $stage 'mod.py')
        $unit = [PSCustomObject]@{
            Type='python'; Name='x.whl'; Path='x'; RelativePath='x.whl'; StagingPath=$stage
        }
        $findings = @(& $desc.Invoke $unit (New-BinContext -Tools @{}))
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $findings.Count | Should -Be 0
    }
}

Describe 'BinaryInspection — real inspection' -Tag 'Online' {

    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:VenvDir
        Update-PipBootstrap -PythonExe $venv.Python
        Install-PipPackage -PythonExe $venv.Python -Package 'pefile'     -MinVersion '2023.2.7'
        Install-PipPackage -PythonExe $venv.Python -Package 'pyelftools' -MinVersion '0.29'

        $script:BinProvision = [PSCustomObject]@{
            Venv  = $venv
            Tools = @{
                'pefile'     = [PSCustomObject]@{ Name='pefile';     Available=$true; ScriptsDir=$venv.Scripts; Version='x' }
                'pyelftools' = [PSCustomObject]@{ Name='pyelftools'; Available=$true; ScriptsDir=$venv.Scripts; Version='x' }
            }
        }
    }

    It 'flags process-injection imports as BINARY-SUSPICIOUS-IMPORT (HIGH)' {
        $result = Invoke-Scan -Path $script:Native -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -HelperDir (Join-Path $Root 'src/helpers') -ProvisionResult $script:BinProvision

        $unit = $result.Units | Where-Object { $_.Name -like 'suspicious_imports*' }
        $hits = @($unit.Findings | Where-Object { $_.TestID -eq 'BINARY-SUSPICIOUS-IMPORT' })
        $hits.Count | Should -BeGreaterThan 0
        $hits[0].Severity | Should -Be 'HIGH'
        $hits[0].Category | Should -Be 'native-binary'
    }

    It 'flags network imports as BINARY-NETWORK-IMPORT' {
        $result = Invoke-Scan -Path $script:Native -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -HelperDir (Join-Path $Root 'src/helpers') -ProvisionResult $script:BinProvision
        $unit = $result.Units | Where-Object { $_.Name -like 'network_native*' }
        @($unit.Findings | Where-Object { $_.TestID -eq 'BINARY-NETWORK-IMPORT' }).Count |
            Should -BeGreaterThan 0
    }

    It 'flags a fake .pyd as BINARY-INVALID-FORMAT (HIGH)' {
        $result = Invoke-Scan -Path $script:Native -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -HelperDir (Join-Path $Root 'src/helpers') -ProvisionResult $script:BinProvision
        $unit = $result.Units | Where-Object { $_.Name -like 'fake_native*' }
        @($unit.Findings | Where-Object { $_.TestID -eq 'BINARY-INVALID-FORMAT' }).Count |
            Should -BeGreaterThan 0
    }

    It 'produces no suspicious findings for a clean native package' {
        $result = Invoke-Scan -Path $script:Native -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -HelperDir (Join-Path $Root 'src/helpers') -ProvisionResult $script:BinProvision
        $unit = $result.Units | Where-Object { $_.Name -like 'native_clean*' }
        # No HIGH/MEDIUM binary findings for the clean baseline
        @($unit.Findings | Where-Object {
            $_.Category -eq 'native-binary' -and $_.Severity -in @('HIGH','MEDIUM')
        }).Count | Should -Be 0
    }
}
