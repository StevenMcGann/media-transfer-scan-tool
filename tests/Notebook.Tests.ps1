#Requires -Version 7.4
<#
    Pester 5 tests for Jupyter notebook code-cell projection (Notebook.ps1)
    and its integration into the engine pre-dispatch step.
#>

BeforeAll {
    $script:Root    = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    $script:Quiet   = $true
    $script:NbDir   = Join-Path $PSScriptRoot 'fixtures/corpus/notebook'
    $script:Out     = Join-Path $env:TEMP "mts-nb-test-$(Get-Random)"
    $script:VenvDir = Join-Path $env:TEMP "mts-nb-venv-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
}

AfterAll {
    Remove-Item $script:Out     -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $script:VenvDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Convert-NotebookToPythonSource' {
    It 'projects code cells into a .py and succeeds for a clean notebook' {
        $proj = Join-Path $env:TEMP "mts-nbproj-$(Get-Random)"
        $r = Convert-NotebookToPythonSource -NotebookPath (Join-Path $NbDir 'nb_clean.ipynb') `
            -OutputRoot $proj -OutputName 'nb_clean.py' -RelPath 'nb_clean.ipynb'
        $r.Success | Should -BeTrue
        Test-Path $r.SourcePath | Should -BeTrue
        (Get-Content $r.SourcePath -Raw) | Should -Match 'x = 1 \+ 1'
        Remove-Item $proj -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'flags saved outputs as NOTEBOOK-SAVED-OUTPUT' {
        $proj = Join-Path $env:TEMP "mts-nbproj-$(Get-Random)"
        $r = Convert-NotebookToPythonSource -NotebookPath (Join-Path $NbDir 'nb_outputs.ipynb') `
            -OutputRoot $proj -RelPath 'nb_outputs.ipynb'
        @($r.Findings | Where-Object { $_.TestID -eq 'NOTEBOOK-SAVED-OUTPUT' }).Count | Should -BeGreaterThan 0
        Remove-Item $proj -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'flags a malformed notebook as NOTEBOOK-MALFORMED and Success=$false' {
        $proj = Join-Path $env:TEMP "mts-nbproj-$(Get-Random)"
        $r = Convert-NotebookToPythonSource -NotebookPath (Join-Path $NbDir 'nb_malformed.ipynb') `
            -OutputRoot $proj -RelPath 'nb_malformed.ipynb'
        $r.Success | Should -BeFalse
        @($r.Findings | Where-Object { $_.TestID -eq 'NOTEBOOK-MALFORMED' }).Count | Should -Be 1
        Remove-Item $proj -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'does NOT execute the notebook (projection is static text only)' {
        # Projection must be pure text transformation — assert the generated file
        # contains the source verbatim, not any execution result.
        $proj = Join-Path $env:TEMP "mts-nbproj-$(Get-Random)"
        $r = Convert-NotebookToPythonSource -NotebookPath (Join-Path $NbDir 'nb_eval.ipynb') `
            -OutputRoot $proj -RelPath 'nb_eval.ipynb'
        (Get-Content $r.SourcePath -Raw) | Should -Match 'eval\(user\)'
        Remove-Item $proj -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Engine — notebook units' {
    It 'classifies .ipynb as a python unit and emits NotebookParser findings under core' {
        $result = Invoke-Scan -Path $script:NbDir -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out
        $outputs = $result.Units | Where-Object { $_.Name -eq 'nb_outputs.ipynb' }
        $outputs.Type | Should -Be 'python'
        @($outputs.Findings | Where-Object { $_.Tool -eq 'NotebookParser' -and $_.TestID -eq 'NOTEBOOK-SAVED-OUTPUT' }).Count |
            Should -BeGreaterThan 0
    }

    It 'reports a malformed notebook without aborting the scan' {
        $result = Invoke-Scan -Path $script:NbDir -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out
        $mal = $result.Units | Where-Object { $_.Name -eq 'nb_malformed.ipynb' }
        @($mal.Findings | Where-Object { $_.TestID -eq 'NOTEBOOK-MALFORMED' }).Count | Should -Be 1
        # Other notebooks still processed
        ($result.Units | Where-Object { $_.Name -eq 'nb_clean.ipynb' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Engine — notebook code scanned via projection' -Tag 'Online' {
    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:VenvDir
        Update-PipBootstrap -PythonExe $venv.Python
        Install-PipPackage -PythonExe $venv.Python -Package 'bandit' -MinVersion '1.7.0'
        $script:Prov = [PSCustomObject]@{
            Venv  = $venv
            Tools = @{ 'bandit' = [PSCustomObject]@{ Name='bandit'; Available=$true; ScriptsDir=$venv.Scripts; Version='x' } }
        }
        # Installed != runnable on an Application Control host — see tests/TestTools.ps1.
        $script:BanditProbe = Test-ExternalToolRunnable -ExePath (Join-Path $venv.Scripts 'bandit.exe')
    }

    It 'Bandit flags eval() inside a notebook code cell under -Profile full' {
        Assert-DeepToolOrSkip -Tool 'bandit' -Probe $script:BanditProbe
        $result = Invoke-Scan -Path $script:NbDir -Profile full `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $script:Out `
            -ProvisionResult $script:Prov
        $nbEval = $result.Units | Where-Object { $_.Name -eq 'nb_eval.ipynb' }
        @($nbEval.Findings | Where-Object { $_.Tool -eq 'Bandit' -and $_.Category -eq 'risky-code' }).Count |
            Should -BeGreaterThan 0
    }
}
