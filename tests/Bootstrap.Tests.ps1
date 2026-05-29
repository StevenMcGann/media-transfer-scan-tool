#Requires -Version 7.4
<#
    Tests for the 5.1-safe bootstrapper (runtime resolution) and the full
    Invoke-Provisioning path (the end-to-end provisioning flow that the analyzer
    tests bypass by passing a pre-built ProvisionResult).
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    $script:Bootstrap = Join-Path $Root 'bootstrap.ps1'
    . $script:Bootstrap          # dot-source loads Resolve-EngineRuntime etc.; guarded main skipped
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')   # engine libs for provisioning test
    $script:Quiet = $true
    $script:RealPwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
    if (-not $script:RealPwsh) {
        $script:RealPwsh = "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe"
    }
}

Describe 'Bootstrap — runtime resolution' {
    It 'returns the bundled pwsh when present and valid (bundled is authoritative)' {
        # Use the real pwsh as the "bundled" path — it is a valid >=7.4 runtime.
        $resolved = Resolve-EngineRuntime -BundledPwsh $script:RealPwsh -AllowPath $false
        $resolved | Should -Be $script:RealPwsh
    }

    It 'falls back to PATH pwsh when no bundled copy exists' {
        $resolved = Resolve-EngineRuntime -BundledPwsh 'Z:\does\not\exist\pwsh.exe' -AllowPath $true
        # On the dev host pwsh is resolvable; resolved should be a real path or $null
        if (Get-Command pwsh -ErrorAction SilentlyContinue) {
            $resolved | Should -Not -BeNullOrEmpty
        }
    }

    It 'returns $null when neither bundled nor PATH yields pwsh >= 7.4' {
        Resolve-EngineRuntime -BundledPwsh 'Z:\nope\pwsh.exe' -AllowPath $false | Should -BeNullOrEmpty
    }

    It 'Get-PwshVersion reports a version >= 7.4 for the real runtime' {
        $v = Get-PwshVersion -Exe $script:RealPwsh
        $v | Should -Not -BeNullOrEmpty
        $v -ge [version]'7.4' | Should -BeTrue
    }
}

Describe 'Invoke-Provisioning — full path (regression: non-interactive crash)' -Tag 'Online' {
    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $script:VenvDir = Join-Path $env:TEMP "mts-prov-e2e-$(Get-Random)"
    }
    AfterAll {
        if ($script:VenvDir) { Remove-Item $script:VenvDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'resolves all core pip tools online WITHOUT prompting (no Read-Host crash)' {
        # This is the path the entry script exercises and the analyzer tests skip.
        # Pre-regression it threw "You cannot call a method on a null-valued expression".
        $reg = Import-AnalyzerRegistry -AnalyzerDir (Join-Path $Root 'src/analyzers')
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile core
        # If this threw (the pre-fix Read-Host-on-null crash), the test fails here.
        $prov = Invoke-Provisioning -EnabledAnalyzers $sel.Enabled `
            -VenvDir $script:VenvDir -Mode online
        $prov.Tools['pip-audit'].Available | Should -BeTrue
        $prov.Tools['pefile'].Available    | Should -BeTrue
    }

    It 'offline mode does not install and marks unavailable tools as a coverage gap' {
        $reg = Import-AnalyzerRegistry -AnalyzerDir (Join-Path $Root 'src/analyzers')
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile core
        $freshVenv = Join-Path $env:TEMP "mts-prov-offline-$(Get-Random)"
        $prov = Invoke-Provisioning -EnabledAnalyzers $sel.Enabled -VenvDir $freshVenv -Mode offline
        # Fresh venv, offline → pip tools cannot be installed, so unavailable (not a crash)
        $prov.Tools['pip-audit'].Available | Should -BeFalse
        Remove-Item $freshVenv -Recurse -Force -ErrorAction SilentlyContinue
    }
}
