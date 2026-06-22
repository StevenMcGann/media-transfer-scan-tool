#Requires -Version 7.4
<#
    F3 / issue #10 — dependency version pinning. dependency-pins.psd1 is the single
    source of truth; provisioning installs exactly these versions (pkg==version)
    instead of latest, and PSGallery modules via -RequiredVersion.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:Analyzers = Join-Path $Root 'src/analyzers'
}

Describe 'Dependency pins (offline)' {
    It 'loads with non-empty pip and psmodule maps' {
        $pins = Get-DependencyPins
        @($pins.pip.Keys).Count      | Should -BeGreaterThan 0
        @($pins.psmodule.Keys).Count | Should -BeGreaterThan 0
    }
    It 'ships under src/ so it is bundled and sealed by the F1 integrity check' {
        Test-Path -LiteralPath (Join-Path $Root 'src/dependency-pins.psd1') | Should -BeTrue
    }
    It 'pins every pip tool that an analyzer requires' {
        $pins = Get-DependencyPins
        $reg  = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        $pipTools = $reg | ForEach-Object { $_.RequiredTools } |
            Where-Object { $_ -and $_.Kind -eq 'pip' } | ForEach-Object { $_.Id } | Sort-Object -Unique
        foreach ($t in $pipTools) {
            $pins.pip[$t] | Should -Not -BeNullOrEmpty -Because "pip tool '$t' must have an exact pin"
        }
    }
    It 'pins every psmodule tool that an analyzer requires' {
        $pins = Get-DependencyPins
        $reg  = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        $psTools = $reg | ForEach-Object { $_.RequiredTools } |
            Where-Object { $_ -and $_.Kind -eq 'psmodule' } | ForEach-Object { $_.Id } | Sort-Object -Unique
        foreach ($t in $psTools) {
            $pins.psmodule[$t] | Should -Not -BeNullOrEmpty -Because "psmodule '$t' must have an exact pin"
        }
    }
    It 'each pinned version satisfies the analyzer MinVersion floor' {
        $pins = Get-DependencyPins
        $reg  = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        foreach ($a in $reg) {
            foreach ($rt in @($a.RequiredTools | Where-Object { $_ -and $_.Kind -in @('pip', 'psmodule') })) {
                $map = if ($rt.Kind -eq 'pip') { $pins.pip } else { $pins.psmodule }
                $pin = $map[$rt.Id]
                if ($pin -and $rt.MinVersion) {
                    ([version]$pin) -ge ([version]$rt.MinVersion) |
                        Should -BeTrue -Because "$($rt.Id) pin $pin must be >= floor $($rt.MinVersion)"
                }
            }
        }
    }
}

Describe 'Pinned provisioning (online)' -Tag 'Online' {
    BeforeAll { $script:Py = Find-Python }

    It 'installs core pip tools at exactly the pinned versions' {
        if (-not $script:Py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        $pins = (Get-DependencyPins).pip
        $reg  = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        $sel  = Resolve-EnabledAnalyzers -Registry $reg -Profile core
        $venvDir = Join-Path $env:TEMP "mts-pins-e2e-$(Get-Random)"
        try {
            $prov = Invoke-Provisioning -EnabledAnalyzers $sel.Enabled -VenvDir $venvDir -Mode online
            $prov.Tools['pip-audit'].Available | Should -BeTrue
            $prov.Tools['pip-audit'].Version   | Should -Be $pins['pip-audit']
            $prov.Tools['pefile'].Version      | Should -Be $pins['pefile']
        } finally {
            Remove-Item $venvDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
