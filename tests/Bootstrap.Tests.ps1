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

    It 'launch args point at a vendored venv but do NOT force offline mode' {
        $venv = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mts-bsvenv-$(Get-Random)") -Force
        $args = Get-EngineLaunchArgs -Engine 'C:\eng.ps1' -BundledVenv $venv.FullName -ForwardArgs @('-Path','X')
        Remove-Item $venv -Recurse -Force -ErrorAction SilentlyContinue
        $args | Should -Contain '-VenvDir'
        # online coverage on a connected host: mode is left to the engine default
        ($args -join ' ') | Should -Not -Match '-Mode\s+offline'
        $args | Should -Contain '-Path'
    }
    It 'forwards an explicit -Mode offline through to the engine' {
        $args = Get-EngineLaunchArgs -Engine 'C:\eng.ps1' -BundledVenv '' -ForwardArgs @('-Path','X','-Mode','offline')
        ($args -join ' ') | Should -Match '-Mode offline'
    }

    It 'Get-PwshVersion reports a version >= 7.4 for the real runtime' {
        $v = Get-PwshVersion -Exe $script:RealPwsh
        $v | Should -Not -BeNullOrEmpty
        $v -ge [version]'7.4' | Should -BeTrue
    }
}

Describe 'Bootstrap — bundle integrity (F1 / issue #8)' {
    BeforeAll {
        # Build a tiny fake "bundle": a couple of sealed files + a manifest whose
        # fileHashes are their real SHA-256. No build-bundle.ps1 needed.
        function script:New-FakeBundle {
            $b = Join-Path $env:TEMP "mts-intg-$(Get-Random)"
            New-Item -ItemType Directory -Path (Join-Path $b 'src/lib') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $b 'src/lib/Engine.ps1') -Value 'Write-Output 1' -Encoding utf8
            Set-Content -LiteralPath (Join-Path $b 'Scan.cmd')           -Value '@echo off'      -Encoding ascii
            $hashes = [ordered]@{}
            foreach ($rel in 'src/lib/Engine.ps1', 'Scan.cmd') {
                $hashes[$rel] = (Get-FileHash -LiteralPath (Join-Path $b ($rel -replace '/','\')) -Algorithm SHA256).Hash
            }
            @{ bundleVersion = 't'; hashAlgorithm = 'SHA256'; fileHashes = $hashes } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $b 'manifest.json') -Encoding utf8
            return $b
        }
    }

    It 'passes for an intact sealed bundle' {
        $b = New-FakeBundle
        Test-BundleIntegrity -Root $b | Should -BeTrue
        Remove-Item $b -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'FAILS when a sealed file is modified' {
        $b = New-FakeBundle
        Add-Content -LiteralPath (Join-Path $b 'src/lib/Engine.ps1') -Value 'malicious'
        Test-BundleIntegrity -Root $b | Should -BeFalse
        Remove-Item $b -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'FAILS when a sealed file is missing' {
        $b = New-FakeBundle
        Remove-Item (Join-Path $b 'Scan.cmd') -Force
        Test-BundleIntegrity -Root $b | Should -BeFalse
        Remove-Item $b -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'proceeds (true) for an unsealed dev checkout with no manifest' {
        $b = Join-Path $env:TEMP "mts-nomani-$(Get-Random)"
        New-Item -ItemType Directory -Path $b -Force | Out-Null
        Test-BundleIntegrity -Root $b | Should -BeTrue
        Remove-Item $b -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'proceeds (true) when manifest has no fileHashes (older bundle)' {
        $b = Join-Path $env:TEMP "mts-nohash-$(Get-Random)"
        New-Item -ItemType Directory -Path $b -Force | Out-Null
        @{ bundleVersion = 't' } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $b 'manifest.json') -Encoding utf8
        Test-BundleIntegrity -Root $b | Should -BeTrue
        Remove-Item $b -Recurse -Force -ErrorAction SilentlyContinue
    }
    It 'a bundle built with a RELATIVE -OutputDir passes its own integrity check' {
        # Regression: relative -OutputDir left fileHashes keys absolute-vs-relative
        # mismatched, so the bundle failed its own bootstrap integrity check.
        $tmp = Join-Path $env:TEMP "mts-relbuild-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        Push-Location $tmp
        try {
            & (Join-Path $Root 'bundle/build-bundle.ps1') -OutputDir 'rel' -Version 'reltest' -SkipPwsh -SkipVenv *> $null
            $bundle = Join-Path $tmp 'rel/media-transfer-scan-tool-reltest'
            Test-BundleIntegrity -Root $bundle | Should -BeTrue
            $man = Get-Content (Join-Path $bundle 'manifest.json') -Raw | ConvertFrom-Json
            # keys must be clean POSIX-relative paths under src/, not drive-letter tails
            @($man.fileHashes.PSObject.Properties.Name | Where-Object { $_ -like 'src/*' }).Count | Should -BeGreaterThan 0
            @($man.fileHashes.PSObject.Properties.Name | Where-Object { $_ -match '^[A-Za-z]:' }).Count | Should -Be 0
        } finally {
            Pop-Location
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
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
