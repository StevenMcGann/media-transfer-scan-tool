#Requires -Version 7.4
<#
    Pester 5 tests for Provisioning.ps1. Validates Python discovery, venv
    creation/reuse, version comparison (PEP 440), and the Resolve-Tool contract.
    No network calls — tests use the real Python on the dev host but only
    create a venv in TEMP; no packages are downloaded.
#>

BeforeAll {
    $script:Root  = Split-Path $PSScriptRoot -Parent
    $script:Entry = Join-Path $Root 'src/Invoke-MediaTransferScan.ps1'
    . $script:Entry          # dot-source loads all libs including Provisioning
    $script:Quiet    = $true
    $script:TestVenv = Join-Path $env:TEMP "mts-test-venv-$(Get-Random)"
}

AfterAll {
    if ($script:TestVenv -and (Test-Path $script:TestVenv)) {
        Remove-Item $script:TestVenv -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Find-Python' {
    It 'finds a Python 3 executable on the dev host' {
        $cmd = Find-Python
        $cmd | Should -Not -BeNullOrEmpty
    }
}

Describe 'Initialize-ScannerVenv' {
    It 'creates a functional venv with python.exe inside it' {
        $py = Find-Python
        $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:TestVenv
        Test-Path $venv.Python | Should -BeTrue
        Test-Path $venv.Pip    | Should -BeTrue
    }

    It 'reuses an existing venv without error' {
        $py = Find-Python
        # Second call — venv already exists.
        { Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:TestVenv } | Should -Not -Throw
    }
}

Describe 'Bundled Python runtime resolution' {
    It 'prefers the relocatable sibling runtime over the build-time venv launcher' {
        $root = Join-Path $env:TEMP "mts-bundled-python-$(Get-Random)"
        $venvDir = Join-Path $root 'venv'
        $pythonDir = Join-Path $root 'python'
        New-Item -ItemType Directory -Path (Join-Path $venvDir 'Scripts'),$pythonDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $venvDir 'Scripts/python.exe') -Value 'venv launcher' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $pythonDir 'python.exe') -Value 'portable runtime' -Encoding ascii
        try {
            $paths = Get-VenvPaths -VenvDir $venvDir
            $paths.Python | Should -Be (Join-Path $pythonDir 'python.exe')
            $paths.Scripts | Should -Be (Join-Path $venvDir 'Scripts')
        } finally {
            Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not require PATH Python when a bundled interpreter is present' {
        $python = (Get-VenvPaths -VenvDir $script:TestVenv).Python
        $analyzer = [PSCustomObject]@{
            RequiredTools = @([PSCustomObject]@{ Kind='pip'; Id='test-package'; MinVersion='1.0'; BundlePath=$null })
        }
        Mock Find-Python { throw 'PATH discovery must not run' }
        Mock Get-VenvPaths { param($VenvDir) [PSCustomObject]@{ Root=$VenvDir; Python=$python; Pip=''; Scripts=(Split-Path $python) } }
        Mock Resolve-PipTool { [PSCustomObject]@{ Name='test-package'; Available=$true; Version='1.0'; ScriptsDir='' } }
        $result = Invoke-Provisioning -EnabledAnalyzers @($analyzer) -VenvDir 'X:\bundled\venv' -Mode offline
        $result.Venv.Python | Should -Be $python
        Should -Invoke Find-Python -Times 0 -Exactly
    }
}

Describe 'Compare-PipVersions (PEP 440)' {
    BeforeAll {
        $py = Find-Python
        $script:VenvPy = (Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:TestVenv).Python
    }

    It 'returns $true when installed >= minimum (simple semver)' {
        Compare-PipVersions -PythonExe $script:VenvPy -Installed '2.0.0' -Minimum '1.7.0' | Should -BeTrue
    }

    It 'returns $false when installed < minimum' {
        Compare-PipVersions -PythonExe $script:VenvPy -Installed '1.4.0' -Minimum '1.7.0' | Should -BeFalse
    }

    It 'returns $true when no minimum is specified' {
        Compare-PipVersions -PythonExe $script:VenvPy -Installed '1.0.0' -Minimum '' | Should -BeTrue
    }

    It 'handles pre-release versions correctly (PEP 440 ordering)' {
        # 1.7.0rc1 < 1.7.0  per PEP 440 — [System.Version] would get this wrong
        Compare-PipVersions -PythonExe $script:VenvPy -Installed '1.7.0rc1' -Minimum '1.7.0' | Should -BeFalse
    }

    It 'fails closed on an unparseable version string' {
        Compare-PipVersions -PythonExe $script:VenvPy -Installed 'not-a-version' -Minimum '1.0.0' | Should -BeFalse
    }
}

Describe 'Get-InstalledPipVersion' {
    It 'returns a version string for pip itself (always present in a fresh venv)' {
        $py = (Initialize-ScannerVenv -PythonCmd (Find-Python) -VenvDir $script:TestVenv).Python
        $ver = Get-InstalledPipVersion -PythonExe $py -PackageName 'pip'
        $ver | Should -Not -BeNullOrEmpty
        $ver | Should -Match '^\d+\.\d+'
    }

    It 'returns $null for a package that is not installed' {
        $py = (Initialize-ScannerVenv -PythonCmd (Find-Python) -VenvDir $script:TestVenv).Python
        Get-InstalledPipVersion -PythonExe $py -PackageName 'this-package-does-not-exist-mts' | Should -BeNullOrEmpty
    }
}
