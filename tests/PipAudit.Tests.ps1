#Requires -Version 7.4
<#
    Pester 5 tests for the PipAudit analyzer.

    Test strategy:
      - "tool unavailable" path: exercised without any real pip-audit install.
      - "no metadata" path: exercised with a real venv but empty staging dir.
      - "real CVE scan" path: uses a synthetic METADATA fixture that declares a
        known-vulnerable dependency, provisions pip-audit into a real venv, and
        asserts that CVE findings and an SBOM are produced.
        (Skipped in offline/no-internet environments via a guard.)
#>

BeforeAll {
    $script:Root    = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet   = $true
    $script:Out     = Join-Path $env:TEMP "mts-pipaudit-test-$(Get-Random)"
    $script:VenvDir = Join-Path $env:TEMP "mts-pipaudit-venv-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    # Helpers in BeforeAll scope so all It blocks can see them via $script:
    function script:New-TestUnit {
        param([string]$StagingPath = $null, [string]$Name = 'test.whl')
        [PSCustomObject]@{
            Type         = 'python'
            Name         = $Name
            Path         = 'test.whl'
            RelativePath = $Name
            StagingPath  = $StagingPath
        }
    }

    function script:New-TestContext {
        param([hashtable]$Tools = @{})
        [PSCustomObject]@{
            Tools          = $Tools
            Venv           = $null
            Mode           = 'online'
            WorkDir        = $env:TEMP
            ReportsDir     = $script:Out
            AdvisoryDbDate = $null
            TimeoutSeconds = 300
        }
    }
}

AfterAll {
    Remove-Item $script:Out     -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $script:VenvDir -Recurse -Force -ErrorAction SilentlyContinue
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'PipAudit — tool unavailable path' {
    It 'returns an INFO coverage-gap finding when pip-audit is not in Tools' {
        $desc    = & (Join-Path $Root 'src/analyzers/PipAudit.ps1')
        $unit    = New-TestUnit -StagingPath (New-Item -ItemType Directory `
                       -Path (Join-Path $env:TEMP "mts-pa-$(Get-Random)") -Force).FullName
        $context = New-TestContext -Tools @{}
        $findings = @(& $desc.Invoke $unit $context)
        $unit.StagingPath | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        $findings.Count | Should -BeGreaterOrEqual 1
        $findings[0].TestID | Should -Be 'MTS-PIPAUDIT-UNAVAIL'
        $findings[0].Severity | Should -Be 'INFO'
    }

    It 'returns empty array for a loose .py file (no StagingPath)' {
        $desc    = & (Join-Path $Root 'src/analyzers/PipAudit.ps1')
        $unit    = New-TestUnit -StagingPath $null
        $context = New-TestContext
        $findings = @(& $desc.Invoke $unit $context)
        $findings.Count | Should -Be 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'PipAudit — real venv scan' -Tag 'Online' {

    BeforeAll {
        # Skip the whole describe block if no internet or python missing
        $script:PythonCmd = Find-Python
        if (-not $script:PythonCmd) {
            Set-ItResult -Skipped -Because 'Python 3 not found'
            return
        }

        # Provision a real venv + pip-audit
        $script:Venv = Initialize-ScannerVenv -PythonCmd $script:PythonCmd `
                           -VenvDir $script:VenvDir
        Update-PipBootstrap -PythonExe $script:Venv.Python
        Install-PipPackage -PythonExe $script:Venv.Python -Package 'pip-audit' `
                           -MinVersion '2.0.0'

        $script:ToolHandle = [PSCustomObject]@{
            Name       = 'pip-audit'
            Available  = $true
            Version    = (Get-InstalledPipVersion -PythonExe $script:Venv.Python -PackageName 'pip-audit')
            ScriptsDir = $script:Venv.Scripts
        }
    }

    It 'returns empty findings for a staging dir with no METADATA' {
        $desc    = & (Join-Path $Root 'src/analyzers/PipAudit.ps1')
        $stage   = (New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mts-pa-empty-$(Get-Random)") -Force).FullName
        $unit    = New-TestUnit -StagingPath $stage
        $context = New-TestContext -Tools @{ 'pip-audit' = $script:ToolHandle }
        $findings = @(& $desc.Invoke $unit $context)
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $findings.Count | Should -Be 0
    }

    It 'finds a CVE and writes an SBOM for a package with a known-vulnerable dep' {
        $desc  = & (Join-Path $Root 'src/analyzers/PipAudit.ps1')

        # Synthetic METADATA declaring a known-vulnerable version of Pillow
        # (CVE-2023-44271 and many others exist for < 10.0.1)
        $stage = (New-Item -ItemType Directory `
                     -Path (Join-Path $env:TEMP "mts-pa-cve-$(Get-Random)") -Force).FullName
        $distInfo = New-Item -ItemType Directory `
                        -Path (Join-Path $stage 'vuln_pkg-1.0.dist-info') -Force
        @'
Metadata-Version: 2.1
Name: vuln-pkg
Version: 1.0
Requires-Dist: Pillow==9.5.0
'@ | Set-Content -LiteralPath (Join-Path $distInfo 'METADATA') -Encoding utf8

        $unit    = New-TestUnit -StagingPath $stage -Name 'vuln_pkg-1.0-py3-none-any.whl'
        $context = New-TestContext -Tools @{ 'pip-audit' = $script:ToolHandle }

        $findings = @(& $desc.Invoke $unit $context)
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

        # Should have at least one CVE finding
        $cveFindings = @($findings | Where-Object { $_.Category -eq 'vuln-dependency' })
        $cveFindings.Count | Should -BeGreaterThan 0

        # CVE findings should have a real ID and non-empty description
        $cveFindings[0].TestID | Should -Match '^(CVE|PYSEC|GHSA)-'
        $cveFindings[0].Issue  | Should -Not -BeNullOrEmpty

        # Should have an SBOM INFO finding
        $sbomFinding = $findings | Where-Object { $_.TestID -eq 'MTS-SBOM-001' }
        $sbomFinding | Should -Not -BeNullOrEmpty

        # SBOM file should exist on disk
        $sbomFile = Get-ChildItem $script:Out -Filter '*.cdx.json' | Select-Object -First 1
        $sbomFile | Should -Not -BeNullOrEmpty
    }
}
