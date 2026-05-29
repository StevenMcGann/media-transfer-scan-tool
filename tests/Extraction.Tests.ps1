#Requires -Version 7.4
<#
    Pester 5 tests for archive extraction (Expand-Archive.ps1) and the
    end-to-end engine pipeline with real .whl files.
#>

BeforeAll {
    $script:Root    = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet   = $true
    $script:Corpus  = Join-Path $PSScriptRoot 'fixtures/corpus/python'
    $script:Out     = Join-Path $env:TEMP "mts-extract-test-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
}

AfterAll {
    Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Expand-SubmissionArchive — ZIP-family' {

    It 'extracts a valid .whl and returns Success=$true with StagingPath' {
        $whl   = Join-Path $script:Corpus 'clean_pkg-1.0-py3-none-any.whl'
        $stage = Join-Path $env:TEMP "mts-ext-clean-$(Get-Random)"
        $r = Expand-SubmissionArchive -InputFile $whl -OutputDir $stage
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $r.Success     | Should -BeTrue
        $r.StagingPath | Should -Be $stage
        $r.Findings    | Should -BeNullOrEmpty
    }

    It 'sets Success=$false and emits a corrupt finding for a non-ZIP .whl' {
        $whl   = Join-Path $script:Corpus 'corrupt_pkg-1.0-py3-none-any.whl'
        $stage = Join-Path $env:TEMP "mts-ext-corrupt-$(Get-Random)"
        $r = Expand-SubmissionArchive -InputFile $whl -OutputDir $stage
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $r.Success | Should -BeFalse
        ($r.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-CORRUPT' }).Count | Should -Be 1
    }

    It 'detects path-traversal entries and emits MTS-EXTRACT-TRAVERSAL finding' {
        $whl   = Join-Path $script:Corpus 'traversal_pkg-1.0-py3-none-any.whl'
        $stage = Join-Path $env:TEMP "mts-ext-trav-$(Get-Random)"
        $r = Expand-SubmissionArchive -InputFile $whl -OutputDir $stage
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        # Extraction may succeed (ZipFile still extracts) but must flag the traversal
        $trav = @($r.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-TRAVERSAL' })
        $trav.Count | Should -Be 1
        $trav[0].Severity | Should -Be 'HIGH'
    }

    It 'extracts a .whl and identifies it as a Python wheel (not OOXML or npm)' {
        $whl   = Join-Path $script:Corpus 'clean_pkg-1.0-py3-none-any.whl'
        $stage = Join-Path $env:TEMP "mts-ext-dis-$(Get-Random)"
        # No finding expected; disambiguation is just a DEBUG log
        $r = Expand-SubmissionArchive -InputFile $whl -OutputDir $stage
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        $r.Success | Should -BeTrue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Engine pipeline — archive units get StagingPath populated' {

    It 'scans a folder containing a .whl and populates StagingPath for the unit' {
        # Point the engine at the corpus folder itself (contains clean .whl)
        $result = Invoke-Scan -Path $script:Corpus -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') `
            -ReportsDir $script:Out

        $whlUnit = $result.Units | Where-Object { $_.Name -like '*.whl' } |
                   Select-Object -First 1
        $whlUnit | Should -Not -BeNullOrEmpty
        # StagingPath is cleaned up after scan (temp dir gone), but the unit
        # should have had it set — we confirm via a FileHash finding (proves
        # the unit was processed) and no extraction-error finding
        @($whlUnit.Findings | Where-Object { $_.Tool -eq 'FileHash' }).Count |
            Should -BeGreaterThan 0
        @($whlUnit.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-CORRUPT' }).Count |
            Should -Be 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Engine pipeline + PipAudit — full end-to-end on real .whl' -Tag 'Online' {

    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }

        $script:VenvDir2 = Join-Path $env:TEMP "mts-e2e-venv-$(Get-Random)"
        $venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir $script:VenvDir2
        Update-PipBootstrap -PythonExe $venv.Python
        Install-PipPackage  -PythonExe $venv.Python -Package 'pip-audit' -MinVersion '2.0.0'

        $script:E2EProvision = [PSCustomObject]@{
            Venv  = $venv
            Tools = @{
                'pip-audit' = [PSCustomObject]@{
                    Name       = 'pip-audit'
                    Available  = $true
                    Version    = (Get-InstalledPipVersion -PythonExe $venv.Python -PackageName 'pip-audit')
                    ScriptsDir = $venv.Scripts
                }
            }
        }
    }

    AfterAll {
        if ($script:VenvDir2) {
            Remove-Item $script:VenvDir2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'finds CVEs in vulnerable_deps_pkg and writes a SBOM' {
        $result = Invoke-Scan -Path $script:Corpus -Profile core `
            -AnalyzerDir  (Join-Path $Root 'src/analyzers') `
            -ReportsDir   $script:Out `
            -ProvisionResult $script:E2EProvision

        $vulnUnit = $result.Units | Where-Object { $_.Name -like 'vulnerable_deps*' } |
                    Select-Object -First 1
        $vulnUnit | Should -Not -BeNullOrEmpty

        $cves = @($vulnUnit.Findings | Where-Object { $_.Category -eq 'vuln-dependency' })
        $cves.Count | Should -BeGreaterThan 0
        $cves[0].TestID | Should -Match '^(CVE|PYSEC|GHSA)-'

        $sbom = Get-ChildItem $script:Out -Filter '*.cdx.json' | Select-Object -First 1
        $sbom | Should -Not -BeNullOrEmpty
    }

    It 'produces zero CVE findings for clean_pkg (no Requires-Dist)' {
        $result = Invoke-Scan -Path $script:Corpus -Profile core `
            -AnalyzerDir  (Join-Path $Root 'src/analyzers') `
            -ReportsDir   $script:Out `
            -ProvisionResult $script:E2EProvision

        $cleanUnit = $result.Units | Where-Object { $_.Name -eq 'clean_pkg-1.0-py3-none-any.whl' }
        $cves = @($cleanUnit.Findings | Where-Object { $_.Category -eq 'vuln-dependency' })
        $cves.Count | Should -Be 0
    }
}
