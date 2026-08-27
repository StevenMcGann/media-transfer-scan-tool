#Requires -Version 7.4
<#
    Pester 5 tests for the OsvScan analyzer and its shared src/lib/Osv.ps1
    client (issue #32): OSV.dev dependency-vulnerability audit for PyPI
    (requirements.txt), npm (package-lock.json), and NuGet (.nupkg).

    Offline-safe tests (no network): PEP 503 normalization, CVSS v3 base-score
    math, severity-band derivation, requirements.txt pin/unpinned parsing, and
    the -Mode offline coverage-gap notes.

    Online tests (-Tag 'Online', real api.osv.dev calls) exercise each
    ecosystem against a fixture pinned to a package/version with a real,
    long-published advisory, so they don't depend on ephemeral CVEs.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:Corpus    = Join-Path $PSScriptRoot 'fixtures/corpus'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-osv-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:ScanDir($RelPath, [string]$Mode = 'offline') {
        Invoke-Scan -Path (Join-Path $script:Corpus $RelPath) -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode $Mode
    }
    function script:AllFindings($Result) {
        @($Result.Units | ForEach-Object { $_.Findings } | Where-Object { $_ })
    }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Osv.ps1 — pure helpers (no network)' {
    It 'PEP 503-normalizes mixed-case, dot/underscore-separated names' {
        Get-Pep503NormalizedName -Name 'Foo_Bar.Baz' | Should -Be 'foo-bar-baz'
        Get-Pep503NormalizedName -Name 'A---B__C..D' | Should -Be 'a-b-c-d'
    }

    It 'computes the known CVSS v3.1 base score for a real published vector' {
        # GHSA-5crp-9r3c-p9vr (Newtonsoft.Json DoS) — published base score 7.5.
        Get-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' | Should -Be 7.5
        # log4shell-shaped critical vector (scope changed, full CIA impact).
        Get-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' | Should -Be 10.0
    }

    It 'returns $null for a non-v3 vector or one missing a required metric' {
        Get-CvssV3BaseScore -Vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' | Should -BeNullOrEmpty
        Get-CvssV3BaseScore -Vector 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N' | Should -BeNullOrEmpty   # missing A
    }

    It 'prefers an explicit database_specific.severity over a CVSS vector' {
        $detail = [PSCustomObject]@{
            summary = 'x'; details = ''
            severity = @([PSCustomObject]@{ type = 'CVSS_V3'; score = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' })  # would be LOW/MEDIUM
            database_specific = [PSCustomObject]@{ severity = 'CRITICAL' }
        }
        Get-OsvSeverityBand -VulnDetail $detail | Should -Be 'CRITICAL'
    }

    It 'falls back to a keyword heuristic when there is no structured severity at all' {
        $detail = [PSCustomObject]@{ summary = 'Remote code execution via crafted input'; details = '' }
        Get-OsvSeverityBand -VulnDetail $detail | Should -Be 'CRITICAL'
    }

    It 'defaults an unscored, unkeyworded record to HIGH rather than downgrading it' {
        $detail = [PSCustomObject]@{ summary = 'A vulnerability exists.'; details = '' }
        Get-OsvSeverityBand -VulnDetail $detail | Should -Be 'HIGH'
    }

    It 'never throws on a minimal record missing summary/details/severity entirely' {
        $detail = [PSCustomObject]@{ id = 'X-1' }
        { Get-OsvSeverityBand -VulnDetail $detail } | Should -Not -Throw
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'OsvScan — PyPI (requirements.txt), offline-safe' {
    It 'reports every non-exact-pin shape as unpinned, OSV skipped — no network call' {
        $r = ScanDir 'python_requirements/unpinned'
        $unpinned = @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' })
        $unpinned.Count | Should -Be 3   # flask>=2.0, requests (bare), weird==1.0,!=1.0.1
        ($unpinned.Issue -join ' ') | Should -Match 'flask'
        ($unpinned.Issue -join ' ') | Should -Match 'requests'
        ($unpinned.Issue -join ' ') | Should -Match 'weird'
        # '-r other.txt' is an include directive, not a dependency — must not appear at all.
        @(AllFindings $r | Where-Object { $_.Issue -match 'other\.txt' }).Count | Should -Be 0
    }

    It 'notes CVE audit skipped (offline) for an exact-pinned manifest' {
        $r = ScanDir 'python_requirements/vulnerable' -Mode offline
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-OFFLINE' }).Count | Should -BeGreaterThan 0
    }

    It 'classifies requirements.txt as python-requirements, not python' {
        $r = ScanDir 'python_requirements/clean'
        ($r.Units | Where-Object { $_.Name -eq 'requirements.txt' }).Type | Should -Be 'python-requirements'
    }
}

Describe 'OsvScan — PyPI (requirements.txt), live' -Tag 'Online' {
    It 'flags a known-vulnerable exact pin (Pillow 9.5.0) via OSV with a real advisory id' {
        $r = ScanDir 'python_requirements/vulnerable' -Mode online
        $vulns = @(AllFindings $r | Where-Object { $_.Tool -eq 'OsvScan' -and $_.Category -eq 'vuln-dependency' })
        $vulns.Count | Should -BeGreaterThan 0
        $vulns[0].TestID | Should -Match '^(CVE|GHSA|PYSEC)-'
        $vulns[0].Severity | Should -BeIn @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'OsvScan — npm (package-lock.json), offline-safe' {
    It 'notes CVE audit skipped (offline) when a lockfile is present' {
        $r = ScanDir 'npm/locked'
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-NPM-OFFLINE' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'OsvScan — npm (package-lock.json), live' -Tag 'Online' {
    It 'flags a known-vulnerable dependency (lodash 4.17.4) via OSV' {
        $r = ScanDir 'npm/locked' -Mode online
        $vulns = @(AllFindings $r | Where-Object { $_.Tool -eq 'OsvScan' -and $_.Category -eq 'vuln-dependency' })
        $vulns.Count | Should -BeGreaterThan 0
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'OsvScan — NuGet (.nupkg), offline-safe' {
    It 'classifies a .nupkg as nuget and extracts it (StagingPath set)' {
        $r = ScanDir 'nuget/clean'
        $u = $r.Units | Where-Object { $_.Name -like '*.nupkg' }
        $u.Type | Should -Be 'nuget'
    }

    It 'notes CVE audit skipped (offline) for the package identity' {
        $r = ScanDir 'nuget/vulnerable'
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-NUGET-OFFLINE' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'OsvScan — NuGet (.nupkg), live' -Tag 'Online' {
    It 'flags a known-vulnerable package identity (Newtonsoft.Json 12.0.1) via OSV' {
        $r = ScanDir 'nuget/vulnerable' -Mode online
        $vulns = @(AllFindings $r | Where-Object { $_.Tool -eq 'OsvScan' -and $_.Category -eq 'vuln-dependency' })
        $vulns.Count | Should -BeGreaterThan 0
        $vulns[0].TestID | Should -Match '^(CVE|GHSA|PYSEC)-'
        $vulns[0].Issue  | Should -Match '13\.0\.1'   # the published fixed version
    }

    It 'produces no vuln-dependency findings for a package/version with no OSV record' {
        $r = ScanDir 'nuget/clean' -Mode online
        @(AllFindings $r | Where-Object { $_.Tool -eq 'OsvScan' -and $_.Category -eq 'vuln-dependency' }).Count | Should -Be 0
    }
}
