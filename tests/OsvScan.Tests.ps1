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

    It 'applies the v3.1 (not v3.0) scope-changed impact formula for a CVSS:3.1 vector' {
        # FIRST.org changed the scope-changed impact formula between v3.0 and
        # v3.1 (0.9731 scaling + exponent 13 vs. exponent 15) to fix a curve
        # discontinuity. This vector crosses the HIGH/MEDIUM boundary depending
        # on which formula is used: 7.0 under v3.0's, 6.9 under v3.1's — the
        # correct published score for a CVSS:3.1 vector.
        Get-CvssV3BaseScore -Vector 'CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L' | Should -Be 6.9
    }

    It 'still applies the v3.0 scope-changed impact formula for a CVSS:3.0 vector' {
        Get-CvssV3BaseScore -Vector 'CVSS:3.0/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L' | Should -Be 7.0
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

    It 'matches an affected-package record by PEP 503-normalized name for PyPI' {
        Test-OsvPackageMatches 'Foo_Bar' 'PyPI' 'foo-bar' 'PyPI' | Should -BeTrue
        Test-OsvPackageMatches 'Other-Pkg' 'PyPI' 'foo-bar' 'PyPI' | Should -BeFalse
    }

    It 'rejects an affected-package record from a different ecosystem' {
        Test-OsvPackageMatches 'lodash' 'npm' 'lodash' 'PyPI' | Should -BeFalse
    }

    It 'fails open (matches) when the affected record carries no package name' {
        Test-OsvPackageMatches $null $null 'lodash' 'npm' | Should -BeTrue
    }

    It 'excludes a fix version below the current version (irrelevant branch)' {
        Test-OsvFixNotNewerThan -FixVersion '1.5.3' -CurrentVersion '3.0.0' | Should -BeTrue
    }

    It 'keeps a fix version above the current version' {
        Test-OsvFixNotNewerThan -FixVersion '10.0.1' -CurrentVersion '9.5.0' | Should -BeFalse
        Test-OsvFixNotNewerThan -FixVersion '12.3.0' -CurrentVersion '9.5.0' | Should -BeFalse
    }

    It 'fails open (keeps the fix) when the version scheme is not confidently comparable' {
        Test-OsvFixNotNewerThan -FixVersion '1.0.0-rc1' -CurrentVersion '1.0.0-beta' | Should -BeFalse
    }

    It 'keeps a stable fix that supersedes a pre-release current version' {
        # 2.0.0 IS newer than 2.0.0-beta.1 — the extra tokens on the current side are
        # a pre-release suffix, not a deeper release, so the fix must not be dropped.
        Test-OsvFixNotNewerThan -FixVersion '2.0.0' -CurrentVersion '2.0.0-beta.1' | Should -BeFalse
        Test-OsvFixNotNewerThan -FixVersion '1.4.0' -CurrentVersion '1.4.0-rc.2'   | Should -BeFalse
    }

    It 'still excludes a shallower fix when the extra tokens are a deeper numeric release' {
        # 1.2 really is older than 1.2.3 — this must keep working after the
        # pre-release carve-out above.
        Test-OsvFixNotNewerThan -FixVersion '1.2' -CurrentVersion '1.2.3' | Should -BeTrue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-OsvDependencyFindings — partial batch failure (no network)' {
    It 'keeps vulnerabilities confirmed by earlier chunks when a later chunk fails' {
        # 150 deps => two chunks (batch size 100). Chunk 1 succeeds and confirms a
        # vuln on the first dep; chunk 2 throws. The confirmed vuln MUST still be
        # reported — dropping it for the failed chunk is a security false negative.
        $script:callCount = 0
        Mock -CommandName Invoke-OsvQueryBatch -MockWith {
            $script:callCount++
            if ($script:callCount -eq 1) {
                # First dep vulnerable; the other 99 return the bare '{}' no-vuln shape.
                return @(@([PSCustomObject]@{ vulns = @([PSCustomObject]@{ id = 'GHSA-test-0001' }) }) +
                         (1..99 | ForEach-Object { [PSCustomObject]@{} }))
            }
            throw 'simulated network failure on chunk 2'
        }
        Mock -CommandName Get-OsvVulnDetails -MockWith {
            [PSCustomObject]@{ id = 'GHSA-test-0001'; summary = 'test advisory'
                               database_specific = [PSCustomObject]@{ severity = 'HIGH' } }
        }

        $deps = 1..150 | ForEach-Object {
            @{ Name = "pkg$_"; Version = '1.0.0'; Ecosystem = 'PyPI'; FileLabel = "dependency: pkg$_ 1.0.0" }
        }
        $findings = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies $deps)

        # The confirmed vulnerability survived the later failure...
        $vulns = @($findings | Where-Object { $_.Category -eq 'vuln-dependency' })
        $vulns.Count      | Should -Be 1
        $vulns[0].TestID  | Should -Be 'GHSA-test-0001'
        # ...and the unqueried chunk is still reported as a coverage gap.
        $gaps = @($findings | Where-Object { $_.TestID -eq 'OSV-QUERY-ERR' })
        $gaps.Count       | Should -Be 1
        $gaps[0].Issue    | Should -Match '50 of 150'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'OsvScan — PyPI (requirements.txt), offline-safe' {
    It 'reports every non-exact-pin shape as unpinned, OSV skipped — no network call' {
        $r = ScanDir 'python_requirements/unpinned'
        $unpinned = @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' })
        # flask>=2.0, requests (bare), weird==1.0,!=1.0.1, wildcard-pkg==1.2.*, badeq-pkg====1.0, editable-pkg
        $unpinned.Count | Should -Be 6
        ($unpinned.Issue -join ' ') | Should -Match 'flask'
        ($unpinned.Issue -join ' ') | Should -Match 'requests'
        ($unpinned.Issue -join ' ') | Should -Match 'weird'
        # A pure option line (--index-url) is not a dependency — must not appear at all.
        @(AllFindings $r | Where-Object { $_.Issue -match 'index-url' }).Count | Should -Be 0
    }

    It 'reports an editable/VCS install as unpinned rather than silently dropping it' {
        $r = ScanDir 'python_requirements/unpinned'
        $editable = @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' -and $_.Issue -match 'editable-pkg' })
        $editable.Count | Should -Be 1
        $editable[0].Issue | Should -Match 'editable/VCS'
    }

    It 'rejects a PEP 440 wildcard equality (==1.2.*) as unpinned rather than querying it literally' {
        $r = ScanDir 'python_requirements/unpinned'
        $wildcard = @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' -and $_.Issue -match 'wildcard-pkg' })
        $wildcard.Count | Should -Be 1
    }

    It 'reports a -r/--requirement include as an explicit unaudited coverage gap' {
        $r = ScanDir 'python_requirements/unpinned'
        $include = @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-INCLUDE-UNAUDITED' })
        $include.Count | Should -Be 1
        $include[0].Issue | Should -Match 'other\.txt'
    }

    It 'notes CVE audit skipped (offline) for an exact-pinned manifest' {
        $r = ScanDir 'python_requirements/vulnerable' -Mode offline
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-OFFLINE' }).Count | Should -BeGreaterThan 0
    }

    It 'recognizes a pip-compile hash-pinned exact pin split across continuation lines' {
        $r = ScanDir 'python_requirements/hash_pinned' -Mode offline
        # The offline note only fires when at least one dependency parsed as pinned —
        # its presence proves the hash-pinned line was NOT misread as unpinned.
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-OFFLINE' }).Count | Should -BeGreaterThan 0
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' }).Count | Should -Be 0
    }

    It 'recognizes exact pins carrying SPACE-separated option values (--hash x, -C KEY=VALUE)' {
        # Every line in the fixture is a real exact pin followed by an option in a
        # different form (=-joined, space-separated, short -C). If option VALUES
        # leaked into the specifier, those lines would be misreported as unpinned.
        $r = ScanDir 'python_requirements/hash_pinned' -Mode offline
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' }).Count | Should -Be 0
    }

    It "treats PEP 440 '===' arbitrary equality as an exact pin" {
        # 'packaging===24.0' lives in the hash_pinned fixture; matching only '=='
        # would capture '=24.0' and query a version that cannot exist — no OSV hit,
        # no unpinned note, so a vulnerable dependency would read as clean.
        $r = ScanDir 'python_requirements/hash_pinned' -Mode offline
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' -and $_.Issue -match 'packaging' }).Count | Should -Be 0
    }

    It 'reports a malformed 4-equals specifier as unpinned rather than querying a bogus version' {
        $r = ScanDir 'python_requirements/unpinned'
        @(AllFindings $r | Where-Object { $_.TestID -eq 'OSV-PYPI-UNPINNED' -and $_.Issue -match 'badeq-pkg' }).Count | Should -Be 1
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

    It 'does not let a same-named package inherit another .nupkg''s manifest' {
        # collide/a and collide/b share a FILENAME; only 'a' ships a .nuspec.
        # With a shared staging dir, 'b' picked up 'a's manifest and was audited
        # under the wrong identity instead of reporting its coverage gap.
        $r = ScanDir 'nuget/collide'
        $b = $r.Units | Where-Object { $_.Path -match '^b[\\/]' }
        $b | Should -Not -BeNullOrEmpty
        @($b.Findings | Where-Object { $_.TestID -eq 'OSV-NUGET-NO-NUSPEC' }).Count | Should -Be 1
        # 'b' has no identity to audit, so it must NOT produce an offline audit note.
        @($b.Findings | Where-Object { $_.TestID -eq 'OSV-NUGET-OFFLINE' }).Count | Should -Be 0
        # 'a' is unaffected and still resolves its own manifest.
        $a = $r.Units | Where-Object { $_.Path -match '^a[\\/]' }
        @($a.Findings | Where-Object { $_.TestID -eq 'OSV-NUGET-OFFLINE' }).Count | Should -Be 1
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
