#Requires -Version 7.4
<#
    Pester 5 tests for src/lib/Kev.ps1 — the CISA KEV catalog client (issue #41)
    and its enrichment of OSV dependency findings.

    Offline-safe by construction: every catalog here is a fixture string parsed
    with ConvertFrom-Json, and each test that touches the network mocks
    Invoke-WebRequest. One -Tag 'Online' test checks the live feed still has the
    shape we depend on, so an upstream schema change is caught deliberately
    rather than by a silent loss of coverage.
#>

BeforeAll {
    $script:Root  = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet = $true

    function script:KevJson {
        param(
            [string]$Cve = 'CVE-2021-44228',
            [string]$Released = '',
            [string]$Ransomware = 'Unknown',
            [string]$Version = '2026.09.11'
        )
        if (-not $Released) { $Released = (Get-Date).ToUniversalTime().ToString('o') }
        @"
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "$Version",
  "dateReleased": "$Released",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "$Cve",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 contains a vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "$Ransomware",
      "notes": "",
      "cwes": ["CWE-502"]
    }
  ]
}
"@
    }
    function script:KevCatalogFixture {
        param([string]$Cve = 'CVE-2021-44228', [string]$Released = '', [string]$Ransomware = 'Unknown')
        ConvertTo-KevCatalog -Parsed ((KevJson -Cve $Cve -Released $Released -Ransomware $Ransomware) | ConvertFrom-Json) `
            -Source 'fixture' -Sha256 'FIXTUREHASH'
    }
    function script:Deps {
        param([int]$Count = 1, [string]$Manifest = 'requirements.txt')
        1..$Count | ForEach-Object {
            @{ Name = "pkg$_"; Version = '1.0.0'; Ecosystem = 'PyPI'; ManifestFile = $Manifest; DepLabel = "pkg$_ 1.0.0" }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-KevCatalog — validation' {
    It 'indexes a well-formed catalog by CVE' {
        $cat = KevCatalogFixture
        $cat.Count      | Should -Be 1
        $cat.Version    | Should -Be '2026.09.11'
        $cat.ByCve.ContainsKey('CVE-2021-44228') | Should -BeTrue
    }

    It 'rejects a proxy/HTML body instead of treating it as an empty catalog' {
        { ConvertTo-KevCatalog -Parsed '<html>sign in</html>' -Source 'proxy' } |
            Should -Throw -ExceptionType ([System.IO.InvalidDataException])
    }

    It 'rejects an object with no vulnerabilities property' {
        { ConvertTo-KevCatalog -Parsed ('{"error":"forbidden"}' | ConvertFrom-Json) -Source 'x' } |
            Should -Throw -ExceptionType ([System.IO.InvalidDataException])
    }

    It 'rejects a vulnerabilities value that is an object rather than an array' {
        # Same @()-coercion trap fixed for OSV querybatch in #43.
        { ConvertTo-KevCatalog -Parsed ('{"vulnerabilities":{}}' | ConvertFrom-Json) -Source 'x' } |
            Should -Throw -ExceptionType ([System.IO.InvalidDataException])
    }

    It 'rejects an empty catalog and one whose entries carry no cveID' {
        { ConvertTo-KevCatalog -Parsed ('{"vulnerabilities":[]}' | ConvertFrom-Json) -Source 'x' } |
            Should -Throw -ExceptionType ([System.IO.InvalidDataException])
        { ConvertTo-KevCatalog -Parsed ('{"vulnerabilities":[{"product":"x"}]}' | ConvertFrom-Json) -Source 'x' } |
            Should -Throw -ExceptionType ([System.IO.InvalidDataException])
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-KevAnnotation / Get-KevCatalogAgeDays' {
    It 'matches a CVE that appears only in the advisory aliases' {
        $ann = Get-KevAnnotation -Catalog (KevCatalogFixture) -Ids @('GHSA-jfh8-c2jp-5v3q', 'CVE-2021-44228')
        $ann.Cve        | Should -Be 'CVE-2021-44228'
        $ann.DateAdded  | Should -Be '2021-12-10'
        $ann.DueDate    | Should -Be '2021-12-24'
    }

    It 'returns $null for a non-KEV advisory and ignores non-CVE identifiers' {
        Get-KevAnnotation -Catalog (KevCatalogFixture) -Ids @('GHSA-xxxx-yyyy-zzzz', 'PYSEC-2021-1') | Should -BeNullOrEmpty
        Get-KevAnnotation -Catalog (KevCatalogFixture) -Ids @('CVE-2000-0001') | Should -BeNullOrEmpty
    }

    It 'returns $null when no catalog is loaded (never a silent "not exploited")' {
        Get-KevAnnotation -Catalog $null -Ids @('CVE-2021-44228') | Should -BeNullOrEmpty
    }

    It 'reports catalog age from dateReleased' {
        $old = KevCatalogFixture -Released ((Get-Date).ToUniversalTime().AddDays(-60).ToString('o'))
        (Get-KevCatalogAgeDays -Catalog $old) | Should -BeGreaterOrEqual 59
        (Get-KevCatalogAgeDays -Catalog (KevCatalogFixture)) | Should -BeLessThan 2
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-KevCatalog — source resolution' {
    BeforeEach {
        $script:KevTmp = Join-Path $env:TEMP "mts-kev-$(Get-Random)"
        New-Item -ItemType Directory -Path $script:KevTmp -Force | Out-Null
        $script:KevFile = Join-Path $script:KevTmp 'kev.json'
        KevJson | Set-Content -LiteralPath $script:KevFile -Encoding utf8
    }
    AfterEach { Remove-Item $script:KevTmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'prefers an operator-supplied catalog and makes no request' {
        Mock -CommandName Invoke-WebRequest -MockWith { throw 'network must not be used' }
        $cat = Get-KevCatalog -Mode online -CatalogPath $script:KevFile
        $cat.Count | Should -Be 1
        Should -Invoke -CommandName Invoke-WebRequest -Times 0 -Exactly
    }

    It 'never makes a request in offline mode, falling back to the vendored copy' {
        Mock -CommandName Invoke-WebRequest -MockWith { throw 'network must not be used' }
        $cat = Get-KevCatalog -Mode offline -VendoredPath $script:KevFile
        $cat.Source | Should -Be 'vendored bundle copy'
        Should -Invoke -CommandName Invoke-WebRequest -Times 0 -Exactly
    }

    It 'falls through to the GitHub mirror when cisa.gov returns an unusable body' {
        Mock -CommandName Invoke-WebRequest -ParameterFilter { $Uri -like '*cisa.gov*' } -MockWith {
            '<html>proxy login</html>' | Set-Content -LiteralPath $OutFile -Encoding utf8
        }
        Mock -CommandName Invoke-WebRequest -ParameterFilter { $Uri -like '*githubusercontent*' } -MockWith {
            KevJson | Set-Content -LiteralPath $OutFile -Encoding utf8
        }
        $cat = Get-KevCatalog -Mode online
        $cat.Count  | Should -Be 1
        $cat.Source | Should -Match 'githubusercontent'
    }

    It 'returns $null with a reportable reason when every source fails' {
        Mock -CommandName Invoke-WebRequest -MockWith { throw 'No such host is known.' }
        $cat = Get-KevCatalog -Mode online
        $cat | Should -BeNullOrEmpty
        $script:KevUnavailableReason | Should -Match 'No usable KEV catalog'
    }

    It 'honours -KevCatalogUrl instead of the default source order' {
        Mock -CommandName Invoke-WebRequest -MockWith { KevJson | Set-Content -LiteralPath $OutFile -Encoding utf8 }
        [void](Get-KevCatalog -Mode online -CatalogUrl 'https://mirror.internal/kev.json')
        Should -Invoke -CommandName Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://mirror.internal/kev.json' }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'OSV findings — KEV enrichment (no network)' {
    BeforeEach {
        Mock -CommandName Invoke-OsvQueryBatch -MockWith {
            param($Queries, $TimeoutSec)
            @($Queries | ForEach-Object { [PSCustomObject]@{ vulns = @([PSCustomObject]@{ id = 'GHSA-jfh8-c2jp-5v3q' }) } })
        }
        Mock -CommandName Get-OsvVulnDetails -MockWith {
            param($Id, $TimeoutSec)
            [PSCustomObject]@{
                id = $Id; summary = 'test advisory'
                aliases = @('CVE-2021-44228')
                database_specific = [PSCustomObject]@{ severity = 'LOW' }
            }
        }
    }

    It 'enriches a GHSA-primary finding whose alias is in KEV, and floors severity at HIGH' {
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) `
                -KevCatalog (KevCatalogFixture))
        $vulns = @($f | Where-Object { $_.Category -eq 'vuln-dependency' })
        $vulns.Count      | Should -Be 1
        $vulns[0].TestID  | Should -Be 'GHSA-jfh8-c2jp-5v3q'   # OSV id stays the TestID
        $vulns[0].Severity| Should -Be 'HIGH'                   # floored up from LOW
        $vulns[0].Issue   | Should -Match 'CISA KEV: CVE-2021-44228 is KNOWN EXPLOITED'
        $vulns[0].Recommendation | Should -Match 'BOD 22-01 due date for US federal agencies'
        # No duplicate/parallel KEV finding.
        @($f | Where-Object { $_.Issue -match 'KNOWN EXPLOITED' }).Count | Should -Be 1
    }

    It 'notes ransomware use without escalating past HIGH (maintainer decision)' {
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) `
                -KevCatalog (KevCatalogFixture -Ransomware 'Known'))
        $v = @($f | Where-Object { $_.Category -eq 'vuln-dependency' })[0]
        $v.Severity | Should -Be 'HIGH'
        $v.Issue    | Should -Match 'Known ransomware campaign use'
    }

    It 'leaves a non-KEV vulnerability untouched' {
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) `
                -KevCatalog (KevCatalogFixture -Cve 'CVE-1999-0001'))
        $v = @($f | Where-Object { $_.Category -eq 'vuln-dependency' })[0]
        $v.Issue    | Should -Not -Match 'CISA KEV'
        $v.Severity | Should -Be 'LOW'
        @($f | Where-Object { $_.TestID -like 'KEV-*' }).Count | Should -Be 0
    }

    It 'reports KEV-CATALOG-UNAVAILABLE per manifest when no catalog was loaded' {
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 2) -KevCatalog $null)
        $gap = @($f | Where-Object { $_.TestID -eq 'KEV-CATALOG-UNAVAILABLE' })
        $gap.Count    | Should -Be 1
        $gap[0].Issue | Should -Match 'not evidence that a CVE is not actively exploited'
        # OSV findings are still reported.
        @($f | Where-Object { $_.Category -eq 'vuln-dependency' }).Count | Should -Be 2
    }

    It 'reports KEV-CATALOG-STALE for a catalog older than 30 days, and still enriches' {
        $old = KevCatalogFixture -Released ((Get-Date).ToUniversalTime().AddDays(-45).ToString('o'))
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) -KevCatalog $old)
        $stale = @($f | Where-Object { $_.TestID -eq 'KEV-CATALOG-STALE' })
        $stale.Count    | Should -Be 1
        $stale[0].Issue | Should -Match 'days old'
        @($f | Where-Object { $_.Issue -match 'KNOWN EXPLOITED' }).Count | Should -Be 1
    }

    It 'reports KEV-NOT-EVALUATED when the advisory detail (and so its aliases) is unavailable' {
        Mock -CommandName Get-OsvVulnDetails -MockWith { throw 'detail endpoint down' }
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) `
                -KevCatalog (KevCatalogFixture))
        @($f | Where-Object { $_.TestID -eq 'KEV-NOT-EVALUATED' }).Count | Should -Be 1
        # The vulnerability itself is still reported, HIGH, without KEV text.
        $v = @($f | Where-Object { $_.Category -eq 'vuln-dependency' })[0]
        $v.Severity | Should -Be 'HIGH'
        $v.Issue    | Should -Not -Match 'CISA KEV'
    }

    It 'still evaluates KEV for a CVE-primary advisory when detail is unavailable' {
        Mock -CommandName Invoke-OsvQueryBatch -MockWith {
            param($Queries, $TimeoutSec)
            @($Queries | ForEach-Object { [PSCustomObject]@{ vulns = @([PSCustomObject]@{ id = 'CVE-2021-44228' }) } })
        }
        Mock -CommandName Get-OsvVulnDetails -MockWith { throw 'detail endpoint down' }
        $f = @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType 'python-requirements' -Dependencies @(Deps 1) `
                -KevCatalog (KevCatalogFixture))
        @($f | Where-Object { $_.TestID -eq 'KEV-NOT-EVALUATED' }).Count | Should -Be 0
        @($f | Where-Object { $_.Issue -match 'KNOWN EXPLOITED' }).Count | Should -Be 1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Describe 'CISA KEV live feed — schema compatibility' -Tag 'Online' {
    It 'still serves a catalog this client can parse' {
        $cat = Invoke-KevCatalogFetch -Url 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' -TimeoutSec 60
        $cat.Count   | Should -BeGreaterThan 1000
        $cat.Version | Should -Not -BeNullOrEmpty
        # The mirror must stay equivalent, or the fallback is not a real fallback.
        $mirror = Invoke-KevCatalogFetch -Url 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json' -TimeoutSec 60
        $mirror.Version | Should -Be $cat.Version
    }
}
