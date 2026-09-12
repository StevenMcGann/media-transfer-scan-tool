#Requires -Version 7.4
<#
    Kev.ps1 - CISA Known Exploited Vulnerabilities (KEV) catalog client (issue #41).

    KEV answers the question OSV cannot: is this vulnerability known to be
    exploited in the wild? The catalog is small (~1.7 MB, ~1,700 entries) and
    matching is an exact CVE lookup, so the whole feature is one fetch per scan
    plus an O(1) hashtable hit per advisory.

    Used by Osv.ps1 to ENRICH an existing 'vuln-dependency' finding rather than
    to emit a second finding: OSV already emits one finding per (dependency,
    advisory), and a parallel KEV finding would make one vulnerability appear
    twice while turning alias de-duplication into a reporting problem.

    Failure posture (the #42 lesson, one layer up): a catalog that cannot be
    fetched, read, or validated NEVER means "this CVE is not exploited". It
    means KEV was not evaluated, and that is reported as an explicit coverage
    gap. Nothing here throws at the caller -- Get-KevCatalog returns $null with
    a .KevUnavailableReason the analyzer can report.
#>

Set-StrictMode -Version Latest

# Both sources are CISA-controlled and were verified byte-identical on
# 2026-09-12 (same size, catalogVersion, and cveID set). The GitHub mirror is a
# fallback for hosts whose proxy allowlists raw.githubusercontent.com but not
# www.cisa.gov -- see the issue #41 discussion.
$script:KevDefaultSources = @(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json'
)
$script:KevMaxBytes    = 32MB   # the real feed is ~1.7 MB; this only stops a runaway/hostile body
$script:KevStaleDays   = 30     # warn past this age: absence of a hit gets weaker as the copy ages
$script:KevVendoredRel = 'tools/kev/known_exploited_vulnerabilities.json'

# Set by Get-KevCatalog; initialized here so a caller that never resolved a
# catalog (unit tests calling the OSV audit directly) can read it under
# Set-StrictMode without tripping an unset-variable error.
$script:KevUnavailableReason = $null

function Format-KevDate {
    <#
        KEV dates render ISO (yyyy-MM-dd), never in the host's culture.
        ConvertFrom-Json turns "2021-12-10" into a [datetime], and a bare
        [string] cast of that yields '12/10/2021' on a US host and something
        else elsewhere -- report text must not vary by operator locale.
    #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-dd') }
    return [string]$Value
}

function ConvertTo-KevCatalog {
    <#
        Validate a parsed KEV document and build the CVE index. Throws
        [System.IO.InvalidDataException] when the document is not a KEV catalog:
        a proxy login page, an error object, or a schema change. Content type is
        deliberately NOT used as the gate -- cisa.gov serves application/json
        while raw.githubusercontent.com serves text/plain, and neither proves
        the body is a catalog. Structure is the only trustworthy check.
    #>
    param(
        $Parsed,
        [Parameter(Mandatory)][string]$Source,
        [string]$Sha256 = ''
    )
    if ($Parsed -isnot [System.Management.Automation.PSCustomObject] -or -not $Parsed.PSObject.Properties['vulnerabilities']) {
        throw [System.IO.InvalidDataException]::new(
            "KEV catalog from $Source is $(Get-OsvResponseShape $Parsed) instead of an object with a 'vulnerabilities' array")
    }
    # A real JSON array, not an object coerced into one element by @() -- the
    # same trap fixed for OSV querybatch in #43.
    if ($Parsed.vulnerabilities -isnot [array]) {
        throw [System.IO.InvalidDataException]::new(
            "KEV catalog from $Source has a 'vulnerabilities' value that is $(Get-OsvResponseShape $Parsed.vulnerabilities), not an array")
    }
    $entries = @($Parsed.vulnerabilities)
    if ($entries.Count -eq 0) {
        throw [System.IO.InvalidDataException]::new("KEV catalog from $Source contains no entries")
    }

    # Malformed entries are REJECTED, not skipped (PR #47 review): silently
    # dropping them yields an index that looks usable and current while missing
    # CVEs, so a known-exploited dependency would go unannotated with no warning.
    # A partially transformed internal mirror must fail loudly instead.
    $byCve   = @{}
    $invalid = 0
    foreach ($e in $entries) {
        if ($e -isnot [System.Management.Automation.PSCustomObject]) { $invalid++; continue }
        $cve = Get-OsvJsonProp $e 'cveID'
        if ($cve -isnot [string] -or $cve -notmatch '^CVE-\d{4}-\d{4,}$') { $invalid++; continue }
        $byCve[$cve.ToUpperInvariant()] = $e
    }
    if ($invalid -gt 0) {
        throw [System.IO.InvalidDataException]::new(
            "KEV catalog from $Source has $invalid of $($entries.Count) entries with a missing or malformed 'cveID'")
    }
    if ($byCve.Count -eq 0) {
        throw [System.IO.InvalidDataException]::new("KEV catalog from $Source has no entries carrying a 'cveID'")
    }
    # The feed declares its own entry count; a mismatch means a truncated or
    # partially rewritten copy, which must not pass as complete.
    # Parse rather than type-test: ConvertFrom-Json may hand back Int32, Int64 or
    # even a string depending on the document, and a too-narrow [int] test
    # silently skipped this check entirely.
    $declared = Get-OsvJsonProp $Parsed 'count'
    if ($null -ne $declared) {
        $declaredCount = 0L
        if ([int64]::TryParse([string]$declared, [ref]$declaredCount) -and $declaredCount -ne $entries.Count) {
            throw [System.IO.InvalidDataException]::new(
                "KEV catalog from $Source declares count $declaredCount but carries $($entries.Count) entries")
        }
    }

    [PSCustomObject]@{
        Version      = [string](Get-OsvJsonProp $Parsed 'catalogVersion')
        DateReleased = Format-KevDate (Get-OsvJsonProp $Parsed 'dateReleased')
        Count        = $byCve.Count
        Sha256       = $Sha256
        Source       = $Source
        RetrievedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ByCve        = $byCve
    }
}

function Read-KevCatalogFile {
    <#
        Load and validate a catalog from disk (the vendored bundle copy or an
        operator-supplied -KevCatalogPath). Throws on an unreadable/invalid file.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$SourceLabel = '')
    $label = if ($SourceLabel) { $SourceLabel } else { $Path }
    $item  = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.Length -gt $script:KevMaxBytes) {
        throw [System.IO.InvalidDataException]::new(
            "KEV catalog at $label is $([Math]::Round($item.Length / 1MB, 1)) MB, over the $($script:KevMaxBytes / 1MB) MB cap")
    }
    $sha    = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $parsed = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json
    return ConvertTo-KevCatalog -Parsed $parsed -Source $label -Sha256 $sha
}

function Invoke-KevDownload {
    <#
        Stream one URL to a file, enforcing $MaxBytes DURING the transfer
        (PR #47 review): Invoke-WebRequest -OutFile writes the whole body first,
        so a hostile or misconfigured source could fill the temp disk long before
        an after-the-fact size check ran. The declared Content-Length is rejected
        up front when it is already over the cap, and the copy loop aborts the
        moment the running total crosses it.

        Separate from Invoke-KevCatalogFetch so tests can substitute it without
        mocking the whole HTTP stack.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$TimeoutSec = 30,
        [int64]$MaxBytes = 0
    )
    if ($MaxBytes -le 0) { $MaxBytes = $script:KevMaxBytes }
    $capMb  = [Math]::Round($MaxBytes / 1MB, 0)
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $resp = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            if (-not $resp.IsSuccessStatusCode) {
                throw "HTTP $([int]$resp.StatusCode) $($resp.ReasonPhrase) from $Url"
            }
            $declared = $resp.Content.Headers.ContentLength
            if ($null -ne $declared -and $declared -gt $MaxBytes) {
                throw [System.IO.InvalidDataException]::new(
                    "KEV response from $Url declares $([Math]::Round($declared / 1MB, 1)) MB, over the $capMb MB cap")
            }
            $in  = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $out = [System.IO.File]::Create($OutFile)
            try {
                $buffer = [byte[]]::new(81920)
                $total  = 0L
                while (($read = $in.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt $MaxBytes) {
                        throw [System.IO.InvalidDataException]::new(
                            "KEV response from $Url exceeded the $capMb MB cap; transfer aborted")
                    }
                    $out.Write($buffer, 0, $read)
                }
            } finally {
                $out.Dispose(); $in.Dispose()
            }
        } finally {
            $resp.Dispose()
        }
    } finally {
        $client.Dispose()
    }
}

function Invoke-KevCatalogFetch {
    <#
        Download one candidate source to a temp file (size-capped mid-transfer),
        hash it, and validate it. Writing to disk first keeps an oversized body
        away from the JSON parser. Throws on transport failure or an invalid
        catalog; the caller decides whether to try the next source.
    #>
    param([Parameter(Mandatory)][string]$Url, [int]$TimeoutSec = 30)
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("mts-kev-{0}.json" -f [guid]::NewGuid().ToString('n'))
    try {
        Invoke-KevDownload -Url $Url -OutFile $tmp -TimeoutSec $TimeoutSec
        return Read-KevCatalogFile -Path $tmp -SourceLabel $Url
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-KevCatalog {
    <#
        Resolve the KEV catalog for one scan, in order:
          1. -CatalogPath (operator-supplied; wins outright, no network)
          2. online refresh -- -CatalogUrl if given, else the default sources in
             order (cisa.gov, then the cisagov/kev-data mirror)
          3. the vendored bundle copy (tools/kev/...), which is how an
             air-gapped host gets coverage at all
        Offline mode NEVER makes a request; it uses 1 or 3 only.

        Non-throwing by design (the analyzer return-don't-throw rule): returns
        $null when no usable catalog was found, and always sets
        $script:KevUnavailableReason to a reportable sentence. Every source is
        validated independently, so a proxy's HTML page from one source cannot
        poison the next.

        The URL set is scanner-controlled: submitted content never influences it.
    #>
    param(
        [ValidateSet('online', 'offline')][string]$Mode = 'online',
        [string]$CatalogPath = '',
        [string]$CatalogUrl = '',
        [string]$VendoredPath = '',
        [int]$TimeoutSec = 30
    )
    $script:KevUnavailableReason = $null
    $attempts = [System.Collections.Generic.List[string]]::new()

    if ($CatalogPath) {
        try {
            $cat = Read-KevCatalogFile -Path $CatalogPath -SourceLabel $CatalogPath
            Write-Log -Message "KEV: loaded operator-supplied catalog $($cat.Version) ($($cat.Count) CVEs) from $CatalogPath"
            return $cat
        } catch {
            # An explicitly supplied path that fails is operator error worth
            # surfacing; fall through so the scan still gets whatever coverage
            # the vendored copy can provide.
            $attempts.Add("-KevCatalogPath '$CatalogPath': $($_.Exception.Message)")
            Write-Log -Level WARN -Message "KEV: operator-supplied catalog unusable: $($_.Exception.Message)"
        }
    }

    if ($Mode -eq 'online') {
        $urls = if ($CatalogUrl) { @($CatalogUrl) } else { $script:KevDefaultSources }
        foreach ($u in $urls) {
            try {
                $cat = Invoke-KevCatalogFetch -Url $u -TimeoutSec $TimeoutSec
                Write-Log -Message "KEV: fetched catalog $($cat.Version) ($($cat.Count) CVEs) from $u"
                return $cat
            } catch {
                $attempts.Add("$u : $($_.Exception.Message)")
                Write-Log -Level WARN -Message "KEV: source failed ($u): $($_.Exception.Message)"
            }
        }
    }

    if ($VendoredPath -and (Test-Path -LiteralPath $VendoredPath)) {
        try {
            $cat = Read-KevCatalogFile -Path $VendoredPath -SourceLabel 'vendored bundle copy'
            Write-Log -Message "KEV: using vendored catalog $($cat.Version) ($($cat.Count) CVEs)"
            return $cat
        } catch {
            $attempts.Add("vendored copy: $($_.Exception.Message)")
            Write-Log -Level WARN -Message "KEV: vendored catalog unusable: $($_.Exception.Message)"
        }
    }

    $detail = if ($attempts.Count -gt 0) { " Tried: $($attempts -join '; ')" } else { '' }
    $script:KevUnavailableReason = if ($Mode -eq 'offline') {
        "No KEV catalog available offline (no -KevCatalogPath and no vendored copy).$detail"
    } else {
        "No usable KEV catalog could be obtained.$detail"
    }
    Write-Log -Level WARN -Message "KEV: $($script:KevUnavailableReason)"
    return $null
}

function Get-KevCatalogAgeDays {
    <#
        Age of the catalog's own release date in days, or $null when the
        catalog does not carry a parseable dateReleased.
    #>
    param([Parameter(Mandatory)]$Catalog)
    $released = $Catalog.DateReleased
    if (-not $released) { return $null }
    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($released, [ref]$parsed)) { return $null }
    return [Math]::Max(0, [int]((Get-Date).ToUniversalTime() - $parsed.ToUniversalTime()).TotalDays)
}

function Get-KevAnnotation {
    <#
        Match one OSV advisory against the catalog and return the KEV facts, or
        $null for no match. $Ids is the advisory's primary id PLUS its aliases:
        OSV records are frequently GHSA- or PYSEC-primary with the CVE only in
        aliases, so matching the primary id alone would miss most entries.

        De-duplicates by CVE: several ids can alias the same CVE, and the caller
        must not annotate the same finding twice for it.
    #>
    # $Catalog is deliberately NOT mandatory: "no catalog loaded" is a normal
    # state (offline, fetch failed), and the caller must be able to ask without
    # branching. A mandatory parameter rejects $null outright.
    param($Catalog = $null, [string[]]$Ids)
    if ($null -eq $Catalog) { return $null }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($id in @($Ids)) {
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $key = $id.Trim().ToUpperInvariant()
        if ($key -notmatch '^CVE-\d{4}-\d{4,}$') { continue }
        if (-not $seen.Add($key)) { continue }
        if ($Catalog.ByCve.ContainsKey($key)) {
            $e = $Catalog.ByCve[$key]
            return [PSCustomObject]@{
                Cve            = $key
                DateAdded      = Format-KevDate (Get-OsvJsonProp $e 'dateAdded')
                DueDate        = Format-KevDate (Get-OsvJsonProp $e 'dueDate')
                RequiredAction = [string](Get-OsvJsonProp $e 'requiredAction')
                Ransomware     = [string](Get-OsvJsonProp $e 'knownRansomwareCampaignUse')
                VendorProduct  = ("{0} {1}" -f (Get-OsvJsonProp $e 'vendorProject'), (Get-OsvJsonProp $e 'product')).Trim()
            }
        }
    }
    return $null
}

function Get-KevIssueText {
    <#
        The sentence appended to an enriched finding's Issue. Kept in one place
        so the JSON, HTML and TXT reports all read identically.
    #>
    param([Parameter(Mandatory)]$Annotation, [Parameter(Mandatory)]$Catalog)
    $ransom = if ($Annotation.Ransomware -eq 'Known') { ' Known ransomware campaign use.' } else { '' }
    return (" CISA KEV: {0} is KNOWN EXPLOITED (added {1}).{2} [catalog {3}]" -f `
        $Annotation.Cve, $Annotation.DateAdded, $ransom, $Catalog.Version)
}

function Get-KevRecommendationText {
    <#
        The sentence appended to an enriched finding's Recommendation. The due
        date is CISA's BOD 22-01 deadline for US FEDERAL agencies -- worded as
        such deliberately, so a private reviewer does not read it as a
        compliance obligation that binds them.
    #>
    param([Parameter(Mandatory)]$Annotation)
    $action = if ($Annotation.RequiredAction) { " CISA required action: $($Annotation.RequiredAction)" } else { '' }
    $due    = if ($Annotation.DueDate) { " (BOD 22-01 due date for US federal agencies: $($Annotation.DueDate))" } else { '' }
    return ("$action$due").TrimEnd()
}
