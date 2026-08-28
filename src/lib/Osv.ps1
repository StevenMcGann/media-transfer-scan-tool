#Requires -Version 7.4
<#
    Osv.ps1 - shared client for the OSV.dev dependency-vulnerability API
    (issue #32). Used by OsvScan.ps1 (PyPI/npm/NuGet) so severity scoring,
    advisory-detail lookup, and coverage-gap wording stay consistent across
    every ecosystem it covers now and any added later.

    Flow: POST /v1/querybatch to find which (name, version) pairs have known
    vulnerabilities, then GET /v1/vulns/{id} once per DISTINCT id found across
    the whole batch (not once per dependency) to pull summary/severity/fixed
    versions for a first-class finding. Best-effort: a network failure at
    either stage degrades to one coverage-gap finding, never a silent empty
    result and never a thrown exception (PLAN §3.2 "return, don't throw").
#>

Set-StrictMode -Version Latest

$script:OsvApiBase = 'https://api.osv.dev/v1'

function Get-Pep503NormalizedName {
    <#
        PEP 503 name normalization: lowercase, runs of -_. collapsed to a
        single '-'. OSV's PyPI ecosystem matches on the normalized name.
    #>
    param([Parameter(Mandatory)][string]$Name)
    return ([regex]::Replace($Name.Trim(), '[-_.]+', '-')).ToLowerInvariant()
}

function Get-CvssV3BaseScore {
    <#
        Compute the CVSS v3.0/3.1 Base Score from a vector string (FIRST.org
        formula). Returns [double] or $null if the vector is missing a
        required metric / isn't a v3 vector. CVSS v4 vectors return $null
        (different, non-additive formula) — callers fall back to another
        severity signal.
    #>
    param([Parameter(Mandatory)][string]$Vector)

    if ($Vector -notmatch '^CVSS:3\.(?<minor>[01])/') { return $null }
    $isV31 = ($Matches['minor'] -eq '1')

    $metrics = @{}
    foreach ($pair in ($Vector -split '/')) {
        $kv = $pair -split ':', 2
        if ($kv.Count -eq 2) { $metrics[$kv[0]] = $kv[1] }
    }
    foreach ($req in @('AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A')) {
        if (-not $metrics.ContainsKey($req)) { return $null }
    }

    $avMap  = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.2 }
    $acMap  = @{ L = 0.77; H = 0.44 }
    $uiMap  = @{ N = 0.85; R = 0.62 }
    $ciaMap = @{ H = 0.56; L = 0.22; N = 0 }
    $scopeChanged = ($metrics['S'] -eq 'C')
    $prMap = if ($scopeChanged) { @{ N = 0.85; L = 0.68; H = 0.5 } } else { @{ N = 0.85; L = 0.62; H = 0.27 } }

    foreach ($check in @(
        @{ Map = $avMap;  Key = 'AV' }, @{ Map = $acMap;  Key = 'AC' }, @{ Map = $prMap; Key = 'PR' },
        @{ Map = $uiMap;  Key = 'UI' }, @{ Map = $ciaMap; Key = 'C' },  @{ Map = $ciaMap; Key = 'I' },
        @{ Map = $ciaMap; Key = 'A' }
    )) {
        if (-not $check.Map.ContainsKey($metrics[$check.Key])) { return $null }
    }

    $av = $avMap[$metrics['AV']]; $ac = $acMap[$metrics['AC']]; $pr = $prMap[$metrics['PR']]; $ui = $uiMap[$metrics['UI']]
    $c  = $ciaMap[$metrics['C']]; $i  = $ciaMap[$metrics['I']]; $a  = $ciaMap[$metrics['A']]

    $iscBase = 1 - ((1 - $c) * (1 - $i) * (1 - $a))
    if ($iscBase -le 0) { return 0.0 }

    # CVSS v3.1 changed the scope-changed impact formula from v3.0 (a documented
    # fix for a discontinuity in the v3.0 curve -- FIRST.org "Changes since
    # CVSS v3.0"): the 0.9731 scaling factor and exponent 13 replace v3.0's
    # unscaled term and exponent 15. Using the wrong one for a v3.1 vector can
    # cross a severity-band boundary (verified: AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L
    # scores 7.0/HIGH under the v3.0 formula but 6.9/MEDIUM under v3.1's).
    $isc = if ($scopeChanged -and $isV31) {
        7.52 * ($iscBase - 0.029) - 3.25 * [Math]::Pow(($iscBase * 0.9731 - 0.02), 13)
    } elseif ($scopeChanged) {
        7.52 * ($iscBase - 0.029) - 3.25 * [Math]::Pow(($iscBase - 0.02), 15)
    } else {
        6.42 * $iscBase
    }
    if ($isc -le 0) { return 0.0 }

    $exploitability = 8.22 * $av * $ac * $pr * $ui
    $raw = if ($scopeChanged) { 1.08 * ($isc + $exploitability) } else { $isc + $exploitability }
    $raw = [Math]::Min($raw, 10.0)

    # CVSS "Roundup" (spec Appendix A) — round UP to the nearest 0.1 via integer
    # math so IEEE-754 float error never rounds a .x5 the wrong way.
    $intInput = [Math]::Round($raw * 100000)
    if ($intInput % 10000 -eq 0) {
        return $intInput / 100000.0
    } else {
        return ([Math]::Floor($intInput / 10000) + 1) / 10.0
    }
}

function Get-OsvJsonProp {
    <#
        Safe optional-property read for a ConvertFrom-Json/Invoke-RestMethod
        object: returns $null for a property that is absent (not just $null)
        rather than throwing under Set-StrictMode -Version Latest. OSV's JSON
        omits keys entirely rather than emitting null/empty ('{}' for "no
        vulns", no 'summary' key on some minimal PYSEC records, etc.).
    #>
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function Get-OsvSeverityBand {
    <#
        Best available severity signal for one OSV vuln-detail record, in
        preference order: (1) an explicit database_specific.severity string
        (GHSA records carry this), (2) a computed CVSS v3 base score, (3) a
        keyword heuristic over the summary/details text (mirrors PipAudit's
        existing fallback for records with no structured severity at all).
        Never returns a value lower than the caller should trust — an
        unscored, unkeyworded record defaults to HIGH rather than silently
        downgrading a known vulnerability.
    #>
    param([Parameter(Mandatory)]$VulnDetail)

    $dbSpecific = Get-OsvJsonProp $VulnDetail 'database_specific'
    $dbSeverity = Get-OsvJsonProp $dbSpecific 'severity'
    if ($dbSeverity) {
        switch -Regex ($dbSeverity) {
            '(?i)^critical$'          { return 'CRITICAL' }
            '(?i)^high$'               { return 'HIGH' }
            '(?i)^(moderate|medium)$'  { return 'MEDIUM' }
            '(?i)^low$'                { return 'LOW' }
        }
    }

    $severities = Get-OsvJsonProp $VulnDetail 'severity'
    if ($severities) {
        foreach ($s in @($severities)) {
            $type  = Get-OsvJsonProp $s 'type'
            $score = Get-OsvJsonProp $s 'score'
            if ($type -eq 'CVSS_V3' -and $score) {
                $base = Get-CvssV3BaseScore -Vector $score
                if ($null -ne $base) {
                    if     ($base -ge 9.0) { return 'CRITICAL' }
                    elseif ($base -ge 7.0) { return 'HIGH' }
                    elseif ($base -ge 4.0) { return 'MEDIUM' }
                    else                   { return 'LOW' }
                }
            }
        }
    }

    $text = "$(Get-OsvJsonProp $VulnDetail 'summary') $(Get-OsvJsonProp $VulnDetail 'details')"
    if ($text -match '(?i)critical|remote code execution|\brce\b')  { return 'CRITICAL' }
    if ($text -match '(?i)privilege escalation')                     { return 'HIGH' }
    if ($text -match '(?i)\b(moderate|medium)\b')                    { return 'MEDIUM' }
    return 'HIGH'
}

function Test-OsvPackageMatches {
    <#
        Does one OSV 'affected[].package' record identify the SAME package we
        queried? An advisory can list several affected packages (cross-language
        GHSA records, monorepo-style entries); without this check a fix-version
        hint can be pulled from an unrelated package. PyPI compares PEP 503-
        normalized names (OSV's own PyPI matching rule); other ecosystems compare
        case-insensitively. A record with no name/ecosystem at all is treated as
        matching (fail open — better to keep a possibly-relevant hint than to
        silently drop it because the advisory's shape is unusually sparse).
    #>
    param($AffectedPackageName, $AffectedEcosystem, [string]$DepName, [string]$DepEcosystem)
    if ($AffectedEcosystem -and $AffectedEcosystem -ne $DepEcosystem) { return $false }
    if (-not $AffectedPackageName) { return $true }
    if ($DepEcosystem -eq 'PyPI') {
        return (Get-Pep503NormalizedName -Name $AffectedPackageName) -eq (Get-Pep503NormalizedName -Name $DepName)
    }
    return $AffectedPackageName.Equals($DepName, [StringComparison]::OrdinalIgnoreCase)
}

function Test-OsvFixNotNewerThan {
    <#
        Best-effort, ecosystem-agnostic version compare: is $FixVersion at or
        below $CurrentVersion, meaning it would be a nonsensical/irrelevant
        "upgrade" hint (an advisory can carry multiple affected ranges — e.g. a
        1.x branch fixed in 1.5.3 and a 2.x branch fixed in 2.3.1 — and the
        wrong branch's fix must not be offered as the remediation for our
        version)? Compares dot/dash/plus/underscore-separated segments
        numerically where both sides are digits, else as case-insensitive
        strings. Returns $false (keep the fix) whenever a segment pair isn't
        confidently comparable — this must never hide a real fix because a
        pre-release suffix or exotic version scheme couldn't be parsed; the
        cost of an occasional over-inclusive hint is far lower than the cost of
        silently dropping a valid one (PLAN §3.2 "return, don't throw" spirit).
    #>
    param([Parameter(Mandatory)][string]$FixVersion, [Parameter(Mandatory)][string]$CurrentVersion)
    $fTok = @($FixVersion     -split '[.\-+_]' | Where-Object { $_ -ne '' })
    $cTok = @($CurrentVersion -split '[.\-+_]' | Where-Object { $_ -ne '' })
    $n = [Math]::Min($fTok.Count, $cTok.Count)
    for ($i = 0; $i -lt $n; $i++) {
        if ($fTok[$i] -match '^\d+$' -and $cTok[$i] -match '^\d+$') {
            $fn = [int64]$fTok[$i]; $cn = [int64]$cTok[$i]
            if ($fn -ne $cn) { return ($fn -lt $cn) }
        } elseif ($fTok[$i] -ne $cTok[$i]) {
            return $false   # not confidently comparable at this segment — fail open
        }
    }
    if ($fTok.Count -ne $cTok.Count) {
        # All shared segments are equal, so the longer version's EXTRA tokens decide.
        # Those extras mean opposite things depending on their shape:
        #   '1.2'   vs '1.2.3'        → extra '3' is numeric: a deeper release, so
        #                               the shorter version really is the older one.
        #   '2.0.0' vs '2.0.0-beta.1' → extra 'beta' is a PRE-RELEASE suffix, so the
        #                               shorter version is the newer, STABLE one.
        # Treating fewer-tokens as "older" unconditionally discarded the stable 2.0.0
        # fix for a 2.0.0-beta.1 current version — dropping a real remediation, which
        # is exactly what this function's fail-open contract forbids.
        $longer     = if ($fTok.Count -gt $cTok.Count) { $fTok } else { $cTok }
        $firstExtra = $longer[$n]
        if ($firstExtra -notmatch '^\d+$') { return $false }   # pre-release suffix — fail open
        return ($fTok.Count -lt $cTok.Count)
    }
    return $false   # equal versions — not "not newer", but nothing to exclude either
}

function Invoke-OsvQueryBatch {
    <#
        POST one batch of package/version queries to /v1/querybatch. Returns
        the raw .results array (each entry has only .vulns[].id/.modified —
        no advisory detail; that's a separate GET per id). Throws on network
        failure; callers decide how to surface that as a finding.
    #>
    param([Parameter(Mandatory)][object[]]$Queries, [int]$TimeoutSec = 30)
    $body = @{ queries = $Queries } | ConvertTo-Json -Depth 6
    $resp = Invoke-RestMethod -Uri "$script:OsvApiBase/querybatch" -Method Post `
        -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec
    return @($resp.results)
}

function Get-OsvVulnDetails {
    <#
        GET the full advisory record for one OSV/CVE/GHSA/PYSEC id.
        Throws on network failure; callers decide how to surface that.
    #>
    param([Parameter(Mandatory)][string]$Id, [int]$TimeoutSec = 30)
    return Invoke-RestMethod -Uri "$script:OsvApiBase/vulns/$Id" -Method Get -TimeoutSec $TimeoutSec
}

function New-OsvOfflineFinding {
    <# Shared wording for "a lock file/manifest is present but Mode=offline". #>
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$UnitType,
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$TestId
    )
    New-Finding -Tool $Tool -Category 'parser' -Severity 'INFO' -Confidence 'HIGH' `
        -UnitType $UnitType -File $File `
        -Issue 'Dependency CVE audit skipped (offline) — a dependency manifest is present but OSV needs network.' `
        -TestID $TestId `
        -Recommendation 'Re-run online, or check declared dependencies against OSV.dev manually before admitting.'
}

function Get-OsvDependencyFindings {
    <#
        The shared audit: batch-query OSV for @{Name; Version; Ecosystem;
        ManifestFile; DepLabel} dependencies, resolve every distinct vuln id to
        full advisory detail, and emit one 'vuln-dependency' finding per
        (dependency, vuln) pair. Chunks the batch at 100 queries/request (well
        under OSV's documented 1000 limit) — every chunk is attempted, none are
        silently dropped for size.

        Finding.File carries the dependency's MANIFEST path (docs/contract.md
        §1: "File (relative...)"), per-dependency rather than a single value for
        the whole call — dependencies merged from several lock files inside one
        archive unit each keep their own source manifest traceable. The
        dependency's own name/version moves into Issue/Recommendation instead.

        Non-throwing: a querybatch failure emits a coverage-gap finding for that
        chunk and moves on; a per-id detail-fetch failure still emits a finding
        for that vuln (id + dependency), just without summary/severity/fix
        detail, so a transient GET failure on one advisory never drops the
        whole result. Bounded: after $MaxConsecutiveFailures chunks fail in a
        row (api.osv.dev is down, not just one flaky request), remaining chunks
        are NOT attempted — every request is only bounded by $TimeoutSec, but
        manifest size is attacker/submission-controlled and the engine applies
        no analyzer-level timeout here, so an unbounded retry loop could hold an
        online scan for $TimeoutSec times the chunk count. The untried
        dependencies are still reported, grouped by manifest, as one gap finding
        each rather than silently dropped.

        The per-id detail-fetch loop below has a SECOND, independent bound:
        $MaxDetailFetches caps total detail-fetch ATTEMPTS regardless of
        outcome. $MaxConsecutiveFailures alone never trips if the endpoint
        alternates failure/success — the counter resets to 0 on every success
        (correct for its own purpose: a genuinely flaky-but-working endpoint
        shouldn't be treated as down) — so a manifest resolving to many
        distinct advisories against a flapping /vulns/{id} endpoint could still
        hold the scan for uniqueIds.Count * $TimeoutSec with no upper bound.
        Stopping at the cap uses the same "detail unavailable" fallback and
        coverage-gap finding as the consecutive-failure case — a hit already
        confirmed by querybatch is never dropped, just reported without
        summary/severity/fix detail.
    #>
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$UnitType,
        [Parameter(Mandatory)][object[]]$Dependencies,   # @{ Name; Version; Ecosystem; ManifestFile; DepLabel }
        [int]$TimeoutSec = 30,
        [string]$ErrorTestId = 'OSV-QUERY-ERR',
        [int]$MaxConsecutiveFailures = 2,
        [int]$MaxDetailFetches = 500
    )
    $out = [System.Collections.Generic.List[object]]::new()
    if ($Dependencies.Count -eq 0) { return $out.ToArray() }

    $batchSize = 100
    $hits = [System.Collections.Generic.List[object]]::new()
    $consecutiveFailures = 0
    $stoppedAtIndex = -1

    for ($i = 0; $i -lt $Dependencies.Count; $i += $batchSize) {
        $end   = [Math]::Min($i + $batchSize, $Dependencies.Count) - 1
        $chunk = $Dependencies[$i..$end]
        $queries = @($chunk | ForEach-Object {
            @{ package = @{ name = $_.Name; ecosystem = $_.Ecosystem }; version = $_.Version } })

        try {
            # @() wrap is REQUIRED: a function's `return` of an empty array collapses
            # to $null at the caller when it's the sole pipeline output — plain
            # assignment does not guard against it (see OsvScan.ps1 for the full note).
            $chunkResults = @(Invoke-OsvQueryBatch -Queries $queries -TimeoutSec $TimeoutSec)
            $consecutiveFailures = 0
        } catch {
            $consecutiveFailures++
            # Report the unqueried chunk, but DO NOT abandon hits already confirmed
            # by earlier chunks — returning here would turn "OSV confirmed 3
            # vulnerable packages, then the 2nd request failed" into a lone INFO
            # coverage note, hiding real findings. Skip only this chunk's
            # dependencies and let the accumulated hits below still be reported.
            $unqueried = @($chunk | ForEach-Object { $_.Name }) -join ', '
            $out.Add((New-Finding -Tool $Tool -Category 'parser' -Severity 'INFO' -Confidence 'LOW' `
                -UnitType $UnitType -File $chunk[0].ManifestFile `
                -Issue ("OSV dependency audit could not reach api.osv.dev for {0} of {1} dependencies ({2}): {3}" -f `
                    $chunk.Count, $Dependencies.Count, $unqueried, $_) `
                -TestID $ErrorTestId `
                -Recommendation 'These dependencies were NOT audited — absence of findings for them is absence of coverage. Re-run online, or check them against OSV.dev manually before admitting.'))

            if ($consecutiveFailures -ge $MaxConsecutiveFailures) {
                # api.osv.dev is down, not just one flaky request — stop spending
                # $TimeoutSec per remaining chunk on a manifest that can be
                # arbitrarily large. $end is the last index already SEEN (this
                # failed chunk); everything after it was never attempted.
                $stoppedAtIndex = $end + 1
                break
            }
            continue
        }

        for ($j = 0; $j -lt $chunkResults.Count; $j++) {
            # A no-vuln result is '{}' — no 'vulns' property at all (Set-StrictMode
            # throws on a bare .vulns access), not an empty array.
            $entry = $chunkResults[$j]
            $vulns = if ($entry.PSObject.Properties['vulns']) { $entry.vulns } else { $null }
            if ($vulns) {
                $hits.Add(@{ Dep = $chunk[$j]; VulnIds = @($vulns | ForEach-Object { $_.id }) })
            }
        }
    }

    if ($stoppedAtIndex -ge 0 -and $stoppedAtIndex -lt $Dependencies.Count) {
        $untried = $Dependencies[$stoppedAtIndex..($Dependencies.Count - 1)]
        foreach ($grp in ($untried | Group-Object ManifestFile)) {
            $names = @($grp.Group | ForEach-Object { $_.Name }) | Select-Object -First 10
            $more  = if ($grp.Count -gt $names.Count) { " and $($grp.Count - $names.Count) more" } else { '' }
            $out.Add((New-Finding -Tool $Tool -Category 'parser' -Severity 'INFO' -Confidence 'LOW' `
                -UnitType $UnitType -File $grp.Name `
                -Issue ("OSV dependency audit stopped after {0} consecutive transport failures -- {1} more dependencies in this manifest were never queried ({2}{3})." -f `
                    $MaxConsecutiveFailures, $grp.Count, ($names -join ', '), $more) `
                -TestID $ErrorTestId `
                -Recommendation 'These dependencies were NOT audited — absence of findings for them is absence of coverage. Re-run online, or check them against OSV.dev manually before admitting.'))
        }
    }

    if ($hits.Count -eq 0) { return $out.ToArray() }

    # One detail fetch per DISTINCT id across the whole batch, not per dependency.
    # Bounded the same way as the querybatch chunk loop above: this is a separate
    # sequential network call per id with its own $TimeoutSec, and the engine
    # applies no analyzer-level timeout here, so a manifest resolving to many
    # distinct advisories during a /vulns/{id} outage could otherwise hold an
    # online scan for uniqueIds.Count * $TimeoutSec. A hit already confirmed by
    # querybatch is NOT dropped when detail is unavailable -- it still gets a
    # finding via the "detail unavailable" fallback below, just without
    # summary/severity/fix detail; only further ATTEMPTS stop.
    $uniqueIds = @($hits | ForEach-Object { $_.VulnIds } | Select-Object -Unique)
    $detailCache = @{}
    $detailConsecutiveFailures = 0
    $detailAttempts = 0
    $detailStoppedAtIndex = -1
    $detailStopReason = $null
    for ($k = 0; $k -lt $uniqueIds.Count; $k++) {
        # Total-attempts cap, independent of the consecutive-failure cap below:
        # checked BEFORE attempting so a manifest with more distinct advisories
        # than $MaxDetailFetches can't out-stall a flapping endpoint that
        # happens to alternate failure/success (the consecutive counter alone
        # never trips in that case — see the doc comment above).
        if ($detailAttempts -ge $MaxDetailFetches) {
            $detailStoppedAtIndex = $k
            $detailStopReason = 'max-fetches'
            break
        }
        $id = $uniqueIds[$k]
        $detailAttempts++
        try {
            $detailCache[$id] = Get-OsvVulnDetails -Id $id -TimeoutSec $TimeoutSec
            $detailConsecutiveFailures = 0
        } catch {
            Write-Log -Level WARN -Message "OSV: advisory detail fetch failed for ${id}: $_"
            $detailCache[$id] = $null
            $detailConsecutiveFailures++
            if ($detailConsecutiveFailures -ge $MaxConsecutiveFailures) {
                $detailStoppedAtIndex = $k + 1
                $detailStopReason = 'consecutive-failures'
                break
            }
        }
    }
    if ($detailStoppedAtIndex -ge 0 -and $detailStoppedAtIndex -lt $uniqueIds.Count) {
        $skippedIds = @($uniqueIds[$detailStoppedAtIndex..($uniqueIds.Count - 1)])
        foreach ($id in $skippedIds) { $detailCache[$id] = $null }   # never attempted, not just failed
        $reasonText = if ($detailStopReason -eq 'max-fetches') {
            "reaching the {0}-advisory total detail-fetch cap for this scan" -f $MaxDetailFetches
        } else {
            "{0} consecutive failures" -f $MaxConsecutiveFailures
        }
        $affectedHits = @($hits | Where-Object { @($_.VulnIds | Where-Object { $_ -in $skippedIds }).Count -gt 0 })
        foreach ($grp in ($affectedHits | Group-Object { $_.Dep.ManifestFile })) {
            $out.Add((New-Finding -Tool $Tool -Category 'parser' -Severity 'INFO' -Confidence 'LOW' `
                -UnitType $UnitType -File $grp.Name `
                -Issue ("OSV advisory-detail lookup stopped after {0} -- {1} of {2} distinct advisories were skipped without an attempt (not just failed). Affected dependencies here are still flagged as vulnerable, without summary/severity/fix detail." -f `
                    $reasonText, $skippedIds.Count, $uniqueIds.Count) `
                -TestID $ErrorTestId `
                -Recommendation 'Re-run online when api.osv.dev is reachable for full advisory detail.'))
        }
    }

    foreach ($hit in $hits) {
        $dep = $hit.Dep
        foreach ($id in $hit.VulnIds) {
            $detail = $detailCache[$id]
            if ($detail) {
                $sev = Get-OsvSeverityBand -VulnDetail $detail
                $summaryProp = Get-OsvJsonProp $detail 'summary'
                $detailsProp = Get-OsvJsonProp $detail 'details'
                $summary = if ($summaryProp) { $summaryProp }
                           elseif ($detailsProp) { ($detailsProp -split "`r?`n" | Select-Object -First 1) }
                           else { 'known vulnerability' }

                $fixed = [System.Collections.Generic.List[string]]::new()
                foreach ($aff in @(Get-OsvJsonProp $detail 'affected')) {
                    $affPkg  = Get-OsvJsonProp $aff 'package'
                    $affName = Get-OsvJsonProp $affPkg 'name'
                    $affEco  = Get-OsvJsonProp $affPkg 'ecosystem'
                    if (-not (Test-OsvPackageMatches $affName $affEco $dep.Name $dep.Ecosystem)) { continue }
                    foreach ($rng in @(Get-OsvJsonProp $aff 'ranges')) {
                        foreach ($ev in @(Get-OsvJsonProp $rng 'events')) {
                            $fixedVer = Get-OsvJsonProp $ev 'fixed'
                            if ($fixedVer -and -not (Test-OsvFixNotNewerThan -FixVersion $fixedVer -CurrentVersion $dep.Version)) {
                                $fixed.Add([string]$fixedVer)
                            }
                        }
                    }
                }
                $fixHint = if ($fixed.Count -gt 0) { " Fix: upgrade to $((@($fixed | Select-Object -Unique)) -join ' or ')." } else { '' }
                $issue = "Dependency '$($dep.DepLabel)': ${id}: ${summary}${fixHint}"
                $rec   = "Review and update '$($dep.Name)' to a patched version.$fixHint"
            } else {
                $sev   = 'HIGH'
                $issue = "Dependency '$($dep.DepLabel)': ${id}: known vulnerability (advisory detail lookup failed — see log for the id)."
                $rec   = "Review '$($dep.Name) $($dep.Version)' against $id manually at https://osv.dev/vulnerability/$id."
            }
            $out.Add((New-Finding -Tool $Tool -Category 'vuln-dependency' -Severity $sev -Confidence 'HIGH' `
                -UnitType $UnitType -File $dep.ManifestFile -Issue $issue -TestID $id -Recommendation $rec))
        }
    }
    return $out.ToArray()
}
