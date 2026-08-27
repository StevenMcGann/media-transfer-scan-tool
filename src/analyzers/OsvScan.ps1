#Requires -Version 7.4
<#
    OsvScan analyzer — dependency-vulnerability audit against OSV.dev
    (POST /v1/querybatch + GET /v1/vulns/{id}), across every ecosystem this
    tool currently reads exact dependency versions from (issue #32):

      - PyPI:  requirements.txt (loose 'python-requirements' unit) — exact
               `==` pins only. Anything else (a range, no specifier, multiple
               comma-joined specifiers, a VCS/URL requirement) is reported as
               an explicit "unpinned, OSV skipped" finding rather than
               silently passed over — a fuzzy specifier can't be matched to
               one OSV record with confidence.
      - npm:   package-lock.json (loose 'npm' unit, or found inside an
               extracted 'archive' unit) — schema v1 (`dependencies`) and
               v2/v3 (`packages`); lockfile versions are always exact-resolved,
               so there is no "unpinned" case here.
      - NuGet: a .nupkg's OWN identity (id + version read from its embedded
               .nuspec, namespace-agnostically — the schema URI has changed
               across NuGet client versions). The artifact itself is the
               pinned dependency; there is no separate lock file to read.

    ON BY DEFAULT (issue #32 decision): this tool always runs with network
    access to the connected/staging host before an air-gapped transfer, so
    the audit is core/default-on rather than opt-in. Offline=true only means
    "no external tool to provision" — the audit itself needs network and
    degrades to one coverage-gap finding per manifest when -Mode offline.

    Shared query/scoring logic (PEP 503 normalization, querybatch, per-vuln
    advisory detail, CVSS v3 base-score severity) lives in src/lib/Osv.ps1 so
    every ecosystem here — and any future one — scores and reports the same way.

    Tier: core (default-on).
#>
@{
    Name           = 'OsvScan'
    Version        = '0.1.0'
    UnitTypes      = @('python-requirements', 'npm', 'archive', 'nuget')
    RequiredTools  = @()
    Offline        = $true   # no tool to provision; the OSV call itself needs network
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $findings = [System.Collections.Generic.List[object]]::new()

        # ── PyPI: requirements.txt ───────────────────────────────────────────
        function Get-PinnedPyPIDeps {
            param($Unit, [System.Collections.Generic.List[object]]$Findings)
            $pinned = [System.Collections.Generic.List[object]]::new()
            foreach ($rawLine in (Get-Content -LiteralPath $Unit.Path -ErrorAction SilentlyContinue)) {
                $line = $rawLine.Trim()
                if (-not $line -or $line.StartsWith('#') -or $line.StartsWith('-')) { continue }   # blank/comment/option-or-include

                $line = ($line -split ';', 2)[0]              # strip environment marker
                $line = ($line -split '\s+#', 2)[0].Trim()    # strip inline comment
                if (-not $line) { continue }

                $nameMatch = [regex]::Match($line, '^([A-Za-z0-9][A-Za-z0-9._-]*)')
                $depName = if ($nameMatch.Success) { $nameMatch.Groups[1].Value } else { $line }

                # Drop extras ('pkg[extra1,extra2]') before splitting on ',' so a
                # comma inside the brackets doesn't look like a compound specifier.
                $noExtras = ([regex]::Replace($line, '\[[^\]]*\]', '')).Trim()
                $specs = @($noExtras -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

                if ($specs.Count -eq 1 -and $specs[0] -match '^[A-Za-z0-9][A-Za-z0-9._-]*\s*==\s*(\S+)$') {
                    $ver = $Matches[1]
                    $pinned.Add(@{
                        Name      = Get-Pep503NormalizedName -Name $depName
                        Version   = $ver
                        Ecosystem = 'PyPI'
                        FileLabel = "dependency: $depName $ver"
                    })
                } else {
                    $Findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity 'LOW' -Confidence 'MEDIUM' `
                        -UnitType 'python-requirements' -File $Unit.RelativePath `
                        -Issue "Dependency '$depName' is not exact-pinned ('$line') — unpinned, OSV skipped." `
                        -TestID 'OSV-PYPI-UNPINNED' `
                        -Recommendation 'Pin an exact version (==) to enable a dependency vulnerability check.'))
                }
            }
            return $pinned.ToArray()
        }

        # ── NuGet: the .nupkg's own id/version from its embedded .nuspec ────
        function Get-NuGetDep {
            param($Unit, [System.Collections.Generic.List[object]]$Findings)
            if (-not ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                      (Test-Path -LiteralPath $Unit.StagingPath -PathType Container))) { return $null }

            $nuspec = @(Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -Filter '*.nuspec' -ErrorAction SilentlyContinue) |
                Select-Object -First 1
            if (-not $nuspec) {
                $Findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity 'LOW' -Confidence 'MEDIUM' `
                    -UnitType 'nuget' -File $Unit.RelativePath `
                    -Issue 'No .nuspec found in the extracted package — cannot identify the package for an OSV lookup.' `
                    -TestID 'OSV-NUGET-NO-NUSPEC'))
                return $null
            }

            try { [xml]$xml = Get-Content -LiteralPath $nuspec.FullName -Raw }
            catch {
                $Findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity 'LOW' -Confidence 'LOW' `
                    -UnitType 'nuget' -File $Unit.RelativePath -Issue "Malformed .nuspec: $_" -TestID 'OSV-NUGET-MALFORMED'))
                return $null
            }

            # Namespace-agnostic: the nuspec xmlns URI has changed across NuGet
            # client versions (2010/05, 2011/08, 2012/06, 2013/01, 2013/05, ...).
            $idNode  = $xml.SelectSingleNode("//*[local-name()='metadata']/*[local-name()='id']")
            $verNode = $xml.SelectSingleNode("//*[local-name()='metadata']/*[local-name()='version']")
            $id  = if ($idNode)  { $idNode.InnerText.Trim() }  else { '' }
            $ver = if ($verNode) { $verNode.InnerText.Trim() } else { '' }
            if (-not $id -or -not $ver) {
                $Findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity 'LOW' -Confidence 'MEDIUM' `
                    -UnitType 'nuget' -File $Unit.RelativePath `
                    -Issue '.nuspec is missing <id> and/or <version> — cannot identify the package for an OSV lookup.' `
                    -TestID 'OSV-NUGET-NO-NUSPEC'))
                return $null
            }
            return @{ Name = $id; Version = $ver; Ecosystem = 'NuGet'; FileLabel = "dependency: $id $ver" }
        }

        # ── npm: package-lock.json (v1 `dependencies` / v2-v3 `packages`) ──
        function Get-NpmLockDeps {
            param([string]$LockPath, [string]$Rel, [System.Collections.Generic.List[object]]$Findings)
            try {
                # -AsHashtable is REQUIRED: v2/v3 has a root package keyed by ""
                # (empty string), which ConvertFrom-Json rejects without it.
                $lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json -AsHashtable
            } catch {
                $Findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity 'LOW' -Confidence 'LOW' `
                    -UnitType 'npm' -File $Rel -Issue "Malformed package-lock.json: $_" -TestID 'OSV-NPM-MALFORMED'))
                return @()
            }
            $deps = [System.Collections.Generic.List[object]]::new()
            if ($lock.ContainsKey('packages') -and $lock.packages) {
                foreach ($key in $lock.packages.Keys) {
                    if ([string]::IsNullOrEmpty($key)) { continue }   # "" = root project
                    $entry = $lock.packages[$key]
                    $ver = $entry.version
                    if (-not $ver) { continue }
                    $nm = if ($entry.ContainsKey('name') -and $entry.name) { $entry.name } else { ($key -replace '.*node_modules/', '') }
                    $deps.Add(@{ Name = $nm; Version = $ver; Ecosystem = 'npm'; FileLabel = "dependency: $nm@$ver" })
                }
            } elseif ($lock.ContainsKey('dependencies') -and $lock.dependencies) {
                foreach ($name in $lock.dependencies.Keys) {
                    $v = $lock.dependencies[$name].version
                    if ($v) { $deps.Add(@{ Name = $name; Version = $v; Ecosystem = 'npm'; FileLabel = "dependency: $name@$v" }) }
                }
            }
            return $deps.ToArray()
        }

        # ── Resolve dependencies + the manifest's relative label by unit shape ──
        $deps = @()
        $manifestRel = $Unit.RelativePath

        switch ($Unit.Type) {
            'python-requirements' {
                if (-not (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) { return @() }
                # @() wrap is REQUIRED: a function's `return` of an empty array collapses
                # to $null at the caller when it's the sole pipeline output (a classic
                # PowerShell gotcha) — plain assignment alone does not guard against it.
                $deps = @(Get-PinnedPyPIDeps -Unit $Unit -Findings $findings)
            }
            'nuget' {
                $dep = Get-NuGetDep -Unit $Unit -Findings $findings
                if ($dep) { $deps = @($dep) }
            }
            default {
                # 'npm' (loose) or 'archive' (extracted .tgz) — find package-lock.json.
                $lockFiles = [System.Collections.Generic.List[string]]::new()
                if ($Unit.Type -eq 'archive') {
                    if (-not ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                              (Test-Path -LiteralPath $Unit.StagingPath -PathType Container))) { return @() }
                    Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -Filter 'package-lock.json' -ErrorAction SilentlyContinue |
                        ForEach-Object { $lockFiles.Add($_.FullName) }
                } elseif ($Unit.Name.ToLowerInvariant() -eq 'package-lock.json') {
                    $lockFiles.Add($Unit.Path)
                }
                if ($lockFiles.Count -eq 0) { return @() }   # not an npm package / no lockfile — nothing for this analyzer here

                $manifestRel = if ($Unit.Type -eq 'archive' -and $Unit.StagingPath -and $lockFiles[0].StartsWith($Unit.StagingPath)) {
                    "$($Unit.RelativePath)!" + $lockFiles[0].Substring($Unit.StagingPath.Length).TrimStart('\', '/')
                } else { $Unit.RelativePath }

                $allDeps = [System.Collections.Generic.List[object]]::new()
                foreach ($lock in $lockFiles) {
                    $lockRel = if ($Unit.Type -eq 'archive' -and $Unit.StagingPath -and $lock.StartsWith($Unit.StagingPath)) {
                        "$($Unit.RelativePath)!" + $lock.Substring($Unit.StagingPath.Length).TrimStart('\', '/')
                    } else { $Unit.RelativePath }
                    foreach ($d in @(Get-NpmLockDeps -LockPath $lock -Rel $lockRel -Findings $findings)) { $allDeps.Add($d) }
                }
                $deps = $allDeps.ToArray()
            }
        }

        if ($deps.Count -eq 0) {
            Write-Log -Level INFO -Message "OsvScan: no queryable dependency in $($Unit.RelativePath)."
            return $findings.ToArray()
        }

        if ($Context.Mode -eq 'offline') {
            $offlineTestId = switch ($Unit.Type) {
                'python-requirements' { 'OSV-PYPI-OFFLINE' }
                'nuget'                { 'OSV-NUGET-OFFLINE' }
                default                { 'OSV-NPM-OFFLINE' }
            }
            $findings.Add((New-OsvOfflineFinding -Tool 'OsvScan' -UnitType $Unit.Type -File $manifestRel -TestId $offlineTestId))
            return $findings.ToArray()
        }

        foreach ($f in (Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType $Unit.Type -Dependencies $deps `
                -TimeoutSec 30 -ErrorTestId 'OSV-QUERY-ERR')) {
            $findings.Add($f)
        }

        Write-Log -Level INFO -Message "OsvScan: $($findings.Count) finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
