#Requires -Version 7.4
<#
    Engine.ps1 - the pipeline (PLAN §3.1): discover -> classify -> extract -> dispatch -> aggregate.
    Returns a result object that the renderers (Report.ps1) consume.

    Recursive archive-member dispatch (issue #31): a generic 'archive' unit's
    extracted contents are classified and dispatched member-by-member through
    the normal analyzer set (Invoke-ArchiveMemberDispatch below), with findings
    folded back onto the PARENT archive under the existing 'archive!inner/path'
    label rather than added as new top-level Units — the v1 JSON schema and unit
    counts are unchanged. Semantic containers (wheels/eggs -> python, .nupkg ->
    nuget, PyTorch .pt/.pth -> model) are extracted the same way but are NOT
    member-dispatched: their existing whole-staging-tree analyzers (PythonRules/
    PipAudit/OsvScan/PickleOpcodeScan) already cover them, and recursing further
    would duplicate those findings. See src/analyzers/OsvScan.ps1, NpmScan.ps1,
    and PickleOpcodeScan.ps1 for the corresponding removal of their old
    generic-'archive' whole-tree walks, now redundant with member dispatch.
#>

# Archive extensions that need extraction before scanning.
$script:ArchiveExtensions = @('.whl', '.egg', '.zip', '.tgz', '.tar.gz', '.nupkg')

# Recursive archive-member dispatch limits (issue #31) — SHARED across the
# whole scan run, not reset per archive. Many individually-small archives
# could otherwise each stay under a per-archive cap while cumulatively
# exhausting the host; Expand-Archive.ps1's 512MB/entry-count checks are a
# separate, per-archive layer (decompression-bomb detection) and are
# unaffected by these.
$script:ArchiveTreeMaxDepth      = 5          # archive-in-archive-in-archive... nesting cap
$script:ArchiveTreeMaxMembers    = 5000       # cumulative classified+dispatched members, whole run
$script:ArchiveTreeMaxBytes      = 1GB        # cumulative member bytes walked, whole run

# When an archive's uncompressed size can't be cheaply estimated before
# extraction (tar/tgz has no central-directory-style index; a corrupt/
# unreadable zip will be rejected by Expand-SubmissionArchive anyway), require
# at least this much headroom before attempting extraction at all. Small
# enough to not block ordinary submissions, large enough that splitting
# content across many small tarballs can't meaningfully outrun the cap.
$script:ArchiveTreeSafeHeadroomBytes = 10MB

function New-AnalyzerContext {
    param(
        [string]$Mode,
        [string]$WorkDir,
        [string]$ReportsDir,
        [string]$HelperDir = '',
        [int]$TimeoutSeconds = 300,
        [PSCustomObject]$ProvisionResult = $null
    )
    [PSCustomObject]@{
        # Tools: keyed by tool Id; each has .Available, .Version, .ScriptsDir / .Command
        Tools          = if ($null -ne $ProvisionResult) { $ProvisionResult.Tools } else { @{} }
        Venv           = if ($null -ne $ProvisionResult) { $ProvisionResult.Venv  } else { $null }
        Mode           = $Mode
        WorkDir        = $WorkDir
        ReportsDir     = $ReportsDir
        HelperDir      = $HelperDir   # src/helpers — Python helper scripts (inspect_binary.py, etc.)
        TimeoutSeconds = $TimeoutSeconds
        AdvisoryDbDate = $null
    }
}

function New-ArchiveTreeBudget {
    <# One of these per Invoke-Scan run — mutated in place as archives (at any
       nesting depth) are extracted and their members walked. #>
    [PSCustomObject]@{
        MaxDepth       = $script:ArchiveTreeMaxDepth
        MaxMembers     = $script:ArchiveTreeMaxMembers
        MaxBytes       = $script:ArchiveTreeMaxBytes
        MemberCount    = 0
        ExpandedBytes  = 0L
        NextStageIndex = 0   # global counter for unique staging-dir names, any depth
    }
}

function Get-DiscoveredFiles {
    param([string]$ScanRoot)
    $reportsPrefix = (Join-Path $ScanRoot '.reports').TrimEnd('\') + '\'
    Get-ChildItem -LiteralPath $ScanRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { -not $_.FullName.StartsWith($reportsPrefix, [StringComparison]::OrdinalIgnoreCase) }
}

function Test-IsArchiveUnit {
    param([PSCustomObject]$Unit)
    $name = $Unit.Name.ToLowerInvariant()
    if ($name.EndsWith('.tar.gz') -or $name.EndsWith('.tgz')) { return $true }
    $ext = [IO.Path]::GetExtension($Unit.Name).ToLowerInvariant()
    return $ext -in @('.whl', '.egg', '.zip', '.nupkg')
}

function Get-ArchiveExpansionEstimate {
    <#
        Cheap, NO-EXTRACTION estimate of an archive's uncompressed size and
        entry count, read straight from the ZIP central directory (a listing
        that already exists in the file — no decompression needed). Returns
        @{ Bytes = <int64>; Count = <int> }, or $null when no cheap estimate is
        feasible: tar/tgz has no equivalent index (reading it requires
        decompressing the whole gzip stream), and a corrupt/unreadable zip is
        left for Expand-SubmissionArchive to reject and report properly.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -notin @('.zip', '.whl', '.egg', '.nupkg')) { return $null }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $bytes = 0L
            $count = 0
            foreach ($e in $zip.Entries) { $bytes += [int64]$e.Length; $count++ }
            return @{ Bytes = $bytes; Count = $count }
        } finally { $zip.Dispose() }
    } catch {
        return $null
    }
}

function Test-ArchiveWouldExceedBudget {
    <#
        Would extracting the archive at $Path push the shared archive-tree
        budget over its cap? Look-ahead, not exhaustion-only: a prior check
        that only blocked once the budget was ALREADY at/over the cap let an
        archive through whenever there was SOME headroom left, even if far
        less than that archive's own size — the next big archive still went
        over. Uses an accurate pre-extraction estimate (ZIP central directory)
        when feasible; when it isn't (tar/tgz, or an archive
        Get-ArchiveExpansionEstimate couldn't read), falls back to requiring
        at least $script:ArchiveTreeSafeHeadroomBytes of remaining headroom —
        conservative, since the true size is unknown.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][PSCustomObject]$Budget)

    $remainingBytes = $Budget.MaxBytes - $Budget.ExpandedBytes
    $remainingCount = $Budget.MaxMembers - $Budget.MemberCount
    if ($remainingCount -le 0) { return $true }

    $estimate = Get-ArchiveExpansionEstimate -Path $Path
    if ($null -ne $estimate) {
        return ($estimate.Bytes -gt $remainingBytes) -or ($estimate.Count -gt $remainingCount)
    }
    return $remainingBytes -lt $script:ArchiveTreeSafeHeadroomBytes
}

function Invoke-UnitDispatch {
    <#
        Select analyzers for $Unit, invoke each under the "return, don't throw"
        contract (PLAN §3.2 rule 2), and report whether any TYPE-SPECIFIC
        analyzer (UnitTypes other than 'any') covered it. This is the exact
        select+invoke block the top-level scan loop used inline before issue
        #31 — factored out so archive-member dispatch (below) can reuse it
        identically rather than recursively re-running the whole scan.

        Callers decide how to REPORT an uninspected unit: the top-level loop
        emits one MTS-NO-ANALYZER finding per unit (unchanged behavior);
        archive-member dispatch aggregates HasCoverage=$false members into one
        MTS-ARCHIVE-MEMBER-UNINSPECTED finding per parent archive instead of
        one per member.
    #>
    param([Parameter(Mandatory)][PSCustomObject]$Unit, [Parameter(Mandatory)][PSCustomObject]$Context,
          [Parameter(Mandatory)][object[]]$Enabled)

    $findings = [System.Collections.Generic.List[object]]::new()
    $selected = @(Select-AnalyzersForUnit -Enabled $Enabled -Unit $Unit)
    $hasCoverage = [bool]@($selected | Where-Object { $_.UnitTypes -notcontains 'any' }).Count

    foreach ($analyzer in $selected) {
        try {
            # Return, don't throw (PLAN §3.2 rule 2)
            $out = & $analyzer.Invoke $Unit $Context
            foreach ($f in @($out)) { if ($f) { $findings.Add($f) } }
        } catch {
            $findings.Add((New-Finding -Tool $analyzer.Name -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType $Unit.Type -File $Unit.RelativePath `
                -Issue "Analyzer '$($analyzer.Name)' errored: $_" -TestID 'MTS-ANALYZER-ERR'))
            Write-Log -Level ERROR -Message "Analyzer '$($analyzer.Name)' failed on $($Unit.RelativePath): $_"
        }
    }
    return [PSCustomObject]@{ Findings = $findings.ToArray(); HasCoverage = $hasCoverage }
}

function Expand-UnitInPlace {
    <#
        Given a freshly classified $Unit (StagingPath=$null), extract it (if
        it's an archive — hardened path, zip-slip/bomb/symlink guards apply) or
        project it (if it's a notebook), into a globally-unique dir under
        $Context.WorkDir, mutating $Unit.StagingPath on success. Every
        extraction/projection in the run — top-level or any nesting depth —
        lands as a direct child of the SAME run-wide staging root and shares
        one globally-increasing name counter ($Budget.NextStageIndex): flat,
        not nested-on-disk, so the existing single top-level cleanup
        (Invoke-Scan's finally block) removes everything regardless of depth,
        and two archives can never collide on a staging dir name even if they
        share a basename at different nesting depths.
        Returns @{ Findings; IsArchive } — IsArchive tells the caller whether
        this unit is eligible for archive-member recursion (only true for
        Test-IsArchiveUnit units; wheels/nupkg/model containers are extracted
        here too but the caller must not recurse into them — see Engine.ps1
        header comment).
    #>
    param([Parameter(Mandatory)][PSCustomObject]$Unit, [Parameter(Mandatory)][PSCustomObject]$Context,
          [Parameter(Mandatory)][PSCustomObject]$Budget)

    $findings  = [System.Collections.Generic.List[object]]::new()
    $isArchive = Test-IsArchiveUnit -Unit $Unit

    if ($isArchive) {
        # The per-unit index makes the staging dir unique. Keying it on the
        # file NAME alone collided whenever two archives (anywhere in the
        # tree, at any depth) shared a basename: extraction does not clear the
        # directory first, so the second archive inherited the first's
        # leftover files and an analyzer's recursive "find the manifest"
        # lookup could read the WRONG package's metadata. On untrusted input a
        # same-name collision is attacker-arrangeable, so this must not depend
        # on submission filenames being distinct.
        $Budget.NextStageIndex++
        $safeName = $Unit.Name -replace '[^\w\-.]', '_'
        $stageDir = Join-Path $Context.WorkDir "unit$($Budget.NextStageIndex)_$safeName"
        $fallback = if ($null -ne $Context.Venv) { $Context.Venv.Python } else { '' }

        $extraction = Expand-SubmissionArchive -InputFile $Unit.Path -OutputDir $stageDir -FallbackPython $fallback
        foreach ($f in $extraction.Findings) { $findings.Add($f) }

        if ($extraction.Success) {
            $Unit.StagingPath = $extraction.StagingPath
            Write-Log -Level DEBUG -Message "StagingPath set: $($Unit.StagingPath)"
        } else {
            Write-Log -Level WARN -Message "Extraction failed for $($Unit.Name) — analyzers requiring staging will skip."
        }
    }
    elseif (Test-IsNotebookUnit -Unit $Unit) {
        # Like extraction, this is a pre-dispatch transform: it emits structural
        # NotebookParser findings (always, core behavior) and points downstream
        # analyzers (Bandit/detect-secrets, deep tier) at the projected .py.
        $Budget.NextStageIndex++
        $safeName = $Unit.Name -replace '[^\w\-.]', '_'
        $projDir  = Join-Path $Context.WorkDir "nb$($Budget.NextStageIndex)_$safeName"
        $proj = Convert-NotebookToPythonSource -NotebookPath $Unit.Path -OutputRoot $projDir `
            -OutputName "$safeName.py" -RelPath $Unit.RelativePath
        foreach ($f in $proj.Findings) { $findings.Add($f) }
        if ($proj.Success) {
            $Unit.StagingPath = $projDir   # code-cell projection; scanners read this
            Write-Log -Level DEBUG -Message "Notebook projection dir: $projDir"
        }
    }

    return @{ Findings = $findings.ToArray(); IsArchive = $isArchive }
}

function Invoke-ArchiveMemberDispatch {
    <#
        Recursively classify and dispatch every member of an extracted, generic
        'archive' unit (issue #31 — see Engine.ps1 header comment for the full
        design). Content-first classification via New-Unit (catches a disguised
        script hiding behind an innocent extension for free — the same
        mechanism the top-level classifier already uses), each member routed
        through Invoke-UnitDispatch, findings folded back onto the parent
        archive using the 'archive!inner/path' label — never added to the
        top-level Units array.

        A member that is itself a supported archive is extracted (the same
        hardened path — zip-slip/bomb/symlink guards run before every
        extraction, at every depth) and recursed into, subject to $Budget's
        shared cumulative member-count/byte cap (across the WHOLE scan run,
        not per archive) and $Depth's cap against $Budget.MaxDepth. A member
        classified as a semantic container (python/nuget/model) is extracted
        and dispatched as a single unit but NOT member-dispatched further —
        its own whole-staging-tree analyzer already covers it.

        Members with no type-specific analyzer coverage are NOT each given
        their own finding (one warning per README/data file in a large
        archive would be noise) — they're aggregated into ONE
        MTS-ARCHIVE-MEMBER-UNINSPECTED finding per parent archive, capped
        sample of paths, so a disabled/unsupported type never silently reads
        as "reviewed and clean" either.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$ArchiveUnit,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][object[]]$Enabled,
        [Parameter(Mandatory)][PSCustomObject]$Budget,
        [int]$Depth = 1
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if ($Depth -gt $Budget.MaxDepth) {
        $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' `
            -Confidence 'HIGH' -UnitType 'archive' -File $ArchiveUnit.RelativePath `
            -Issue "Nested archive not opened — depth cap ($($Budget.MaxDepth)) reached." `
            -TestID 'MTS-ARCHIVE-DEPTH-CAP' `
            -Recommendation 'Deeply nested archives are a common evasion/bomb vector; inspect this member manually if it is expected content.'))
        return $findings.ToArray()
    }

    $members = @(Get-ChildItem -LiteralPath $ArchiveUnit.StagingPath -Recurse -File -ErrorAction SilentlyContinue)
    $uninspected   = [System.Collections.Generic.List[string]]::new()
    $budgetSkipped = 0

    for ($i = 0; $i -lt $members.Count; $i++) {
        $file = $members[$i]
        # Look-ahead: would ACCEPTING this member push the cumulative total
        # past the byte cap? Checking the total alone (post-hoc, AFTER
        # accepting) let the one member that crosses 1GB slip through — its
        # own size was never weighed against the remaining headroom before it
        # was admitted. MemberCount's check needs no look-ahead: "count >=
        # max" and "count + 1 > max" are the same test for an integer tally.
        if ($Budget.MemberCount -ge $Budget.MaxMembers -or
            ($Budget.ExpandedBytes + [int64]$file.Length) -gt $Budget.MaxBytes) {
            $budgetSkipped = $members.Count - $i
            break
        }
        $Budget.MemberCount++
        $Budget.ExpandedBytes += [int64]$file.Length

        $innerPath = $file.FullName.Substring($ArchiveUnit.StagingPath.Length).TrimStart('\', '/')
        $childRel  = "$($ArchiveUnit.RelativePath)!$innerPath"

        $classified = New-Unit -File $file -ScanRoot $ArchiveUnit.StagingPath
        $childUnit  = $classified.Unit
        $childUnit.RelativePath = $childRel
        # Relabel every finding this member produces (classification's own
        # disguised-file finding, and extraction/projection findings below) to
        # the full logical 'top.zip!inner.zip!path' chain — each layer only
        # knows its own immediate relative path, not the parent's label.
        foreach ($f in $classified.Findings) { $f.File = $childRel; $findings.Add($f) }

        # These two traversal gates apply ONLY to a member that will be
        # member-dispatched further (a GENERIC 'archive' child, recursed into
        # below) — NOT to a semantic container (python/nuget/model: a wheel/
        # egg/.nupkg also happens to be a ZIP file, but it is never recursed
        # into and its whole-staging-tree analyzer (PythonRules/OsvScan/...)
        # depends on its StagingPath existing. Gating those on depth or budget
        # blocked PythonRules from ever seeing a wheel's contents and broke
        # NuGet identity parsing (.nuspec unreadable) whenever an EARLIER,
        # unrelated generic archive had already used up the shared budget or
        # nesting depth — semantic containers must always extract.
        $isGenericArchiveChild = $childUnit.Type -eq 'archive'

        # Depth cap MUST be checked before extraction, not after: recursing
        # into a would-be-too-deep nested archive via Invoke-ArchiveMemberDispatch
        # would open/decompress it first and only THEN discover, at the top of
        # that call, that Depth exceeds the cap -- the report would say "not
        # opened" for an archive that was, in fact, opened. Check here, one
        # level up, using the depth the RECURSIVE call would run at, and skip
        # Expand-UnitInPlace entirely when it would already be over the cap.
        $depthBlocked  = $false
        $budgetBlocked = $false
        $recursed      = $false
        if ($isGenericArchiveChild -and ($Depth + 1) -gt $Budget.MaxDepth) {
            $depthBlocked = $true
            $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'archive' -File $childRel `
                -Issue "Nested archive not opened — depth cap ($($Budget.MaxDepth)) reached." `
                -TestID 'MTS-ARCHIVE-DEPTH-CAP' `
                -Recommendation 'Deeply nested archives are a common evasion/bomb vector; inspect this member manually if it is expected content.'))
            $dispatch = Invoke-UnitDispatch -Unit $childUnit -Context $Context -Enabled $Enabled
            foreach ($f in $dispatch.Findings) { $findings.Add($f) }
        }
        # Look-ahead budget check (review follow-up): would extracting THIS
        # nested archive push the shared cumulative total over the cap? The
        # per-member pre-charge above only weighed the archive's own
        # (compressed) file size against the budget -- its EXPANDED contents,
        # once opened, are what actually consume the budget as its own member
        # loop walks them. Checked here so a nested archive that would clearly
        # blow the remaining headroom is never opened in the first place.
        elseif ($isGenericArchiveChild -and (Test-ArchiveWouldExceedBudget -Path $file.FullName -Budget $Budget)) {
            $budgetBlocked = $true
            $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'archive' -File $childRel `
                -Issue 'Nested archive not opened — extracting it would exceed the shared archive-tree budget for this scan.' `
                -TestID 'MTS-ARCHIVE-BUDGET-EXCEEDED' `
                -Recommendation 'Absence of findings here is absence of coverage, not evidence this archive is safe. Split the submission across multiple scans if this is expected content.'))
            $dispatch = Invoke-UnitDispatch -Unit $childUnit -Context $Context -Enabled $Enabled
            foreach ($f in $dispatch.Findings) { $findings.Add($f) }
        }
        else {
            $expansion = Expand-UnitInPlace -Unit $childUnit -Context $Context -Budget $Budget
            foreach ($f in $expansion.Findings) { $f.File = $childRel; $findings.Add($f) }

            $dispatch = Invoke-UnitDispatch -Unit $childUnit -Context $Context -Enabled $Enabled
            foreach ($f in $dispatch.Findings) { $findings.Add($f) }

            if ($expansion.IsArchive -and $childUnit.StagingPath) {
                if ($isGenericArchiveChild) {
                    $recursed = $true
                    $nestedFindings = Invoke-ArchiveMemberDispatch -ArchiveUnit $childUnit -Context $Context `
                        -Enabled $Enabled -Budget $Budget -Depth ($Depth + 1)
                    foreach ($f in $nestedFindings) { $findings.Add($f) }
                } else {
                    # Semantic container (python/nuget/model): not recursed, so
                    # its expanded size is never otherwise counted anywhere —
                    # the pre-charge above only counted the compressed file.
                    # Charge its REAL on-disk footprint so later archives in
                    # this scan see accurate remaining headroom. A recursed
                    # generic archive is NOT charged here too — its own member
                    # loop already charges each of ITS members individually;
                    # doing both would double-count the same bytes.
                    $expandedSize = (Get-ChildItem -LiteralPath $childUnit.StagingPath -Recurse -File -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum
                    if ($expandedSize) { $Budget.ExpandedBytes += [int64]$expandedSize }
                }
            }
        }

        # Depth-capped, budget-blocked, and recursed members already carry
        # their own explicit finding explaining why nothing more is here —
        # don't ALSO fold them into the generic "no analyzer coverage"
        # aggregate below.
        if (-not $dispatch.HasCoverage -and -not $depthBlocked -and -not $budgetBlocked -and -not $recursed) {
            $uninspected.Add("$childRel ($($childUnit.Type))")
        }
    }

    if ($uninspected.Count -gt 0) {
        $sample = ($uninspected | Select-Object -First 10) -join ', '
        $more   = if ($uninspected.Count -gt 10) { " and $($uninspected.Count - 10) more" } else { '' }
        $findings.Add((New-Finding -Tool 'Engine' -Category 'parser' -Severity 'INFO' `
            -Confidence 'HIGH' -UnitType 'archive' -File $ArchiveUnit.RelativePath `
            -Issue ("{0} member(s) had no analyzer coverage: {1}{2}." -f $uninspected.Count, $sample, $more) `
            -TestID 'MTS-ARCHIVE-MEMBER-UNINSPECTED' `
            -Recommendation 'Absence of findings here is absence of coverage, not evidence these members are safe.'))
    }

    if ($budgetSkipped -gt 0) {
        $skippedNames = @($members[($members.Count - $budgetSkipped)..($members.Count - 1)] | ForEach-Object {
            $_.FullName.Substring($ArchiveUnit.StagingPath.Length).TrimStart('\', '/')
        } | Select-Object -First 10)
        $more = if ($budgetSkipped -gt $skippedNames.Count) { " and $($budgetSkipped - $skippedNames.Count) more" } else { '' }
        $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' `
            -Confidence 'HIGH' -UnitType 'archive' -File $ArchiveUnit.RelativePath `
            -Issue ("Archive-tree budget exhausted (cumulative {0} member(s) / {1:N0} bytes across this scan) — {2} member(s) not inspected: {3}{4}." -f `
                $Budget.MaxMembers, $Budget.MaxBytes, $budgetSkipped, ($skippedNames -join ', '), $more) `
            -TestID 'MTS-ARCHIVE-BUDGET-EXCEEDED' `
            -Recommendation 'Absence of findings here is absence of coverage, not evidence these members are safe. Split the submission across multiple scans if this is expected content.'))
    }

    return $findings.ToArray()
}

function Invoke-Scan {
    <#
        Run the full pipeline against a folder. Pure orchestration; no rendering.
        Archive units are extracted to a per-run staging dir in $env:TEMP that is
        cleaned up in a finally block regardless of success or failure.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('core', 'full')][string]$Profile = 'core',
        [string[]]$EnableAnalyzers = @(),
        [string[]]$DisableAnalyzers = @(),
        [string]$Mode = 'online',
        [string]$AnalyzerDir,
        [string]$ReportsDir,
        [string]$HelperDir = '',
        [PSCustomObject]$ProvisionResult = $null
    )

    $startTime    = Get-Date
    $scanRoot     = (Resolve-Path -LiteralPath $Path).ProviderPath
    $stamp        = Get-Date -Format 'yyyyMMdd_HHmmss'
    $stagingRoot  = Join-Path $env:TEMP "mts-staging-$stamp-$(Get-Random)"

    # Default HelperDir as sibling of the analyzers dir (src/helpers).
    if (-not $HelperDir -and $AnalyzerDir) {
        $HelperDir = Join-Path (Split-Path $AnalyzerDir -Parent) 'helpers'
    }

    Write-Log -Message "Importing analyzer registry from: $AnalyzerDir"
    $registry = Import-AnalyzerRegistry -AnalyzerDir $AnalyzerDir
    $sel      = Resolve-EnabledAnalyzers -Registry $registry -Profile $Profile `
                    -EnableAnalyzers $EnableAnalyzers -DisableAnalyzers $DisableAnalyzers
    Write-Log -Message ("Profile '{0}': {1} analyzer(s) enabled, {2} disabled." -f `
        $Profile, $sel.Enabled.Count, $sel.DisabledNames.Count)

    $context = New-AnalyzerContext -Mode $Mode -WorkDir $stagingRoot -ReportsDir $ReportsDir `
                   -HelperDir $HelperDir -ProvisionResult $ProvisionResult
    $budget  = New-ArchiveTreeBudget

    $unitResults = [System.Collections.Generic.List[object]]::new()

    try {
        New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null

        foreach ($file in Get-DiscoveredFiles -ScanRoot $scanRoot) {
            $classified = New-Unit -File $file -ScanRoot $scanRoot
            $unit       = $classified.Unit
            $findings   = [System.Collections.Generic.List[object]]::new()
            foreach ($f in $classified.Findings) { $findings.Add($f) }

            # ── Extraction / notebook projection ────────────────────────────
            # Budget check BEFORE extraction, not after: Invoke-ArchiveMemberDispatch
            # only throttles MEMBER processing inside an already-extracted archive —
            # nothing previously stopped this loop from unconditionally decompressing
            # every TOP-LEVEL archive first. A submission of many individually-small,
            # individually-valid archives could otherwise exhaust disk before the
            # shared budget ever got a chance to fire. Look-ahead (Test-ArchiveWouldExceedBudget),
            # not exhaustion-only: a check that only blocked once the budget was
            # ALREADY at/over the cap let the one archive that pushes it over
            # through, every time, since there was always SOME headroom left
            # right up until that archive's own extraction filled it.
            #
            # Gated on $unit.Type -eq 'archive' specifically, NOT
            # Test-IsArchiveUnit (which also matches .whl/.egg/.nupkg): a
            # semantic container is never member-dispatched and does not
            # itself consume this budget, but PythonRules/OsvScan depend on
            # its StagingPath existing -- blocking its extraction because an
            # unrelated EARLIER generic archive used up the budget silently
            # broke wheel/NuGet analysis. Semantic containers always extract.
            $topLevelBudgetBlocked = $false
            if ($unit.Type -eq 'archive' -and (Test-ArchiveWouldExceedBudget -Path $unit.Path -Budget $budget)) {
                $topLevelBudgetBlocked = $true
                $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' `
                    -Confidence 'HIGH' -UnitType 'archive' -File $unit.RelativePath `
                    -Issue 'Archive not opened — extracting it would exceed the shared archive-tree budget for this scan.' `
                    -TestID 'MTS-ARCHIVE-BUDGET-EXCEEDED' `
                    -Recommendation 'Absence of findings here is absence of coverage, not evidence this archive is safe. Split the submission across multiple scans if this is expected content.'))
            } else {
                $expansion = Expand-UnitInPlace -Unit $unit -Context $context -Budget $budget
                foreach ($f in $expansion.Findings) { $findings.Add($f) }

                # A top-level semantic container's expanded size is otherwise
                # never counted (it isn't member-dispatched, so no per-member
                # loop charges it) -- charge its real on-disk footprint so
                # later archives in this scan see accurate remaining headroom.
                if ($expansion.IsArchive -and $unit.Type -ne 'archive' -and $unit.StagingPath) {
                    $expandedSize = (Get-ChildItem -LiteralPath $unit.StagingPath -Recurse -File -ErrorAction SilentlyContinue |
                        Measure-Object -Property Length -Sum).Sum
                    if ($expandedSize) { $budget.ExpandedBytes += [int64]$expandedSize }
                }
            }

            Show-Status "Analyzing: $($unit.RelativePath) [$($unit.Type)]"

            # ── Dispatch to analyzers ─────────────────────────────────────────
            $dispatch = Invoke-UnitDispatch -Unit $unit -Context $context -Enabled $sel.Enabled
            foreach ($f in $dispatch.Findings) { $findings.Add($f) }

            # ── Recursive archive-member dispatch (issue #31) ─────────────────
            # Only generic 'archive' units recurse — semantic containers (python
            # wheels/eggs, nuget, model .pt/.pth) are extracted above but their
            # existing whole-staging-tree analyzer already covers them; see the
            # header comment. When this runs, it takes over responsibility for
            # reporting member-level coverage gaps (its own aggregate finding),
            # so the top-level "unit not covered" check below is skipped for it.
            $memberDispatched = $false
            if ($unit.Type -eq 'archive' -and $unit.StagingPath) {
                $memberFindings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $context `
                    -Enabled $sel.Enabled -Budget $budget -Depth 1
                foreach ($f in $memberFindings) { $findings.Add($f) }
                $memberDispatched = $true
            }

            # No silent coverage gaps: if nothing but the type-agnostic analyzers
            # (FileHash and friends, UnitTypes = 'any') claimed this unit, the file
            # was hashed and listed but never actually understood. Say so, at INFO,
            # rather than letting it read as "reviewed and clean". Fires for
            # 'unsupported' units and for any type with no enabled analyzer.
            # Scope note: this answers "did anything claim this UNIT", which is
            # descriptor truth — if no analyzer claims the unit's type, nothing ran.
            # For a generic 'archive' unit whose extraction succeeded, member
            # dispatch (above) now answers the deeper "was the content INSIDE
            # the archive inspected" question honestly via its own aggregate
            # finding — this check is skipped for it so the two don't produce
            # contradictory/redundant notices on the same unit. Same reasoning
            # for a top-level archive the budget blocked before extraction: the
            # MTS-ARCHIVE-BUDGET-EXCEEDED finding above already explains the gap.
            if (-not $dispatch.HasCoverage -and -not $memberDispatched -and -not $topLevelBudgetBlocked) {
                $findings.Add((New-Finding -Tool 'Engine' -Category 'parser' -Severity 'INFO' `
                    -Confidence 'HIGH' -UnitType $unit.Type -File $unit.RelativePath `
                    -Issue ("No analyzer covers unit type '{0}' — file was hashed and listed but not inspected." -f $unit.Type) `
                    -TestID 'MTS-NO-ANALYZER' `
                    -Recommendation 'Absence of findings here is absence of coverage, not evidence the file is safe.'))
            }

            $unitResults.Add([PSCustomObject]@{
                Name     = $unit.Name
                Type     = $unit.Type
                Path     = $unit.RelativePath
                Findings = $findings.ToArray()
            })
        }
    } finally {
        # Always clean up staging — holds extracted submission content, at
        # every nesting depth (Expand-UnitInPlace lands every extraction here).
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    [PSCustomObject]@{
        ScanRoot          = $scanRoot
        StartTime         = $startTime
        EndTime           = Get-Date
        Profile           = $Profile
        Mode              = $Mode
        EnabledAnalyzers  = @($sel.Enabled | ForEach-Object { $_.Name })
        DisabledAnalyzers = $sel.DisabledNames
        Units             = $unitResults.ToArray()
    }
}
