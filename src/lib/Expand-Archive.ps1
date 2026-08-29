#Requires -Version 7.4
<#
    Expand-Archive.ps1 - safely extract submission archives into a staging dir.

    Ported from scan-python-packages v1.6.1 Expand-PythonArchive, then hardened
    for v0.8 archive analysis:
      - PS 7: [System.IO.Compression.ZipFile] used directly for ZIP-family
        archives (.whl, .egg, .zip) — no temp-copy-to-.zip workaround needed
        (that workaround existed solely for PS 5.1's Expand-Archive restriction).
      - PS 7: no EAP wrapper around tar (native stderr no longer triggers Stop).
      - ZIP-family disambiguation: peek at entries to distinguish OOXML / Python
        wheel / npm / plain ZIP (informational; routing is by classified type).
      - v0.8 archive hardening (ZIP): the archive is inspected BEFORE extraction
        and HARD-BLOCKED (never extracted) on a path-traversal entry or a
        decompression bomb; symlink entries and nested archives are flagged.
      - tar (issue #31 review): extracted entry-by-entry via .NET's
        System.Formats.Tar (available since .NET 7 / pwsh 7.4's runtime) —
        no external tar binary or Python fallback. Path-traversal entries are
        HARD-blocked per entry; when a shared archive-tree $Budget is supplied
        (Engine.ps1 always supplies one), each entry's size is checked against
        it BEFORE writing. This is the only way to bound what a tarball
        actually writes: unlike a ZIP's central directory, a gzip-wrapped
        tar's uncompressed size can't be read upfront, and the PREVIOUS
        bulk-extraction approach (`tar -xzf` / Python tarfile.extractall())
        wrote everything before returning control — a highly-compressible
        nested tar could consume unbounded disk before any accounting ran.
        A per-archive aggregate cap and entry-count cap (the same constants
        the ZIP path uses) apply regardless of $Budget, for parity with ZIP's
        bomb guard, which no per-entry compression ratio exists for a tar
        (the whole stream is one continuous gzip, not per-entry like ZIP).

    Returns @{ Success; StagingPath; Findings }. On failure (corrupt / blocked /
    error) Success=$false and the staging dir is left empty or partial.
#>

Set-StrictMode -Version Latest

# Decompression-bomb thresholds (v0.8).
$script:MaxTotalUncompressed = 512MB   # aggregate cap across all entries
$script:BombEntryFloor       = 10MB    # only ratio-check entries above this size
$script:BombRatio            = 100      # uncompressed/compressed ratio that signals a bomb
$script:MaxEntryCount        = 50000    # absurd entry counts are bomb-like

# Extensions that indicate a nested archive (flagged, not recursively expanded).
$script:NestedArchiveExt = @('.zip', '.whl', '.egg', '.jar', '.tgz', '.gz', '.tar', '.7z', '.rar', '.bz2', '.xz')

function Test-ZipArchiveHazards {
    <#
        Inspect a ZIP's entries (without extracting) for path traversal,
        decompression bombs, symlinks, and nested archives. Returns
        @{ Block = <bool>; Findings = <object[]>; EntryNames = <string[]> }.
        Block is set for traversal or bomb hazards — the caller must NOT extract.
    #>
    param([string]$InputFile, [string]$RelPath)

    $findings = [System.Collections.Generic.List[object]]::new()
    $entryNames = @()
    $block = $false

    $zip = [System.IO.Compression.ZipFile]::OpenRead($InputFile)   # throws InvalidDataException if corrupt
    try {
        $entries = @($zip.Entries)
        $entryNames = @($entries | ForEach-Object { $_.FullName })

        # ── Path traversal (zip-slip) — HARD block ───────────────────────────
        $traversal = @($entryNames | Where-Object {
            $_ -match '\.\.[/\\]' -or [IO.Path]::IsPathRooted($_) -or $_.StartsWith('/') -or $_ -match '^[A-Za-z]:'
        })
        if ($traversal.Count -gt 0) {
            $block = $true
            $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $RelPath `
                -Issue "Path-traversal (zip-slip) entry/entries: $(($traversal | Select-Object -First 3) -join ', ')" `
                -TestID 'MTS-EXTRACT-TRAVERSAL' `
                -Recommendation 'Rejected — the archive tries to write outside the extraction directory.'))
        }

        # ── Decompression bomb — HARD block ──────────────────────────────────
        $totalUncompressed = 0L
        foreach ($e in $entries) {
            $totalUncompressed += [int64]$e.Length
            if ($e.Length -gt $script:BombEntryFloor -and $e.CompressedLength -gt 0) {
                $ratio = [double]$e.Length / [double]$e.CompressedLength
                if ($ratio -gt $script:BombRatio) {
                    $block = $true
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                        -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $RelPath `
                        -Issue ("Decompression-bomb entry '{0}': {1:N0} bytes from {2:N0} (ratio {3:N0}x)." -f `
                            $e.FullName, $e.Length, $e.CompressedLength, $ratio) `
                        -TestID 'MTS-EXTRACT-BOMB' `
                        -Recommendation 'Rejected — entry expands far beyond its compressed size.'))
                }
            }
        }
        if ($totalUncompressed -gt $script:MaxTotalUncompressed) {
            $block = $true
            $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $RelPath `
                -Issue ("Total uncompressed size {0:N0} bytes exceeds the {1:N0}-byte cap." -f $totalUncompressed, $script:MaxTotalUncompressed) `
                -TestID 'MTS-EXTRACT-BOMB' `
                -Recommendation 'Rejected — aggregate decompressed size exceeds the safety cap.'))
        }
        if ($entries.Count -gt $script:MaxEntryCount) {
            $block = $true
            $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $RelPath `
                -Issue "Archive has $($entries.Count) entries (cap $($script:MaxEntryCount))." `
                -TestID 'MTS-EXTRACT-BOMB'))
        }

        # ── Symlink entries — flag (not blocked; .NET extract ignores them) ──
        $symlinks = @($entries | Where-Object {
            # Unix mode is the high 16 bits of ExternalAttributes; S_IFLNK = 0xA000.
            # Mask to 32 bits first so a sign-extended int32 doesn't skew the shift.
            ((([int64]$_.ExternalAttributes -band 0xFFFFFFFF) -shr 16) -band 0xF000) -eq 0xA000
        })
        if ($symlinks.Count -gt 0) {
            $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                -Severity 'MEDIUM' -Confidence 'MEDIUM' -UnitType 'archive' -File $RelPath `
                -Issue "Archive contains $($symlinks.Count) symlink entry/entries: $((@($symlinks | ForEach-Object { $_.FullName }) | Select-Object -First 3) -join ', ')" `
                -TestID 'MTS-EXTRACT-SYMLINK' `
                -Recommendation 'Review — symlinks in archives can redirect writes/reads outside the tree.'))
        }

        # ── Nested archives — flag (informational; recursed by the engine) ───
        # Generic 'archive' units are recursively member-dispatched (issue #31):
        # a nested archive found here IS opened, extracted, and its own members
        # classified and analyzed, subject to the shared depth/count/byte budget
        # (Engine.ps1). This finding is now purely informational -- it names
        # what nesting was present, not a coverage gap by itself; a real gap
        # (depth/budget exhausted) gets its own explicit finding at that point.
        $nested = @($entryNames | Where-Object {
            $n = $_.ToLowerInvariant()
            @($script:NestedArchiveExt | Where-Object { $n.EndsWith($_) }).Count -gt 0
        })
        if ($nested.Count -gt 0) {
            $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                -Severity 'LOW' -Confidence 'MEDIUM' -UnitType 'archive' -File $RelPath `
                -Issue "Archive contains $($nested.Count) nested archive(s): $(($nested | Select-Object -First 3) -join ', ')" `
                -TestID 'MTS-EXTRACT-NESTED' `
                -Recommendation 'Nested archives are a common bomb/evasion vector — review the recursively-scanned findings for these members.'))
        }
    } finally {
        $zip.Dispose()
    }

    return @{ Block = $block; Findings = $findings.ToArray(); EntryNames = $entryNames }
}

function Expand-TarArchive {
    <#
        Stream-extract a gzip tarball entry-by-entry via .NET's System.Formats.Tar
        (issue #31 review — see the module header for why). Returns
        @{ Success; Findings; BudgetStopped }.

        Path-traversal entries are HARD-blocked (matching the ZIP path):
        nothing is written for that entry or any entry after it, and the whole
        call reports Success=$false.

        When $Budget is supplied (non-$null), each file entry's size is
        weighed against a SNAPSHOT of the shared archive-tree budget's
        remaining headroom, taken once before streaming starts — look-ahead,
        the same principle as every other budget check in this codebase
        (Engine.ps1's Test-ArchiveWouldExceedBudget and per-member loop).
        Extraction simply STOPS at that entry (Success stays $true — this is
        normal, expected behavior for a large submission, not an error) and
        $findings carries an MTS-ARCHIVE-BUDGET-EXCEEDED note.

        This function reads $Budget but never writes to it: every extracted
        member here is a NEW unit that Invoke-ArchiveMemberDispatch walks and
        charges for real immediately afterwards (the same authoritative
        charging point ZIP-extracted members already go through). Charging
        $Budget here too would double-count these exact files a moment
        later — undercounting real remaining headroom and starving dispatch
        of budget it should have had (issue #31 review round 4).

        $Budget = $null means "no budget enforcement" (e.g. a direct test
        call, or a future caller that doesn't need it) — extraction proceeds
        unbounded by budget, same as before this fix, still subject to the
        aggregate/entry-count caps below.

        A per-archive aggregate size cap and entry-count cap
        ($script:MaxTotalUncompressed / $script:MaxEntryCount, the SAME
        constants the ZIP path uses) apply regardless of $Budget — parity
        with ZIP's bomb guard. No per-entry compression-ratio check exists
        here (unlike ZIP): a gzip-wrapped tar compresses the whole stream
        continuously, so there is no meaningful per-entry compressed size to
        compare against.
    #>
    param(
        [Parameter(Mandatory)][string]$InputFile,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$RelPath,
        [PSCustomObject]$Budget = $null
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    $budgetStopped = $false
    $budgetSkippedNames = [System.Collections.Generic.List[string]]::new()
    $localTotal = 0L
    $entryCount = 0
    $symlinkCount = 0
    $nestedNames = [System.Collections.Generic.List[string]]::new()

    # Read-only snapshot of remaining headroom — Invoke-ArchiveMemberDispatch
    # charges $Budget for real once these members are walked; this function
    # only ever reads it, never mutates it (see the double-charge note above).
    $budgetRemainingCount = [int64]0
    $budgetRemainingBytes = [int64]0
    if ($null -ne $Budget) {
        # StagedDirectories included: directories already created by earlier
        # extractions in this run consume inodes exactly as files do (review
        # follow-up 5, #14), and this tarball's own directory entries are
        # counted against the same headroom below.
        $budgetRemainingCount = $Budget.MaxMembers - $Budget.MemberCount - $Budget.StagedDirectories
        $budgetRemainingBytes = $Budget.MaxBytes - $Budget.ExpandedBytes
    }
    $budgetLocalCount = 0
    $budgetLocalBytes = 0L

    # A HARD-block (traversal/bomb/entry-count cap) or a stream-read error can
    # fire after EARLIER entries in this same tarball were already written --
    # streaming extraction has no "inspect first, then extract" phase the way
    # ZIP's central-directory precheck does. Leaving that partial content
    # behind on failure both wastes disk (repeated crafted tarballs never get
    # charged against the budget, since StagingPath is never set on failure)
    # and is stale content nothing will ever clean up until the whole scan's
    # staging root is removed. Called immediately before every Success=$false
    # return in this function.
    $clearPartialExtraction = {
        Remove-Item -LiteralPath $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $fileStream = $null; $gzipStream = $null; $tarReader = $null
    try {
        $fileStream = [System.IO.File]::OpenRead($InputFile)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        $tarReader  = [System.Formats.Tar.TarReader]::new($gzipStream)

        while ($true) {
            $entry = $tarReader.GetNextEntry()
            if ($null -eq $entry) { break }
            $entryName = $entry.Name

            # ── Path traversal (zip-slip for tar) — HARD block ────────────────
            if ($entryName -match '\.\.[/\\]' -or [IO.Path]::IsPathRooted($entryName) -or
                $entryName.StartsWith('/') -or $entryName -match '^[A-Za-z]:') {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                    -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $RelPath `
                    -Issue "Path-traversal entry in tarball: $entryName" `
                    -TestID 'MTS-EXTRACT-TRAVERSAL' `
                    -Recommendation 'Rejected — tarball tries to write outside the extraction directory.'))
                & $clearPartialExtraction
                return @{ Success = $false; Findings = $findings.ToArray(); BudgetStopped = $false }
            }

            $entryCount++
            if ($entryCount -gt $script:MaxEntryCount) {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' -Severity 'HIGH' -Confidence 'HIGH' `
                    -UnitType 'archive' -File $RelPath -Issue "Tarball has more than $($script:MaxEntryCount) entries." `
                    -TestID 'MTS-EXTRACT-BOMB' -Recommendation 'Rejected — aggregate entry count exceeds the safety cap.'))
                & $clearPartialExtraction
                return @{ Success = $false; Findings = $findings.ToArray(); BudgetStopped = $false }
            }

            $isFileEntry = $entry.EntryType -in @(
                [System.Formats.Tar.TarEntryType]::RegularFile,
                [System.Formats.Tar.TarEntryType]::V7RegularFile,
                [System.Formats.Tar.TarEntryType]::ContiguousFile)

            if ($entry.EntryType -eq [System.Formats.Tar.TarEntryType]::SymbolicLink -or
                $entry.EntryType -eq [System.Formats.Tar.TarEntryType]::HardLink) {
                $symlinkCount++
                continue   # not written — same treatment as ZIP's symlink entries
            }
            if (-not $isFileEntry -and $entry.EntryType -ne [System.Formats.Tar.TarEntryType]::Directory) {
                continue   # device/fifo/etc. — never written
            }

            if ($isFileEntry) {
                $entrySize = [Math]::Max(0L, [int64]$entry.Length)
                $localTotal += $entrySize
                if ($localTotal -gt $script:MaxTotalUncompressed) {
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' -Severity 'HIGH' -Confidence 'HIGH' `
                        -UnitType 'archive' -File $RelPath `
                        -Issue ("Total uncompressed size exceeds the {0:N0}-byte per-archive cap." -f $script:MaxTotalUncompressed) `
                        -TestID 'MTS-EXTRACT-BOMB' -Recommendation 'Rejected — aggregate decompressed size exceeds the safety cap.'))
                    & $clearPartialExtraction
                    return @{ Success = $false; Findings = $findings.ToArray(); BudgetStopped = $false }
                }

                $n = $entryName.ToLowerInvariant()
                if (@($script:NestedArchiveExt | Where-Object { $n.EndsWith($_) }).Count -gt 0) {
                    $nestedNames.Add($entryName)
                }
            }

            # Budget applies to DIRECTORY entries as well as files (review
            # follow-up 5, #14): a directory this loop creates is a real
            # staged inode, and nothing downstream ever charges it --
            # MemberCount counts dispatchable members, and member dispatch
            # enumerates -File only. A tarball of pure directory entries
            # previously consumed no budget at all. Only the BYTE half is
            # file-specific; a directory contributes no length.
            if ($null -ne $Budget) {
                # Count exhaustion is a true dead end: the local count only
                # grows, so once it hits the remaining headroom, no LATER
                # entry (regardless of size) can ever be admitted either --
                # stop reading entirely.
                if (($budgetLocalCount + 1) -gt $budgetRemainingCount) {
                    $budgetStopped = $true
                    break
                }
                # Per-entry byte miss is NOT exhaustion-wide (review
                # follow-up 5, #9 -- the same fix as
                # Invoke-ArchiveMemberDispatch's per-member loop, review
                # follow-up 5, #7): one large entry must not block a
                # LATER, smaller one that would still fit within the
                # remaining headroom on its own. Skip only this entry --
                # don't write it -- and keep reading subsequent headers;
                # TarReader discards the unread data automatically on the
                # next GetNextEntry() call.
                if ($isFileEntry -and ($budgetLocalBytes + $entrySize) -gt $budgetRemainingBytes) {
                    $budgetStopped = $true
                    $budgetSkippedNames.Add($entryName)
                    continue
                }
                $budgetLocalCount++
                if ($isFileEntry) { $budgetLocalBytes += $entrySize }
            }

            $dest = Join-Path $OutputDir $entryName
            if ($entry.EntryType -eq [System.Formats.Tar.TarEntryType]::Directory) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
            } else {
                $destDir = Split-Path $dest -Parent
                if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                $entry.ExtractToFile($dest, $true)
            }
        }
    } catch {
        $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' -Severity 'HIGH' -Confidence 'MEDIUM' `
            -UnitType 'archive' -File $RelPath -Issue "Tarball extraction error: $_" `
            -TestID 'MTS-EXTRACT-TAR-ERR' -Recommendation 'Verify the archive is a valid gzip tarball.'))
        & $clearPartialExtraction
        return @{ Success = $false; Findings = $findings.ToArray(); BudgetStopped = $false }
    } finally {
        if ($tarReader)  { $tarReader.Dispose() }
        if ($gzipStream) { $gzipStream.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
    }

    if ($symlinkCount -gt 0) {
        $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' -Severity 'MEDIUM' -Confidence 'MEDIUM' `
            -UnitType 'archive' -File $RelPath -Issue "Tarball contains $symlinkCount symlink/hardlink entry/entries (not extracted)." `
            -TestID 'MTS-EXTRACT-SYMLINK' -Recommendation 'Review — symlinks in archives can redirect writes/reads outside the tree.'))
    }
    if ($nestedNames.Count -gt 0) {
        $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' -Severity 'LOW' -Confidence 'MEDIUM' `
            -UnitType 'archive' -File $RelPath `
            -Issue "Tarball contains $($nestedNames.Count) nested archive(s): $(($nestedNames | Select-Object -First 3) -join ', ')" `
            -TestID 'MTS-EXTRACT-NESTED' `
            -Recommendation 'Nested archives are a common bomb/evasion vector — review the recursively-scanned findings for these members.'))
    }
    if ($budgetStopped) {
        $skippedNote = if ($budgetSkippedNames.Count -gt 0) {
            $sample = ($budgetSkippedNames | Select-Object -First 10) -join ', '
            $more   = if ($budgetSkippedNames.Count -gt 10) { " and $($budgetSkippedNames.Count - 10) more" } else { '' }
            " ({0} entries skipped: {1}{2})" -f $budgetSkippedNames.Count, $sample, $more
        } else { '' }
        $findings.Add((New-Finding -Tool 'Engine' -Category 'archive-hazard' -Severity 'INFO' -Confidence 'HIGH' `
            -UnitType 'archive' -File $RelPath `
            -Issue "Tarball extraction stopped partway through — the shared archive-tree budget for this scan was reached.$skippedNote" `
            -TestID 'MTS-ARCHIVE-BUDGET-EXCEEDED' `
            -Recommendation 'Absence of findings past this point is absence of coverage, not evidence remaining content is safe.'))
    }
    return @{ Success = $true; Findings = $findings.ToArray(); BudgetStopped = $budgetStopped }
}

function Expand-SubmissionArchive {
    <#
        Extract one archive file into $OutputDir, with v0.8 hazard guards.
        $Budget (issue #31 review — optional, $null means unenforced) is the
        shared archive-tree budget from Engine.ps1; passed straight through to
        Expand-TarArchive, the only extraction path here where the archive's
        own uncompressed size can't be known before writing starts.
        Returns @{ Success; StagingPath; Findings }.
    #>
    param(
        [Parameter(Mandatory)][string]$InputFile,
        [Parameter(Mandatory)][string]$OutputDir,
        [PSCustomObject]$Budget = $null
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $relPath  = Split-Path $InputFile -Leaf
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $name  = (Split-Path $InputFile -Leaf).ToLowerInvariant()
    $ext   = [IO.Path]::GetExtension($InputFile).ToLowerInvariant()
    $isTar = $name.EndsWith('.tar.gz') -or $name.EndsWith('.tgz')
    $isZip = $ext -in @('.whl', '.egg', '.zip', '.nupkg')

    Write-Log -Level INFO -Message "Extracting: $relPath -> $OutputDir"

    try {
        if ($isZip) {
            # Inspect BEFORE extracting (zip-slip / bomb must be caught pre-write).
            try {
                $hazards = Test-ZipArchiveHazards -InputFile $InputFile -RelPath $relPath
            } catch [System.IO.InvalidDataException] {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                    -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' `
                    -File $relPath -Issue 'Archive appears corrupt or is not a valid ZIP.' `
                    -TestID 'MTS-EXTRACT-CORRUPT' `
                    -Recommendation 'Reject this archive — content cannot be inspected.'))
                return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
            }
            foreach ($f in $hazards.Findings) { $findings.Add($f) }

            # ZIP-family disambiguation (informational).
            $en = $hazards.EntryNames
            if     ($en -contains '[Content_Types].xml')                       { Write-Log -Level DEBUG -Message "ZIP: $name -> OOXML/Office" }
            elseif ($en -contains 'package/package.json')                      { Write-Log -Level DEBUG -Message "ZIP: $name -> npm package" }
            elseif (@($en | Where-Object { $_ -match '\.dist-info/' }).Count)  { Write-Log -Level DEBUG -Message "ZIP: $name -> Python wheel/egg" }
            else                                                               { Write-Log -Level DEBUG -Message "ZIP: $name -> plain ZIP" }

            # HARD block: never extract a traversal/bomb archive.
            if ($hazards.Block) {
                Write-Log -Level WARN -Message "Blocked extraction of $name (archive hazard)."
                return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
            }

        # Safe to extract. Use ZipFile directly under PS 7.
            [System.IO.Compression.ZipFile]::ExtractToDirectory($InputFile, $OutputDir, $true)
            Write-Log -Level DEBUG -Message "Extracted ZIP-family archive OK."
        }
        elseif ($isTar) {
            $tarResult = Expand-TarArchive -InputFile $InputFile -OutputDir $OutputDir -RelPath $relPath -Budget $Budget
            foreach ($f in $tarResult.Findings) { $findings.Add($f) }
            if (-not $tarResult.Success) {
                Write-Log -Level WARN -Message "Blocked/failed extraction of $name (tarball)."
                return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
            }
            if ($tarResult.BudgetStopped) {
                Write-Log -Level WARN -Message "Tarball extraction for $name stopped early — shared archive-tree budget reached."
            } else {
                Write-Log -Level DEBUG -Message "Extracted tarball OK."
            }
        }
        else {
            Write-Log -Level WARN -Message "Unrecognized archive type: $name — skipping extraction."
            return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
        }

        return @{ Success = $true; StagingPath = $OutputDir; Findings = $findings.ToArray() }

    } catch {
        Write-Log -Level ERROR -Message "Extraction failed for $name : $_"
        $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
            -Severity 'HIGH' -Confidence 'LOW' -UnitType 'archive' -File $relPath `
            -Issue "Extraction error: $_" -TestID 'MTS-EXTRACT-ERR'))
        return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
    }
}
