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
      - tar: a `tar -tzf` listing is checked for path traversal before extraction;
        the Python tarfile fallback uses the secure `data` extraction filter.

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

function Resolve-TarExe {
    <#
        Resolve a tar executable, preferring Windows' built-in bsdtar (libarchive)
        at %SystemRoot%\System32\tar.exe. MSYS / Git-for-Windows GNU tar misreads a
        native path like 'D:\dir\file.tgz' as a remote host spec ('Cannot connect
        to D: resolve failed') because of the drive-letter colon, and silently
        produces an EMPTY extraction tree — a false negative for a scanner. bsdtar
        handles drive-letter paths natively and is what GitHub's windows-latest
        runner already uses. On non-Windows, falls back to the PATH 'tar' (GNU tar,
        no colon issue there). Returns the exe path, or $null if none is found.
    #>
    if ($IsWindows) {
        $bsd = Join-Path $env:SystemRoot 'System32\tar.exe'
        if (Test-Path -LiteralPath $bsd) { return $bsd }
    }
    $c = Get-Command 'tar' -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

function Expand-SubmissionArchive {
    <#
        Extract one archive file into $OutputDir, with v0.8 hazard guards.
        Returns @{ Success; StagingPath; Findings }.
    #>
    param(
        [Parameter(Mandatory)][string]$InputFile,
        [Parameter(Mandatory)][string]$OutputDir,
        [string]$FallbackPython = ''   # venv Python for tar fallback
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

            # Safe to extract. PS 7: ZipFile directly (PLAN §6).
            [System.IO.Compression.ZipFile]::ExtractToDirectory($InputFile, $OutputDir, $true)
            Write-Log -Level DEBUG -Message "Extracted ZIP-family archive OK."
        }
        elseif ($isTar) {
            $tarExe = Resolve-TarExe
            if ($tarExe) {
                Write-Log -Level DEBUG -Message "Using tar: $tarExe"
                # Pre-list and block path traversal before extracting (zip-slip for tar).
                $listing = & $tarExe -tzf $InputFile 2>$null
                $traversal = @($listing | Where-Object { $_ -match '\.\.[/\\]' -or $_ -match '^/' -or $_ -match '^[A-Za-z]:' })
                if ($traversal.Count -gt 0) {
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                        -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $relPath `
                        -Issue "Path-traversal entry/entries in tarball: $(($traversal | Select-Object -First 3) -join ', ')" `
                        -TestID 'MTS-EXTRACT-TRAVERSAL' `
                        -Recommendation 'Rejected — tarball tries to write outside the extraction directory.'))
                    return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                }
                $tarOut = & $tarExe -xzf $InputFile -C $OutputDir 2>&1
                foreach ($line in $tarOut) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "tar: $s" } }
                if ($LASTEXITCODE -ne 0) {
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                        -Severity 'HIGH' -Confidence 'MEDIUM' -UnitType 'archive' `
                        -File $relPath -Issue "tar exited $LASTEXITCODE — archive may be corrupt." `
                        -TestID 'MTS-EXTRACT-TAR-ERR' `
                        -Recommendation 'Verify the archive is a valid gzip tarball.'))
                    return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                }
                Write-Log -Level DEBUG -Message "Extracted tarball with system tar OK."
            } else {
                if (-not $FallbackPython) {
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                        -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' `
                        -File $relPath -Issue 'system tar not found and no Python fallback available.' `
                        -TestID 'MTS-EXTRACT-NO-TAR'))
                    return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                }
                Write-Log -Level WARN -Message "system tar not found; using Python tarfile fallback (secure 'data' filter)."
                # tarfile's 'data' filter (PEP 706) blocks path traversal, absolute
                # paths, and dangerous symlinks during extraction.
                $pyScript = @'
import sys, tarfile, os
infile, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
with tarfile.open(infile, 'r:*') as t:
    try:
        t.extractall(outdir, filter='data')
    except TypeError:
        t.extractall(outdir)  # Python < 3.12 has no filter kwarg
'@
                $tmpScript = Join-Path $env:TEMP "mts_tar_$([IO.Path]::GetRandomFileName()).py"
                Set-Content -LiteralPath $tmpScript -Value $pyScript -Encoding utf8
                try {
                    $pyOut = & $FallbackPython $tmpScript $InputFile $OutputDir 2>&1
                    foreach ($line in $pyOut) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "tarfile: $s" } }
                    if ($LASTEXITCODE -ne 0) {
                        $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                            -Severity 'HIGH' -Confidence 'MEDIUM' -UnitType 'archive' -File $relPath `
                            -Issue "Python tarfile extraction exited $LASTEXITCODE — archive may be corrupt or unsafe." `
                            -TestID 'MTS-EXTRACT-PYTAR-ERR'))
                        return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                    }
                    Write-Log -Level DEBUG -Message "Extracted tarball with Python tarfile OK."
                } finally {
                    Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
                }
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
