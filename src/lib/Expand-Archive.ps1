#Requires -Version 7.4
<#
    Expand-Archive.ps1 - extract Python package archives into a staging directory.

    Ported from scan-python-packages v1.6.1 Expand-PythonArchive with:
      - PS 7: [System.IO.Compression.ZipFile] used directly for ZIP-family
        archives (.whl, .egg, .zip) — no temp-copy-to-.zip workaround needed
        (that workaround existed solely for PS 5.1's Expand-Archive restriction)
      - PS 7: no EAP wrapper around tar (native stderr no longer triggers Stop)
      - Zip-family disambiguation: after extraction, peek at entries to detect
        OOXML (.docx etc.) vs Python wheel/egg vs plain ZIP — logged for now;
        full routing to office/npm analyzers arrives in v0.3/v0.6
      - Archive-hazard guards (PLAN §4 v0.8): path-traversal and size cap stubs
        that log warnings and will be enforcement-hardened in v0.8.0

    Returns a PSCustomObject { Success; StagingPath; Findings }
    Findings carry any archive-hazard parser findings. On failure, Success=$false
    and StagingPath is the partially-extracted directory (may be empty).
#>

Set-StrictMode -Version Latest

# Maximum uncompressed bytes we'll extract (256 MB); prevents decompression bombs.
# Will become a hard abort in v0.8.0 archive hardening.
$script:MaxExtractedBytes = 256MB

function Expand-SubmissionArchive {
    <#
        Extract one archive file into $OutputDir.
        Returns @{ Success; StagingPath; Findings }
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
    $isZip = $ext -in @('.whl', '.egg', '.zip')

    Write-Log -Level INFO -Message "Extracting: $(Split-Path $InputFile -Leaf) -> $OutputDir"

    try {
        if ($isZip) {
            # ── Pre-extraction inspection (PLAN §3.7 disambiguation + path-traversal)
            # Must happen BEFORE ExtractToDirectory because .NET 6+ throws IOException
            # on traversal entries during extraction — we need to flag them first.
            $entryNames = @()
            try {
                $zip = [System.IO.Compression.ZipFile]::OpenRead($InputFile)
                try { $entryNames = @($zip.Entries | ForEach-Object { $_.FullName }) }
                finally { $zip.Dispose() }
            } catch [System.IO.InvalidDataException] {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                    -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' `
                    -File $relPath -Issue 'Archive appears corrupt or is not a valid ZIP.' `
                    -TestID 'MTS-EXTRACT-CORRUPT' `
                    -Recommendation 'Reject this archive — content cannot be inspected.'))
                return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
            }

            # ZIP-family disambiguation
            $isOoxml = $entryNames -contains '[Content_Types].xml'
            $isWheel = @($entryNames | Where-Object { $_ -match '\.dist-info/' }).Count -gt 0
            $isNpm   = $entryNames -contains 'package/package.json'
            if ($isOoxml)       { Write-Log -Level DEBUG -Message "ZIP disambiguation: $name → OOXML/Office (routes to office analyzer in v0.3)" }
            elseif ($isNpm)     { Write-Log -Level DEBUG -Message "ZIP disambiguation: $name → npm package (routes to npm analyzer in v0.6)" }
            elseif ($isWheel)   { Write-Log -Level DEBUG -Message "ZIP disambiguation: $name → Python wheel/egg ✓" }
            else                { Write-Log -Level DEBUG -Message "ZIP disambiguation: $name → plain ZIP archive" }

            # Path-traversal guard — flag before extracting (v0.8.0 will make this a hard abort)
            $traversal = @($entryNames | Where-Object {
                $_ -match '\.\.[/\\]' -or [IO.Path]::IsPathRooted($_) -or $_.StartsWith('/')
            })
            if ($traversal.Count -gt 0) {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'archive-hazard' `
                    -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' -File $relPath `
                    -Issue "Archive contains $($traversal.Count) path-traversal entry/entries: $(($traversal | Select-Object -First 3) -join ', ')" `
                    -TestID 'MTS-EXTRACT-TRAVERSAL' `
                    -Recommendation 'Reject this archive — it may attempt to write files outside the extraction directory.'))
                Write-Log -Level WARN -Message "Path-traversal entries detected in $name — extraction will be attempted (hard block in v0.8.0)"
            }

            # ── Extract ────────────────────────────────────────────────────
            # PS 7: use ZipFile directly — no temp-copy-to-.zip workaround (PLAN §6)
            try {
                [System.IO.Compression.ZipFile]::ExtractToDirectory($InputFile, $OutputDir, $true)
            } catch [System.IO.InvalidDataException] {
                $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                    -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' `
                    -File $relPath -Issue 'Archive appears corrupt or is not a valid ZIP.' `
                    -TestID 'MTS-EXTRACT-CORRUPT' `
                    -Recommendation 'Reject this archive — content cannot be inspected.'))
                return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
            } catch [System.IO.IOException] {
                # .NET 6+ throws IOException on path-traversal entries during extraction.
                # We already flagged this above; mark extraction as failed.
                if ($traversal.Count -gt 0) {
                    return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                }
                throw   # unexpected IOException — re-raise
            }

            Write-Log -Level DEBUG -Message "Extracted ZIP-family archive OK."
        }
        elseif ($isTar) {
            $tarCmd = Get-Command 'tar' -ErrorAction SilentlyContinue
            if ($tarCmd) {
                # PS 7: no EAP wrapper needed (PLAN §6 retire)
                $tarOut = & tar -xzf $InputFile -C $OutputDir 2>&1
                foreach ($line in $tarOut) {
                    $s = ([string]$line).Trim()
                    if ($s) { Write-Log -Level DEBUG -Message "tar: $s" }
                }
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
                # Fallback: Python tarfile module (always available in any venv)
                if (-not $FallbackPython) {
                    $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                        -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'archive' `
                        -File $relPath -Issue "system tar not found and no Python fallback available." `
                        -TestID 'MTS-EXTRACT-NO-TAR'))
                    return @{ Success = $false; StagingPath = $OutputDir; Findings = $findings.ToArray() }
                }

                Write-Log -Level WARN -Message "system tar not found; using Python tarfile fallback."
                $pyScript = @'
import sys, tarfile, os
infile, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
with tarfile.open(infile, 'r:*') as t:
    t.extractall(outdir)
'@
                $tmpScript = Join-Path $env:TEMP "mts_tar_$([IO.Path]::GetRandomFileName()).py"
                Set-Content -LiteralPath $tmpScript -Value $pyScript -Encoding utf8
                try {
                    $pyOut = & $FallbackPython $tmpScript $InputFile $OutputDir 2>&1
                    foreach ($line in $pyOut) {
                        $s = ([string]$line).Trim()
                        if ($s) { Write-Log -Level DEBUG -Message "tarfile: $s" }
                    }
                    if ($LASTEXITCODE -ne 0) {
                        $findings.Add((New-Finding -Tool 'Extractor' -Category 'parser' `
                            -Severity 'HIGH' -Confidence 'MEDIUM' -UnitType 'archive' `
                            -File $relPath `
                            -Issue "Python tarfile extraction exited $LASTEXITCODE — archive may be corrupt." `
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
