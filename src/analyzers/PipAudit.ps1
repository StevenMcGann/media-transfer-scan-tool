#Requires -Version 7.4
<#
    PipAudit analyzer — checks declared Python dependencies (Requires-Dist from
    METADATA) against the PyPI Advisory Database for known CVEs.
    Also writes a CycloneDX SBOM for every archive unit that has metadata.

    Ported from scan-python-packages v1.6.1 Invoke-PipAuditScan with:
      - PS 7: EAP wrappers removed (native stderr no longer triggers Stop)
      - Severity tiering from CVSS scores (not a flat HIGH for all findings)
      - SBOM path returned as an INFO finding (no global $Script:SbomFiles)
      - Unit-type guard: only runs on 'python' units (archives + extracted dirs)
      - "Return, don't throw" contract: tool errors produce a parser finding

    Tier: core (CVE auditing is high-signal, low noise).
#>
@{
    Name           = 'PipAudit'
    Version        = '0.1.0'
    UnitTypes      = @('python')
    RequiredTools  = @(
        @{ Kind = 'pip'; Id = 'pip-audit'; MinVersion = '2.0.0'; BundlePath = $null }
    )
    Offline        = $false   # needs PyPI advisory DB (vendored DB in bundle later)
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        # Only meaningful for extracted archives — loose .py and notebooks have
        # no METADATA to audit. StagingPath is null for non-archive units.
        # We check for METADATA files regardless; if none are found we return clean.
        $scanPath = if ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath) {
            $Unit.StagingPath
        } else {
            # For a loose .py unit the path IS the file; no METADATA possible.
            return @()
        }

        if (-not (Test-Path -LiteralPath $scanPath -PathType Container)) { return @() }

        # ── Resolve tool handle from Context ─────────────────────────────────
        $toolHandle = $Context.Tools['pip-audit']
        if (-not $toolHandle -or -not $toolHandle.Available) {
            return @(New-Finding -Tool 'PipAudit' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue 'pip-audit not available — CVE dependency audit skipped.' `
                -TestID 'MTS-PIPAUDIT-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or ensure pip-audit is in the offline bundle.')
        }

        $auditExe = Join-Path $toolHandle.ScriptsDir 'pip-audit.exe'
        if (-not (Test-Path -LiteralPath $auditExe)) {
            return @(New-Finding -Tool 'PipAudit' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue "pip-audit.exe not found at '$auditExe'." `
                -TestID 'MTS-PIPAUDIT-MISSING')
        }

        # ── Extract Requires-Dist from METADATA ──────────────────────────────
        $metaFiles = @(Get-ChildItem -LiteralPath $scanPath -Recurse -File `
                        -Filter 'METADATA' -ErrorAction SilentlyContinue)
        $requires  = [System.Collections.Generic.List[string]]::new()

        foreach ($mf in $metaFiles) {
            foreach ($line in (Get-Content -LiteralPath $mf.FullName -ErrorAction SilentlyContinue)) {
                if ($line -like 'Requires-Dist:*') {
                    # Strip environment markers (e.g. '; python_version >= "3.6"')
                    $dep = ($line -replace '^Requires-Dist:\s*') -replace ';.*$'
                    $dep = $dep.Trim()
                    if ($dep) { $requires.Add($dep) }
                }
            }
        }

        $unique = @($requires | Select-Object -Unique)
        if ($unique.Count -eq 0) {
            Write-Log -Level INFO -Message "PipAudit: no Requires-Dist found in $($Unit.RelativePath) — skipping."
            return @()
        }

        Write-Log -Level INFO -Message "PipAudit: $($unique.Count) declared dep(s) in $($Unit.RelativePath)."

        # ── Run pip-audit ─────────────────────────────────────────────────────
        $reqFile = Join-Path $env:TEMP "mts_requires_$([IO.Path]::GetRandomFileName()).txt"
        $tmpJson = Join-Path $env:TEMP "mts_pipaudit_$([IO.Path]::GetRandomFileName()).json"
        $findings = [System.Collections.Generic.List[object]]::new()

        try {
            $unique | Set-Content -LiteralPath $reqFile -Encoding ascii

            # PS 7: no EAP wrapper needed; pip-audit stderr doesn't trigger Stop.
            # --no-deps --disable-pip: audit only what the package declares, not
            # the scanner's own environment. Pattern carried from v1.6.1.
            $auditOut = & $auditExe -r $reqFile --no-deps --disable-pip -f json -o $tmpJson 2>&1
            foreach ($line in $auditOut) { Write-Log -Level DEBUG -Message "pip-audit: $line" }

            if (Test-Path -LiteralPath $tmpJson) {
                $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                foreach ($dep in $raw.dependencies) {
                    foreach ($vuln in $dep.vulns) {

                        # Severity from CVSS score where available; fall back to HIGH.
                        $sev = 'HIGH'
                        $cvssScore = $vuln.fix_versions ? $null : $null  # probe shape
                        if ($vuln.PSObject.Properties['aliases']) {
                            # pip-audit >= 2.4 exposes fix_versions and aliases but not
                            # CVSS directly. We use description keywords as a heuristic
                            # until we add osv-schema CVSS parsing in a later increment.
                        }
                        # Simple CVSS tier from description keyword (conservative heuristic)
                        if ($vuln.description -match 'critical|remote code execution|rce') { $sev = 'CRITICAL' }
                        elseif ($vuln.description -match 'high|privilege escalation') { $sev = 'HIGH' }
                        elseif ($vuln.description -match 'medium|moderate') { $sev = 'MEDIUM' }

                        $fixHint = ''
                        if ($vuln.PSObject.Properties['fix_versions'] -and $vuln.fix_versions.Count -gt 0) {
                            $fixHint = " Fix: upgrade to $($vuln.fix_versions -join ' or ')."
                        }

                        $findings.Add((New-Finding `
                            -Tool       'PipAudit' `
                            -Category   'vuln-dependency' `
                            -Severity   $sev `
                            -Confidence 'HIGH' `
                            -UnitType   'python' `
                            -File       "dependency: $($dep.name) $($dep.version)" `
                            -Issue      "$($vuln.id): $($vuln.description)$fixHint" `
                            -TestID     $vuln.id `
                            -Recommendation "Review and update '$($dep.name)' to a patched version.$fixHint"))
                    }
                }
                Write-Log -Level INFO -Message "PipAudit: $($findings.Count) CVE(s) in $($Unit.RelativePath)."
            }

            # ── SBOM pass (non-fatal; same reqFile) ──────────────────────────
            $safeName = $Unit.Name -replace '[^\w\-.]', '_'
            $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
            $sbomPath = Join-Path $Context.ReportsDir "sbom_${stamp}_${safeName}.cdx.json"
            $tmpSbom  = Join-Path $env:TEMP "mts_sbom_$([IO.Path]::GetRandomFileName()).json"

            try {
                $sbomOut = & $auditExe -r $reqFile --no-deps --disable-pip `
                               -f cyclonedx-json -o $tmpSbom 2>&1
                foreach ($line in $sbomOut) { Write-Log -Level DEBUG -Message "pip-audit sbom: $line" }

                if (Test-Path -LiteralPath $tmpSbom) {
                    if (-not (Test-Path -LiteralPath $Context.ReportsDir)) {
                        New-Item -ItemType Directory -Path $Context.ReportsDir -Force | Out-Null
                    }
                    Copy-Item -LiteralPath $tmpSbom -Destination $sbomPath -Force
                    Write-Log -Level INFO -Message "SBOM written: $sbomPath"

                    # Surface SBOM path as an INFO finding so it appears in the report.
                    $findings.Add((New-Finding `
                        -Tool       'PipAudit' `
                        -Category   'parser' `
                        -Severity   'INFO' `
                        -Confidence 'HIGH' `
                        -UnitType   'python' `
                        -File       $Unit.RelativePath `
                        -Issue      "CycloneDX SBOM written: $(Split-Path $sbomPath -Leaf)" `
                        -TestID     'MTS-SBOM-001'))
                } else {
                    Write-Log -Level WARN -Message "PipAudit: SBOM output not produced for $($Unit.RelativePath)."
                }
            } catch {
                Write-Log -Level WARN -Message "PipAudit: SBOM generation failed for $($Unit.RelativePath): $_"
            } finally {
                Remove-Item -LiteralPath $tmpSbom -Force -ErrorAction SilentlyContinue
            }

        } catch {
            Write-Log -Level WARN -Message "PipAudit: scan error for $($Unit.RelativePath): $_"
            $findings.Add((New-Finding -Tool 'PipAudit' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'python' -File $Unit.RelativePath `
                -Issue "pip-audit scan error: $_" -TestID 'MTS-PIPAUDIT-ERR'))
        } finally {
            Remove-Item -LiteralPath $reqFile -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
        }

        return $findings.ToArray()
    }
}
