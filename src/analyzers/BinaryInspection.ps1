#Requires -Version 7.4
<#
    BinaryInspection analyzer — static triage of native binaries (.pyd, .so, .dll).

    Delegates to src/helpers/inspect_binary.py (ported from scan-python-packages
    v1.6.1) which uses pefile (PE) and pyelftools (ELF) to inspect:
      - format validity (catches a binary disguised under a native extension)
      - Authenticode signature presence (PE)
      - import table (flags injection/anti-analysis/network/credential APIs)
      - section entropy (flags packing/encryption)
      - stripped symbols (ELF)

    Runs on:
      - python units (walks the extracted StagingPath for embedded .pyd/.so/.dll)
      - native-binary units (a loose .dll/.so/.pyd dropped directly in the folder)

    PS 7: no EAP wrapper around the python invocation. All analysis is static —
    the helper parses headers, it never loads or executes the binary.

    Tier: core (targeted, low-noise — only fires on real native binaries).
#>
@{
    Name           = 'BinaryInspection'
    Version        = '0.1.0'
    UnitTypes      = @('python', 'native-binary')
    RequiredTools  = @(
        @{ Kind = 'pip'; Id = 'pefile';     MinVersion = '2023.2.7'; BundlePath = $null }
        @{ Kind = 'pip'; Id = 'pyelftools'; MinVersion = '0.29';     BundlePath = $null }
    )
    Offline        = $true   # no network; advisory DB not needed
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $nativeExts = @('.pyd', '.so', '.dll')

        # ── Collect target binaries ──────────────────────────────────────────
        $targets = [System.Collections.Generic.List[string]]::new()
        if ($Unit.Type -eq 'native-binary') {
            $targets.Add($Unit.Path)
        } elseif ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                  (Test-Path -LiteralPath $Unit.StagingPath -PathType Container)) {
            Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in $nativeExts } |
                ForEach-Object { $targets.Add($_.FullName) }
        }

        if ($targets.Count -eq 0) { return @() }   # no native binaries in this unit

        # ── Resolve venv Python + helper script ──────────────────────────────
        $pythonExe = if ($null -ne $Context.Venv) { $Context.Venv.Python } else { '' }
        $helper    = if ($Context.HelperDir) { Join-Path $Context.HelperDir 'inspect_binary.py' } else { '' }

        $pefileOk = $Context.Tools.ContainsKey('pefile')     -and $Context.Tools['pefile'].Available
        $elfOk    = $Context.Tools.ContainsKey('pyelftools') -and $Context.Tools['pyelftools'].Available

        if (-not $pythonExe -or -not (Test-Path -LiteralPath $pythonExe) -or
            -not $helper -or -not (Test-Path -LiteralPath $helper) -or
            (-not $pefileOk -and -not $elfOk)) {
            return @(New-Finding -Tool 'BinaryInspection' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType $Unit.Type -File $Unit.RelativePath `
                -Issue "Native binary triage skipped ($($targets.Count) binary/binaries not inspected) — pefile/pyelftools or helper unavailable." `
                -TestID 'MTS-BININSPECT-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or vendor pefile/pyelftools in the offline bundle.')
        }

        # ── Inspect each binary ───────────────────────────────────────────────
        $findings = [System.Collections.Generic.List[object]]::new()

        foreach ($binPath in $targets) {
            $relForReport = if ($Unit.Type -eq 'native-binary') {
                $Unit.RelativePath
            } else {
                # Show path relative to the staging root for readability.
                "$($Unit.RelativePath)!" + $binPath.Substring($Unit.StagingPath.Length).TrimStart('\', '/')
            }

            $tmpJson = Join-Path $env:TEMP "mts_binary_$([IO.Path]::GetRandomFileName()).json"
            try {
                $r = Invoke-BoundedProcess -FilePath $pythonExe -Arguments @($helper, $binPath, $tmpJson) -TimeoutSeconds $Context.TimeoutSeconds
                if ($r.TimedOut) {
                    Write-Log -Level WARN -Message "BinaryInspection: helper timed out ($($Context.TimeoutSeconds)s) for $binPath."
                    $findings.Add((New-TimeoutFinding -Tool 'BinaryInspection' -UnitType $Unit.Type -File $relForReport -TimeoutSeconds $Context.TimeoutSeconds))
                    continue
                }
                $exit = $r.ExitCode
                foreach ($line in (($r.StdOut + $r.StdErr) -split "`n")) {
                    $s = ([string]$line).Trim()
                    if ($s) { Write-Log -Level DEBUG -Message "binary-inspect: $s" }
                }

                if ($exit -ne 0) {
                    Write-Log -Level WARN -Message "BinaryInspection: helper exited $exit for $binPath."
                    continue
                }
                if (-not (Test-Path -LiteralPath $tmpJson)) {
                    Write-Log -Level WARN -Message "BinaryInspection: no output for $binPath."
                    continue
                }

                $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                foreach ($f in @($raw.findings)) {
                    $findings.Add((New-Finding `
                        -Tool       'BinaryInspection' `
                        -Category   'native-binary' `
                        -Severity   $f.severity `
                        -Confidence $f.confidence `
                        -UnitType   $Unit.Type `
                        -File       $relForReport `
                        -Issue      $f.issue `
                        -TestID     $f.testId))
                }
            } catch {
                Write-Log -Level WARN -Message "BinaryInspection: error for $binPath : $_"
                $findings.Add((New-Finding -Tool 'BinaryInspection' -Category 'parser' -Severity 'LOW' `
                    -Confidence 'LOW' -UnitType $Unit.Type -File $relForReport `
                    -Issue "Binary inspection error: $_" -TestID 'MTS-BININSPECT-ERR'))
            } finally {
                Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
            }
        }

        Write-Log -Level INFO -Message "BinaryInspection: $($findings.Count) finding(s) across $($targets.Count) binary/binaries in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
