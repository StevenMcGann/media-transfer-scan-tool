#Requires -Version 7.4
<#
    Bandit analyzer — static analysis of Python source for risky code patterns
    (eval/exec, pickle, subprocess shell, weak crypto, insecure network, etc.).

    Ported from scan-python-packages v1.6.1 Invoke-BanditScan.
    Scans the extracted StagingPath for archive units, or the file itself for
    loose .py units. PS 7: no EAP wrapper. All analysis is static.

    Tier: deep (opt-in, default-off) — Bandit's broad pattern matching is noisy
    on routine ingress. Enable with -Profile full or -EnableAnalyzers Bandit.
#>
@{
    Name           = 'Bandit'
    Version        = '0.1.0'
    UnitTypes      = @('python')
    RequiredTools  = @(@{ Kind = 'pip'; Id = 'bandit'; MinVersion = '1.7.0'; BundlePath = $null })
    Offline        = $true
    Tier           = 'deep'
    DefaultEnabled = $false
    Invoke         = {
        param($Unit, $Context)

        # Determine scan target: extracted dir for archives, file for loose .py
        $target = if ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath) {
            $Unit.StagingPath
        } else {
            $Unit.Path
        }
        if (-not $target -or -not (Test-Path -LiteralPath $target)) { return @() }

        $tool = $Context.Tools['bandit']
        if (-not $tool -or -not $tool.Available) {
            return @(New-Finding -Tool 'Bandit' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue 'Bandit not available — risky-code scan skipped.' `
                -TestID 'MTS-BANDIT-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or vendor bandit in the offline bundle.')
        }
        $banditExe = Join-Path $tool.ScriptsDir 'bandit.exe'
        if (-not (Test-Path -LiteralPath $banditExe)) {
            return @(New-Finding -Tool 'Bandit' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue "bandit.exe not found at '$banditExe'." -TestID 'MTS-BANDIT-MISSING')
        }

        $tmpJson  = Join-Path $env:TEMP "mts_bandit_$([IO.Path]::GetRandomFileName()).json"
        $findings = [System.Collections.Generic.List[object]]::new()
        try {
            # -ll : report MEDIUM and HIGH severity only (cuts low-value noise)
            $r = Invoke-BoundedProcess -FilePath $banditExe -Arguments @('-r', $target, '-ll', '-f', 'json', '-o', $tmpJson) -TimeoutSeconds $Context.TimeoutSeconds
            if ($r.TimedOut) {
                Write-Log -Level WARN -Message "Bandit: timed out ($($Context.TimeoutSeconds)s) for $($Unit.RelativePath)."
                return @(New-TimeoutFinding -Tool 'Bandit' -UnitType 'python' -File $Unit.RelativePath -TimeoutSeconds $Context.TimeoutSeconds)
            }
            foreach ($line in (($r.StdOut + $r.StdErr) -split "`n")) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "bandit: $s" } }

            if (Test-Path -LiteralPath $tmpJson) {
                $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                foreach ($r in @($raw.results)) {
                    # Make the reported file path readable relative to the unit.
                    $relFile = $r.filename
                    if ($Unit.StagingPath -and $relFile.StartsWith($Unit.StagingPath)) {
                        $relFile = "$($Unit.RelativePath)!" + $relFile.Substring($Unit.StagingPath.Length).TrimStart('\','/')
                    }
                    $findings.Add((New-Finding `
                        -Tool       'Bandit' `
                        -Category   'risky-code' `
                        -Severity   $r.issue_severity `
                        -Confidence $r.issue_confidence `
                        -UnitType   'python' `
                        -File       $relFile `
                        -Line       ([int]$r.line_number) `
                        -Issue      $r.issue_text `
                        -TestID     $r.test_id))
                }
                Write-Log -Level INFO -Message "Bandit: $($findings.Count) finding(s) in $($Unit.RelativePath)."
            }
        } catch {
            Write-Log -Level WARN -Message "Bandit: scan error for $($Unit.RelativePath): $_"
            $findings.Add((New-Finding -Tool 'Bandit' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'python' -File $Unit.RelativePath `
                -Issue "Bandit scan error: $_" -TestID 'MTS-BANDIT-ERR'))
        } finally {
            Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
        }
        return $findings.ToArray()
    }
}
