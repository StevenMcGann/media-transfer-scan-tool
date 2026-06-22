#Requires -Version 7.4
<#
    OleVbaScan analyzer — static triage of Office documents (PLAN §4 v0.3).

    Delegates to src/helpers/scan_office.py: VBA macro presence + auto-exec /
    suspicious keywords (oletools), DDE/DDEAUTO fields, and remote-template
    injection. The document is parsed structurally — never opened in Office,
    never executed.

    Runs on `office` units (.docx/.docm/.xls(x/m)/.ppt(x)/.rtf, classified by the
    OOXML/OLE magic bytes). Office files are scanned in place (not extracted to
    staging). Uses the venv Python; the zip-based checks still work if oletools
    is unavailable (scan_office.py degrades and notes it).

    Tier: core (macro/DDE/template detection is targeted and high-signal).
#>
@{
    Name           = 'OleVbaScan'
    Version        = '0.1.0'
    UnitTypes      = @('office')
    RequiredTools  = @(@{ Kind = 'pip'; Id = 'oletools'; MinVersion = '0.60'; BundlePath = $null })
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        if (-not (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) { return @() }

        # Need a Python interpreter for the helper. Prefer the provisioned venv
        # (where oletools lives); the helper's zip checks work even without oletools.
        $pythonExe = if ($null -ne $Context.Venv) { $Context.Venv.Python } else { '' }
        $helper    = if ($Context.HelperDir) { Join-Path $Context.HelperDir 'scan_office.py' } else { '' }

        if (-not $pythonExe -or -not (Test-Path -LiteralPath $pythonExe) -or
            -not $helper -or -not (Test-Path -LiteralPath $helper)) {
            return @(New-Finding -Tool 'OleVbaScan' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'office' -File $Unit.RelativePath `
                -Issue 'Office macro triage skipped — Python helper or venv unavailable.' `
                -TestID 'MTS-OFFICE-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or vendor oletools in the offline bundle.')
        }

        $tmpJson  = Join-Path $env:TEMP "mts_office_$([IO.Path]::GetRandomFileName()).json"
        $findings = [System.Collections.Generic.List[object]]::new()
        try {
            $r = Invoke-BoundedProcess -FilePath $pythonExe -Arguments @($helper, $Unit.Path, $tmpJson) -TimeoutSeconds $Context.TimeoutSeconds
            if ($r.TimedOut) {
                Write-Log -Level WARN -Message "OleVbaScan: helper timed out ($($Context.TimeoutSeconds)s) for $($Unit.RelativePath)."
                return @(New-TimeoutFinding -Tool 'OleVbaScan' -UnitType 'office' -File $Unit.RelativePath -TimeoutSeconds $Context.TimeoutSeconds)
            }
            $exit = $r.ExitCode
            foreach ($line in (($r.StdOut + $r.StdErr) -split "`n")) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "scan_office: $s" } }

            if ($exit -ne 0 -or -not (Test-Path -LiteralPath $tmpJson)) {
                Write-Log -Level WARN -Message "OleVbaScan: helper exit $exit for $($Unit.RelativePath)."
                return @(New-Finding -Tool 'OleVbaScan' -Category 'parser' -Severity 'LOW' `
                    -Confidence 'LOW' -UnitType 'office' -File $Unit.RelativePath `
                    -Issue "Office triage produced no result (helper exit $exit)." -TestID 'MTS-OFFICE-ERR')
            }

            $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
            foreach ($f in @($raw.findings)) {
                $cat = if ($f.PSObject.Properties['category'] -and $f.category) { $f.category } else { 'macro' }
                $findings.Add((New-Finding -Tool 'OleVbaScan' -Category $cat -Severity $f.severity `
                    -Confidence $f.confidence -UnitType 'office' -File $Unit.RelativePath `
                    -Issue $f.issue -TestID $f.testId))
            }
            Write-Log -Level INFO -Message "OleVbaScan: $($findings.Count) finding(s) in $($Unit.RelativePath)."
        } catch {
            Write-Log -Level WARN -Message "OleVbaScan: error for $($Unit.RelativePath): $_"
            $findings.Add((New-Finding -Tool 'OleVbaScan' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'office' -File $Unit.RelativePath `
                -Issue "Office triage error: $_" -TestID 'MTS-OFFICE-ERR'))
        } finally {
            Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
        }
        return $findings.ToArray()
    }
}
