#Requires -Version 7.4
<#
    PickleOpcodeScan analyzer — static triage of ML/model files (PLAN §4 v0.7).

    Delegates to src/helpers/scan_pickle.py, which uses pickletools.genops to walk
    the pickle opcode stream WITHOUT executing it. CRITICAL invariant: a pickle is
    NEVER unpickled (unpickling runs arbitrary code). Flags GLOBAL/STACK_GLOBAL
    (arbitrary imports), REDUCE (the code-exec primitive), and dangerous modules
    (os/subprocess/builtins/...). Recognizes safe-by-design formats (safetensors,
    GGUF) and scans pickles embedded in PyTorch ZIP containers (.pt/.pth) — the
    helper opens those as a ZIP internally; .pt/.pth are never engine-extracted
    (not in Engine.ps1's Test-IsArchiveUnit list), so the unit's own file path is
    always passed straight through, whole.

    Tier: core. Runs on `model` units only. A model file inside a GENERIC archive
    is classified as its own 'model' unit by recursive archive-member dispatch
    (issue #31) and reaches this analyzer through the exact same path as a loose
    model file — this used to ALSO walk a generic archive's StagingPath itself
    (UnitTypes included 'archive'); removed, since that would now duplicate
    every finding member dispatch already produces for the same file. The full
    set of extensions routed to 'model' (.pkl/.pickle/.pt/.pth/.joblib/
    .safetensors/.gguf/.bin/.h5/.hdf5/.pb/.onnx/.npy/.npz) lives in
    Classify.ps1's ExtTypeMap — one classification decision shared by loose
    top-level files and archive members alike, not a separate list here that
    could silently drift out of sync with what New-Unit actually classifies.
#>
@{
    Name           = 'PickleOpcodeScan'
    Version        = '0.2.0'
    UnitTypes      = @('model')
    RequiredTools  = @()           # stdlib-only helper; needs Python, no pip package
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $targets = [System.Collections.Generic.List[string]]::new()
        $targets.Add($Unit.Path)

        # Resolve Python: provisioned venv first, else system Python.
        $pythonExe = if ($null -ne $Context.Venv) { $Context.Venv.Python } else { Find-Python }
        $helper    = if ($Context.HelperDir) { Join-Path $Context.HelperDir 'scan_pickle.py' } else { '' }

        if (-not $pythonExe -or -not $helper -or -not (Test-Path -LiteralPath $helper)) {
            return @(New-Finding -Tool 'PickleOpcodeScan' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'model' -File $Unit.RelativePath `
                -Issue "Pickle opcode triage skipped ($($targets.Count) model file(s)) — Python or helper unavailable." `
                -TestID 'MTS-PICKLE-UNAVAIL' `
                -Recommendation 'Provide a Python 3 interpreter (system or bundled venv) for model-file triage.')
        }

        $findings = [System.Collections.Generic.List[object]]::new()
        foreach ($binPath in $targets) {
            $rel = $Unit.RelativePath
            $tmpJson = Join-Path $env:TEMP "mts_pickle_$([IO.Path]::GetRandomFileName()).json"
            try {
                $r = Invoke-BoundedProcess -FilePath $pythonExe -Arguments @($helper, $binPath, $tmpJson) -TimeoutSeconds $Context.TimeoutSeconds
                if (-not $r.Started) {
                    $findings.Add((New-ToolBlockedFinding -Tool 'PickleOpcodeScan' -UnitType 'model' -File $rel -Reason $r.StartError))
                    continue
                }
                if ($r.TimedOut) {
                    Write-Log -Level WARN -Message "PickleOpcodeScan: helper timed out ($($Context.TimeoutSeconds)s) for $rel."
                    $findings.Add((New-TimeoutFinding -Tool 'PickleOpcodeScan' -UnitType 'model' -File $rel -TimeoutSeconds $Context.TimeoutSeconds))
                    continue
                }
                $exit = $r.ExitCode
                foreach ($line in (($r.StdOut + $r.StdErr) -split "`n")) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "scan_pickle: $s" } }
                if ($exit -ne 0 -or -not (Test-Path -LiteralPath $tmpJson)) {
                    Write-Log -Level WARN -Message "PickleOpcodeScan: helper exit $exit for $rel."
                    continue
                }
                $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                foreach ($f in @($raw.findings)) {
                    $cat = if ($f.PSObject.Properties['category'] -and $f.category) { $f.category } else { 'deserialization' }
                    $findings.Add((New-Finding -Tool 'PickleOpcodeScan' -Category $cat -Severity $f.severity `
                        -Confidence $f.confidence -UnitType 'model' -File $rel `
                        -Issue $f.issue -TestID $f.testId `
                        -Recommendation 'Pickle/model files can execute code on load — never unpickle an untrusted model; prefer safetensors.'))
                }
            } catch {
                Write-Log -Level WARN -Message "PickleOpcodeScan: error for $rel : $_"
                $findings.Add((New-Finding -Tool 'PickleOpcodeScan' -Category 'parser' -Severity 'LOW' `
                    -Confidence 'LOW' -UnitType 'model' -File $rel `
                    -Issue "Pickle triage error: $_" -TestID 'MTS-PICKLE-ERR'))
            } finally {
                Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Log -Level INFO -Message "PickleOpcodeScan: $($findings.Count) finding(s) across $($targets.Count) model file(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
