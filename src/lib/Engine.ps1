#Requires -Version 7.4
<#
    Engine.ps1 - the pipeline (PLAN §3.1): discover -> classify -> extract -> dispatch -> aggregate.
    Returns a result object that the renderers (Report.ps1) consume.
#>

# Archive extensions that need extraction before scanning.
$script:ArchiveExtensions = @('.whl', '.egg', '.zip', '.tgz', '.tar.gz')

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
    return $ext -in @('.whl', '.egg', '.zip')
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

    $unitResults = [System.Collections.Generic.List[object]]::new()

    try {
        New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null

        foreach ($file in Get-DiscoveredFiles -ScanRoot $scanRoot) {
            $classified = New-Unit -File $file -ScanRoot $scanRoot
            $unit       = $classified.Unit
            $findings   = [System.Collections.Generic.List[object]]::new()
            foreach ($f in $classified.Findings) { $findings.Add($f) }

            # ── Archive extraction ────────────────────────────────────────────
            if (Test-IsArchiveUnit -Unit $unit) {
                $safeName  = $unit.Name -replace '[^\w\-.]', '_'
                $stageDir  = Join-Path $stagingRoot "unit_$safeName"
                $fallback  = if ($null -ne $context.Venv) { $context.Venv.Python } else { '' }

                $extraction = Expand-SubmissionArchive `
                    -InputFile     $unit.Path `
                    -OutputDir     $stageDir `
                    -FallbackPython $fallback

                foreach ($f in $extraction.Findings) { $findings.Add($f) }

                if ($extraction.Success) {
                    $unit.StagingPath = $extraction.StagingPath
                    Write-Log -Level DEBUG -Message "StagingPath set: $($unit.StagingPath)"
                } else {
                    Write-Log -Level WARN -Message "Extraction failed for $($unit.Name) — analyzers requiring staging will skip."
                }
            }
            # ── Notebook projection ───────────────────────────────────────────
            # Like extraction, this is a pre-dispatch transform: it emits structural
            # NotebookParser findings (always, core behavior) and points downstream
            # analyzers (Bandit/detect-secrets, deep tier) at the projected .py.
            elseif (Test-IsNotebookUnit -Unit $unit) {
                $safeName = $unit.Name -replace '[^\w\-.]', '_'
                $projDir  = Join-Path $stagingRoot "nb_$safeName"
                $proj = Convert-NotebookToPythonSource `
                    -NotebookPath $unit.Path -OutputRoot $projDir `
                    -OutputName "$safeName.py" -RelPath $unit.RelativePath
                foreach ($f in $proj.Findings) { $findings.Add($f) }
                if ($proj.Success) {
                    $unit.StagingPath = $projDir   # code-cell projection; scanners read this
                    Write-Log -Level DEBUG -Message "Notebook projection dir: $projDir"
                }
            }

            Show-Status "Analyzing: $($unit.RelativePath) [$($unit.Type)]"

            # ── Dispatch to analyzers ─────────────────────────────────────────
            $selected = @(Select-AnalyzersForUnit -Enabled $sel.Enabled -Unit $unit)

            # No silent coverage gaps: if nothing but the type-agnostic analyzers
            # (FileHash and friends, UnitTypes = 'any') claimed this unit, the file
            # was hashed and listed but never actually understood. Say so, at INFO,
            # rather than letting it read as "reviewed and clean". Fires for
            # 'unsupported' units and for any type with no enabled analyzer.
            $typeClaimed = @($selected | Where-Object { $_.UnitTypes -notcontains 'any' })

            # Claiming a type in a descriptor is not the same as inspecting the
            # content. For an `archive` unit both NpmScan and PickleOpcodeScan claim
            # 'archive', which would suppress the gap notice below — but NpmScan
            # returns immediately without a package.json and PickleOpcodeScan without
            # model files, so a ZIP full of shell scripts came out hashed, unscanned
            # and unremarked. Judge extracted content on its own types: one is covered
            # only when an enabled analyzer claims BOTH that type and 'archive'.
            # 'unsupported' is excluded — a readme inside a zip is not a coverage gap
            # worth a line, whereas an unscanned .ps1 is.
            $uncoveredInside = @()
            if ($unit.StagingPath -and (Test-Path -LiteralPath $unit.StagingPath -PathType Container)) {
                $insideTypes = @(Get-ChildItem -LiteralPath $unit.StagingPath -Recurse -File -ErrorAction SilentlyContinue |
                    ForEach-Object { $t = Get-DeclaredType -File $_; if ($t) { $t } } |
                    Sort-Object -Unique)
                foreach ($t in $insideTypes) {
                    if (-not @($sel.Enabled | Where-Object {
                            $_.UnitTypes -contains $t -and $_.UnitTypes -contains 'archive' })) {
                        $uncoveredInside += $t
                    }
                }
            }

            if (-not $typeClaimed) {
                $findings.Add((New-Finding -Tool 'Engine' -Category 'parser' -Severity 'INFO' `
                    -Confidence 'HIGH' -UnitType $unit.Type -File $unit.RelativePath `
                    -Issue ("No analyzer covers unit type '{0}' — file was hashed and listed but not inspected." -f $unit.Type) `
                    -TestID 'MTS-NO-ANALYZER' `
                    -Recommendation 'Absence of findings here is absence of coverage, not evidence the file is safe.'))
            }
            elseif ($uncoveredInside.Count -gt 0) {
                $findings.Add((New-Finding -Tool 'Engine' -Category 'parser' -Severity 'INFO' `
                    -Confidence 'HIGH' -UnitType $unit.Type -File $unit.RelativePath `
                    -Issue ("Extracted content of type(s) '{0}' was NOT inspected — no enabled analyzer covers those types inside an archive." -f ($uncoveredInside -join ', ')) `
                    -TestID 'MTS-NO-ANALYZER' `
                    -Recommendation 'The archive itself was hazard-checked, but this content was not analyzed. Extract to a folder and re-scan it directly before trusting a clean result.'))
            }

            foreach ($analyzer in $selected) {
                try {
                    # Return, don't throw (PLAN §3.2 rule 2)
                    $out = & $analyzer.Invoke $unit $context
                    foreach ($f in @($out)) { if ($f) { $findings.Add($f) } }
                } catch {
                    $findings.Add((New-Finding -Tool $analyzer.Name -Category 'parser' -Severity 'LOW' `
                        -Confidence 'LOW' -UnitType $unit.Type -File $unit.RelativePath `
                        -Issue "Analyzer '$($analyzer.Name)' errored: $_" -TestID 'MTS-ANALYZER-ERR'))
                    Write-Log -Level ERROR -Message "Analyzer '$($analyzer.Name)' failed on $($unit.RelativePath): $_"
                }
            }

            $unitResults.Add([PSCustomObject]@{
                Name     = $unit.Name
                Type     = $unit.Type
                Path     = $unit.RelativePath
                Findings = $findings.ToArray()
            })
        }
    } finally {
        # Always clean up staging — holds extracted submission content
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
