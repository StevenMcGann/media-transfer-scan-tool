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
    $scanRoot     = (Resolve-Path -LiteralPath $Path).Path
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

            Show-Status "Analyzing: $($unit.RelativePath) [$($unit.Type)]"

            # ── Dispatch to analyzers ─────────────────────────────────────────
            foreach ($analyzer in (Select-AnalyzersForUnit -Enabled $sel.Enabled -Unit $unit)) {
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
