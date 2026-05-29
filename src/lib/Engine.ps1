#Requires -Version 7.4
<#
    Engine.ps1 - the pipeline (PLAN §3.1): discover -> classify -> dispatch -> aggregate.
    Returns a result object that the renderers (Report.ps1) consume.
#>

function New-AnalyzerContext {
    param(
        [string]$Mode,
        [string]$WorkDir,
        [string]$ReportsDir,
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

function Invoke-Scan {
    <#
        Run the full pipeline against a folder. Pure orchestration; no rendering.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('core', 'full')][string]$Profile = 'core',
        [string[]]$EnableAnalyzers = @(),
        [string[]]$DisableAnalyzers = @(),
        [string]$Mode = 'online',
        [string]$AnalyzerDir,
        [string]$ReportsDir,
        [PSCustomObject]$ProvisionResult = $null
    )

    $startTime = Get-Date
    $scanRoot  = (Resolve-Path -LiteralPath $Path).Path

    Write-Log -Message "Importing analyzer registry from: $AnalyzerDir"
    $registry = Import-AnalyzerRegistry -AnalyzerDir $AnalyzerDir
    $sel      = Resolve-EnabledAnalyzers -Registry $registry -Profile $Profile `
                    -EnableAnalyzers $EnableAnalyzers -DisableAnalyzers $DisableAnalyzers
    Write-Log -Message ("Profile '{0}': {1} analyzer(s) enabled, {2} disabled." -f `
        $Profile, $sel.Enabled.Count, $sel.DisabledNames.Count)

    $context = New-AnalyzerContext -Mode $Mode -WorkDir $env:TEMP -ReportsDir $ReportsDir `
                   -ProvisionResult $ProvisionResult

    $unitResults = [System.Collections.Generic.List[object]]::new()

    foreach ($file in Get-DiscoveredFiles -ScanRoot $scanRoot) {
        $classified = New-Unit -File $file -ScanRoot $scanRoot
        $unit       = $classified.Unit
        $findings   = [System.Collections.Generic.List[object]]::new()
        foreach ($f in $classified.Findings) { $findings.Add($f) }

        Show-Status "Analyzing: $($unit.RelativePath) [$($unit.Type)]"

        foreach ($analyzer in (Select-AnalyzersForUnit -Enabled $sel.Enabled -Unit $unit)) {
            try {
                # Return, don't throw (PLAN §3.2 rule 2): a broken analyzer degrades
                # coverage via an analyzer-error finding, it never aborts the run.
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
