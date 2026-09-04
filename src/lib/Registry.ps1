#Requires -Version 7.4
<#
    Registry.ps1 - analyzer registry. Imports self-describing
    descriptors from src/analyzers/*.ps1 and selects them per unit + profile.
#>

function Import-AnalyzerRegistry {
    <#
        Dot-source each analyzer file; each emits one descriptor hashtable.
        Returns the descriptor array.
    #>
    param([string]$AnalyzerDir)

    $registry = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $AnalyzerDir -Filter '*.ps1' -File | Sort-Object Name) {
        try {
            $desc = & $file.FullName
            if ($null -eq $desc) { continue }
            foreach ($req in @('Name', 'UnitTypes', 'Invoke')) {
                if (-not $desc.ContainsKey($req)) { throw "analyzer '$($file.Name)' descriptor missing required key '$req'" }
            }
            # Apply contract defaults.
            if (-not $desc.ContainsKey('Tier'))           { $desc.Tier = 'core' }
            if (-not $desc.ContainsKey('DefaultEnabled'))  { $desc.DefaultEnabled = ($desc.Tier -eq 'core') }
            if (-not $desc.ContainsKey('Version'))         { $desc.Version = '0.0.0' }
            if (-not $desc.ContainsKey('RequiredTools'))   { $desc.RequiredTools = @() }
            if (-not $desc.ContainsKey('Offline'))         { $desc.Offline = $true }
            if (-not $desc.ContainsKey('UnitTypeExtensions')) { $desc.UnitTypeExtensions = @{} }
            if ($desc.UnitTypeExtensions -isnot [Collections.IDictionary]) { throw "analyzer '$($file.Name)' UnitTypeExtensions must be a dictionary" }
            $registry.Add([PSCustomObject]$desc)
            Write-Log -Level DEBUG -Message "Registered analyzer: $($desc.Name) [tier=$($desc.Tier), default=$($desc.DefaultEnabled)]"
        } catch {
            Write-Log -Level ERROR -Message "Failed to load analyzer '$($file.Name)': $_"
        }
    }
    return $registry.ToArray()
}

function Resolve-EnabledAnalyzers {
    <#
        Decide which analyzers are enabled for this run, independent of unit type.
        Profile sets the baseline; explicit Enable/Disable lists override by name.
        Returns @{ Enabled = <descriptor[]>; DisabledNames = <string[]> }.
    #>
    param(
        [object[]]$Registry,
        [ValidateSet('core', 'full')][string]$Profile = 'core',
        [string[]]$EnableAnalyzers = @(),
        [string[]]$DisableAnalyzers = @()
    )
    $enabled = [System.Collections.Generic.List[object]]::new()
    $disabledNames = [System.Collections.Generic.List[string]]::new()

    foreach ($a in $Registry) {
        # Baseline from profile: 'full' enables every tier; 'core' enables core-tier only.
        $on = ($Profile -eq 'full') -or $a.DefaultEnabled
        if ($a.Name -in $EnableAnalyzers)  { $on = $true }
        if ($a.Name -in $DisableAnalyzers) { $on = $false }
        if ($on) { $enabled.Add($a) } else { $disabledNames.Add($a.Name) }
    }
    return @{ Enabled = $enabled.ToArray(); DisabledNames = $disabledNames.ToArray() }
}

function Select-AnalyzersForUnit {
    param([object[]]$Enabled, [PSCustomObject]$Unit)
    return @($Enabled | Where-Object {
        if ($_.UnitTypes -notcontains $Unit.Type -and $_.UnitTypes -notcontains 'any') { return $false }
        # Optional restrictions narrow one shared unit type without adding a
        # public type or claiming coverage for variants the analyzer ignores.
        $hasRestrictions = if ($_ -is [Collections.IDictionary]) { $_.Contains('UnitTypeExtensions') }
                           else { [bool]$_.PSObject.Properties['UnitTypeExtensions'] }
        if ($hasRestrictions -and $_.UnitTypeExtensions.Contains($Unit.Type)) {
            $name = if ($Unit.PSObject.Properties['Name']) { $Unit.Name } else { '' }
            return [IO.Path]::GetExtension($name) -in @($_.UnitTypeExtensions[$Unit.Type])
        }
        return $true
    })
}
