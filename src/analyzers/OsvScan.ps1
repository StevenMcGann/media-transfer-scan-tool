#Requires -Version 7.4
<#
    OsvScan analyzer - exact dependency and packaged-component lookups against
    OSV.dev. Parsing lives in lib/DependencyMetadata.ps1 so ordinary files,
    extracted semantic containers, and issue #39's metadata-only fallback use
    one interpretation of every supported manifest.

    Direct/extracted wheels query their own Name/Version here. Their
    Requires-Dist dependencies remain PipAudit's responsibility on the normal
    extraction path, avoiding duplicate findings; the metadata-only fallback
    queries both identity and exact Requires-Dist records because PipAudit
    cannot operate without a staging tree.
    Eggs retain their exact dependencies here because PipAudit only consumes
    wheel METADATA, not the canonical egg PKG-INFO file.
#>
@{
    Name           = 'OsvScan'
    Version        = '0.3.0'
    UnitTypes      = @('python-requirements', 'npm', 'nuget', 'python')
    # Package-identity lookups do not inspect loose Python source/notebooks.
    # Selection must know this before the engine computes analyzer coverage.
    UnitTypeExtensions = @{ python = @('.whl', '.egg') }
    RequiredTools  = @()
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $findings = [Collections.Generic.List[object]]::new()
        $parsed = $null
        $manifestRel = $Unit.RelativePath

        function Read-ManifestBytes([string]$Path, [string]$Rel, [string]$Kind, [string]$UnitType) {
            try {
                $info = Get-Item -LiteralPath $Path -ErrorAction Stop
                if ($info.Length -gt 1MB) {
                    return [PSCustomObject]@{ Dependencies=@(); Findings=@(
                        New-DependencyParseFinding -File $Rel -UnitType $UnitType -Severity INFO -Confidence HIGH `
                            -Issue "Dependency manifest exceeds the 1 MiB parser limit ($($info.Length) bytes)." `
                            -TestID 'MTS-ARCHIVE-METADATA-LIMIT') }
                }
                $bytes = [IO.File]::ReadAllBytes($Path)
                return Convert-DependencyMetadataContent -Kind $Kind -Bytes $bytes -ManifestFile $Rel -UnitType $UnitType
            } catch {
                return [PSCustomObject]@{ Dependencies=@(); Findings=@(
                    New-DependencyParseFinding -File $Rel -UnitType $UnitType `
                        -Issue "Dependency manifest could not be read: $_" -TestID 'MTS-ARCHIVE-METADATA-ERROR') }
            }
        }

        switch ($Unit.Type) {
            'python-requirements' {
                if (-not (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) { return @() }
                $kind = Get-DependencyMetadataKind -EntryName $Unit.Path
                if (-not $kind) { return @() }
                $parsed = Read-ManifestBytes $Unit.Path $Unit.RelativePath $kind 'python-requirements'
            }
            'npm' {
                if (-not (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) { return @() }
                $kind = Get-DependencyMetadataKind -EntryName $Unit.Name
                if ($kind -ne 'npm-lock') { return @() }
                $parsed = Read-ManifestBytes $Unit.Path $Unit.RelativePath $kind 'npm'
            }
            'nuget' {
                if ($Unit.Name.ToLowerInvariant().EndsWith('.nuspec') -and (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) {
                    $parsed = Read-ManifestBytes $Unit.Path $Unit.RelativePath 'nuspec' 'nuget'
                } elseif ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                          (Test-Path -LiteralPath $Unit.StagingPath -PathType Container)) {
                    $rootNuspecs = @(Get-ChildItem -LiteralPath $Unit.StagingPath -File -Filter '*.nuspec' -ErrorAction SilentlyContinue)
                    if ($rootNuspecs.Count -gt 1) {
                        $names = ($rootNuspecs | ForEach-Object { $_.Name }) -join ', '
                        return @(New-DependencyParseFinding -File $Unit.RelativePath -UnitType nuget -Severity MEDIUM -Confidence HIGH `
                            -Issue "Package has $($rootNuspecs.Count) root .nuspec files ($names) - ambiguous identity, cannot identify the package for an OSV lookup." `
                            -TestID 'OSV-NUGET-AMBIGUOUS-NUSPEC')
                    }
                    $nuspec = $rootNuspecs | Select-Object -First 1
                    if (-not $nuspec) {
                        return @(New-DependencyParseFinding -File $Unit.RelativePath -UnitType nuget `
                            -Issue 'No root .nuspec found in the extracted package - cannot identify it for an OSV lookup.' `
                            -TestID 'OSV-NUGET-NO-NUSPEC')
                    }
                    $parsed = Read-ManifestBytes $nuspec.FullName $Unit.RelativePath 'nuspec' 'nuget'
                } else { return @() }
            }
            'python' {
                if (-not ($Unit.Name.ToLowerInvariant().EndsWith('.whl') -or $Unit.Name.ToLowerInvariant().EndsWith('.egg'))) { return @() }
                if (-not ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                          (Test-Path -LiteralPath $Unit.StagingPath -PathType Container))) { return @() }
                $isEgg = $Unit.Name.ToLowerInvariant().EndsWith('.egg')
                if ($isEgg) {
                    # A zipped egg owns one root EGG-INFO/PKG-INFO. Do not use
                    # unrelated/vendored distributions to infer its identity.
                    $eggInfo = Join-Path $Unit.StagingPath 'EGG-INFO/PKG-INFO'
                    $metadata = @(Get-Item -LiteralPath $eggInfo -ErrorAction SilentlyContinue |
                        Where-Object { -not $_.PSIsContainer })
                } else {
                    $metadata = @(Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -Filter 'METADATA' -ErrorAction SilentlyContinue |
                        Where-Object { $_.Directory.Name.ToLowerInvariant().EndsWith('.dist-info') })
                }
                $metadataLayout = if ($isEgg) { 'root EGG-INFO/PKG-INFO' } else { '.dist-info/METADATA' }
                if ($metadata.Count -ne 1) {
                    return @(New-DependencyParseFinding -File $Unit.RelativePath -UnitType python -Severity MEDIUM -Confidence HIGH `
                        -Issue "Python package has $($metadata.Count) $metadataLayout files; exactly one is required for an OSV package-identity lookup." `
                        -TestID 'OSV-PYPI-AMBIGUOUS-METADATA')
                }
                $parsed = Read-ManifestBytes $metadata[0].FullName $Unit.RelativePath 'python-metadata' 'python'
            }
            default { return @() }
        }

        foreach ($f in @($parsed.Findings)) { $findings.Add($f) }
        $deps = @($parsed.Dependencies)
        if ($Unit.Type -eq 'python' -and -not $isEgg) {
            $deps = @($deps | Where-Object { $_.SourceRole -eq 'package' })
        }
        if ($deps.Count -eq 0) { return $findings.ToArray() }

        if ($Context.Mode -eq 'offline') {
            $offlineTestId = switch ($Unit.Type) {
                'python-requirements' { 'OSV-PYPI-OFFLINE' }
                'python'              { 'OSV-PYPI-OFFLINE' }
                'nuget'               { 'OSV-NUGET-OFFLINE' }
                default               { 'OSV-NPM-OFFLINE' }
            }
            $findings.Add((New-OsvOfflineFinding -Tool 'OsvScan' -UnitType $Unit.Type -File $manifestRel -TestId $offlineTestId))
            return $findings.ToArray()
        }

        foreach ($f in @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType $Unit.Type -Dependencies $deps `
                -TimeoutSec 30 -ErrorTestId 'OSV-QUERY-ERR')) { $findings.Add($f) }
        return $findings.ToArray()
    }
}
