#Requires -Version 7.4
<#
    DependencyMetadata.ps1 - bounded dependency-manifest parsing and the
    metadata-only fallback for archives that the shared extraction budget
    refuses to open (issue #39).

    The same Convert-DependencyMetadataContent entry point is used by OsvScan
    for ordinary/extracted manifests and by the archive fallback.  The fallback
    never creates a Unit.StagingPath and never extracts payload files.  It reads
    only recognized manifests into bounded byte arrays; nested ZIP/TAR
    containers are spooled to a dedicated temporary directory under a separate,
    scan-wide byte budget and are always removed by the caller.

    Keep this fallback only at Engine.ps1's four pre-extraction budget gates.
    Do not add it to mid-member or mid-TAR budget exhaustion paths: those paths
    have already dispatched members and would create duplicate dependency
    findings for metadata that was successfully reached before the stop.
#>

Set-StrictMode -Version Latest

function New-ArchiveMetadataBudget {
    <# One mutable instance per Invoke-Scan run.  All blocked archives share it. #>
    [PSCustomObject]@{
        MaxEntries             = 10000
        MaxCandidates          = 200
        MaxManifestBytes       = 1MB
        MaxDecodedBytes        = 16MB
        MaxDepth               = 3
        # Aggregate spool work across the scan, not current/peak disk usage.
        # Failed spools stay charged after deletion so repeated malformed
        # containers cannot buy unlimited write/delete I/O under one scan.
        MaxTempBytes           = 64MB
        MaxStreamBytes         = 256MB
        MaxDependencies        = 5000
        MaxMilliseconds        = 30000
        MaxCompressionRatio    = 100.0
        CompressionRatioFloor = 64KB

        Entries                = 0
        Candidates             = 0
        DecodedBytes           = 0L
        TempBytes              = 0L
        StreamBytes            = 0L
        Dependencies           = 0
        ElapsedMilliseconds    = 0L
    }
}

function Get-DependencyMetadataKind {
    param([Parameter(Mandatory)][string]$EntryName)

    $name = ($EntryName -replace '\\', '/').TrimStart('/').ToLowerInvariant()
    $leaf = [IO.Path]::GetFileName($name)
    if ($name -match '(?:^|/)[^/]+\.dist-info/metadata$') { return 'python-metadata' }
    if ($name -match '(?:^|/)(?:[^/]+\.)?egg-info/pkg-info$') { return 'python-metadata' }
    if ($name -match '(?:^|/)requirements[^/]*\.txt$') { return 'requirements' }
    if ($leaf -in @('package-lock.json', 'npm-shrinkwrap.json')) { return 'npm-lock' }
    if ($leaf -eq 'pipfile.lock') { return 'pipfile-lock' }
    if ($leaf -eq 'pyproject.toml') { return 'pyproject' }
    if ($leaf -eq 'poetry.lock') { return 'poetry-lock' }
    if ($leaf -eq 'uv.lock') { return 'uv-lock' }
    if ($leaf.EndsWith('.nuspec')) { return 'nuspec' }
    return $null
}

function Get-ArchiveMetadataContainerKind {
    param([Parameter(Mandatory)][string]$EntryName)
    $name = ($EntryName -replace '\\', '/').ToLowerInvariant()
    if ($name.EndsWith('.tar.gz') -or $name.EndsWith('.tgz')) { return 'tar-gzip' }
    $ext = [IO.Path]::GetExtension($name)
    if ($ext -in @('.zip', '.whl', '.egg', '.nupkg')) { return 'zip' }
    if ($ext -eq '.tar') { return 'tar' }
    return $null
}

function Test-ArchiveMetadataUnsafeName {
    param([Parameter(Mandatory)][string]$EntryName)
    $n = $EntryName -replace '\\', '/'
    return [IO.Path]::IsPathRooted($EntryName) -or $n.StartsWith('/') -or
           $n -match '(^|/)\.\.(/|$)' -or $n -match '^[A-Za-z]:'
}

function Convert-DependencyBytesToText {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $ms = [IO.MemoryStream]::new($Bytes, $false)
    $sr = [IO.StreamReader]::new($ms, [Text.Encoding]::UTF8, $true)
    try { return $sr.ReadToEnd() }
    finally { $sr.Dispose(); $ms.Dispose() }
}

function New-ParsedDependency {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][ValidateSet('PyPI','npm','NuGet')][string]$Ecosystem,
        [Parameter(Mandatory)][string]$ManifestFile,
        [string]$DepLabel = '',
        [ValidateSet('package','dependency')][string]$SourceRole = 'dependency'
    )
    if (-not $DepLabel) {
        $DepLabel = if ($Ecosystem -eq 'npm') { "$Name@$Version" } else { "$Name $Version" }
    }
    [PSCustomObject]@{
        Name         = $Name
        Version      = $Version
        Ecosystem    = $Ecosystem
        ManifestFile = $ManifestFile
        DepLabel     = $DepLabel
        SourceRole   = $SourceRole
    }
}

function New-DependencyParseFinding {
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][string]$Issue,
        [Parameter(Mandatory)][string]$TestID,
        [string]$UnitType = 'archive',
        [ValidateSet('INFO','LOW','MEDIUM')][string]$Severity = 'LOW',
        [ValidateSet('HIGH','MEDIUM','LOW')][string]$Confidence = 'MEDIUM'
    )
    New-Finding -Tool 'OsvScan' -Category 'parser' -Severity $Severity -Confidence $Confidence `
        -UnitType $UnitType -File $File -Issue $Issue -TestID $TestID `
        -Recommendation 'This dependency metadata was not fully audited; inspect it manually before admitting the submission.'
}

function Convert-RequirementsMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    $logicalLines = [Collections.Generic.List[string]]::new()
    $carry = ''
    foreach ($rawLine in ($Text -split "`r?`n")) {
        $joined = if ($carry) { "$carry $($rawLine.Trim())" } else { $rawLine }
        if ($joined.TrimEnd().EndsWith('\')) {
            $carry = $joined.TrimEnd().TrimEnd('\').TrimEnd()
        } else {
            $logicalLines.Add($joined)
            $carry = ''
        }
    }
    if ($carry) { $logicalLines.Add($carry) }

    foreach ($rawLine in $logicalLines) {
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        if ($line -match '^(?:-e\s*|--editable(?:=|\s+))(.+)$') {
            $spec = $Matches[1].Trim()
            $label = if ($spec -match '#egg=([A-Za-z0-9][A-Za-z0-9._-]*)') { $Matches[1] } else { $spec }
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue "Dependency '$label' is an editable/VCS install ('$line') - unpinned, OSV skipped." `
                -TestID 'OSV-PYPI-UNPINNED'))
            continue
        }
        if ($line -match '^(?:-r\s*|--requirement(?:=|\s+))(.+)$') {
            $target = $Matches[1].Trim()
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType -Severity LOW -Confidence HIGH `
                -Issue "Includes '$target' via -r/--requirement - the referenced file was not followed by this manifest parser." `
                -TestID 'OSV-PYPI-INCLUDE-UNAUDITED'))
            continue
        }
        if ($line.StartsWith('-')) { continue }
        $line = ($line -split ';', 2)[0]
        $line = ($line -split '\s+#', 2)[0].Trim()
        if (-not $line) { continue }
        $optStart = [regex]::Match($line, '\s+-{1,2}[A-Za-z]')
        if ($optStart.Success) { $line = $line.Substring(0, $optStart.Index).Trim() }
        $nameMatch = [regex]::Match($line, '^([A-Za-z0-9][A-Za-z0-9._-]*)')
        $depName = if ($nameMatch.Success) { $nameMatch.Groups[1].Value } else { $line }
        $noExtras = ([regex]::Replace($line, '\[[^\]]*\]', '')).Trim()
        $specs = @($noExtras -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($specs.Count -eq 1 -and $specs[0] -match '^[A-Za-z0-9][A-Za-z0-9._-]*\s*===?\s*([^=\s]\S*)$' -and $Matches[1] -notmatch '\*') {
            $ver = $Matches[1]
            $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $depName) -Version $ver `
                -Ecosystem PyPI -ManifestFile $ManifestFile -DepLabel "$depName $ver"))
        } else {
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue "Dependency '$depName' is not exact-pinned ('$line') - unpinned, OSV skipped." `
                -TestID 'OSV-PYPI-UNPINNED'))
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Convert-NpmLockMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    try { $lock = $Text | ConvertFrom-Json -AsHashtable -ErrorAction Stop }
    catch {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
            -Issue "Malformed npm lock file: $_" -TestID 'OSV-NPM-MALFORMED'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    if ($lock.ContainsKey('packages') -and $lock.packages) {
        foreach ($key in $lock.packages.Keys) {
            if ([string]::IsNullOrEmpty($key)) { continue }
            $entry = $lock.packages[$key]
            if (-not $entry -or -not $entry.ContainsKey('version') -or -not $entry.version) { continue }
            $name = if ($entry.ContainsKey('name') -and $entry.name) { $entry.name } else { ($key -replace '.*node_modules/', '') }
            $deps.Add((New-ParsedDependency -Name $name -Version ([string]$entry.version) -Ecosystem npm -ManifestFile $ManifestFile))
        }
    } elseif ($lock.ContainsKey('dependencies') -and $lock.dependencies) {
        foreach ($name in $lock.dependencies.Keys) {
            $entry = $lock.dependencies[$name]
            if ($entry -and $entry.ContainsKey('version') -and $entry.version) {
                $deps.Add((New-ParsedDependency -Name $name -Version ([string]$entry.version) -Ecosystem npm -ManifestFile $ManifestFile))
            }
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Convert-PipfileLockMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    try { $lock = $Text | ConvertFrom-Json -AsHashtable -ErrorAction Stop }
    catch {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
            -Issue "Malformed Pipfile.lock: $_" -TestID 'OSV-PYPI-MALFORMED'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    foreach ($section in @('default','develop')) {
        if (-not $lock.ContainsKey($section) -or -not $lock[$section]) { continue }
        foreach ($name in $lock[$section].Keys) {
            $raw = $lock[$section][$name]
            $spec = if ($raw -is [string]) { [string]$raw }
                    elseif ($raw -is [Collections.IDictionary] -and $raw.Contains('version')) { [string]$raw.version }
                    else { '' }
            if ($spec -match '^===?([^=\s]\S*)$' -and $Matches[1] -notmatch '\*') {
                $ver = $Matches[1]
                $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $name) -Version $ver `
                    -Ecosystem PyPI -ManifestFile $ManifestFile -DepLabel "$name $ver"))
            } else {
                $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                    -Issue "Dependency '$name' in Pipfile.lock is not exact-pinned ('$spec') - OSV skipped." `
                    -TestID 'OSV-PYPI-UNPINNED'))
            }
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Convert-PythonPackageMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    $headers = [Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s+' -and $headers.Count -gt 0) {
            $headers[$headers.Count - 1] = $headers[$headers.Count - 1] + ' ' + $line.Trim()
        } else { $headers.Add($line) }
    }
    $names = @($headers | Where-Object { $_ -match '^Name\s*:' } | ForEach-Object { ($_ -split ':',2)[1].Trim() })
    $versions = @($headers | Where-Object { $_ -match '^Version\s*:' } | ForEach-Object { ($_ -split ':',2)[1].Trim() })
    if ($names.Count -eq 1 -and $versions.Count -eq 1 -and $names[0] -and $versions[0]) {
        $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $names[0]) -Version $versions[0] `
            -Ecosystem PyPI -ManifestFile $ManifestFile -DepLabel "$($names[0]) $($versions[0])" -SourceRole package))
    } else {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType -Severity MEDIUM -Confidence HIGH `
            -Issue "Python package metadata has $($names.Count) Name and $($versions.Count) Version headers; exactly one of each is required for an OSV identity lookup." `
            -TestID 'OSV-PYPI-AMBIGUOUS-METADATA'))
    }
    foreach ($header in @($headers | Where-Object { $_ -match '^Requires-Dist\s*:' })) {
        $spec = (($header -split ':',2)[1] -split ';',2)[0].Trim()
        $plain = ([regex]::Replace($spec, '\[[^\]]*\]', '')).Trim()
        $m = [regex]::Match($plain, '^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\(\s*)?===?\s*([^=\s\)]+)\s*\)?$')
        if ($m.Success -and $m.Groups[2].Value -notmatch '\*') {
            $name = $m.Groups[1].Value; $ver = $m.Groups[2].Value
            $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $name) -Version $ver `
                -Ecosystem PyPI -ManifestFile $ManifestFile -DepLabel "$name $ver"))
        } else {
            $label = if ($plain -match '^([A-Za-z0-9][A-Za-z0-9._-]*)') { $Matches[1] } else { $plain }
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue "Requires-Dist dependency '$label' is not exact-pinned ('$spec') - OSV skipped." `
                -TestID 'OSV-PYPI-UNPINNED'))
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Convert-NuspecMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    try {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = [Math]::Max(1024, $Text.Length * 2)
        $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($Text), $settings)
        try {
            $xml = [Xml.XmlDocument]::new(); $xml.XmlResolver = $null; $xml.Load($reader)
        } finally { $reader.Dispose() }
    } catch {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
            -Issue "Malformed or unsafe .nuspec XML: $_" -TestID 'OSV-NUGET-MALFORMED'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    $root = $xml.DocumentElement
    if (-not $root -or $root.LocalName -ne 'package') {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
            -Issue '.nuspec root is not <package>; package identity cannot be resolved.' -TestID 'OSV-NUGET-MALFORMED'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    $metadataNodes = @($root.ChildNodes | Where-Object { $_.LocalName -eq 'metadata' })
    if ($metadataNodes.Count -ne 1) {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType -Severity MEDIUM -Confidence HIGH `
            -Issue ".nuspec has $($metadataNodes.Count) <metadata> element(s) directly under <package>; exactly one is required." `
            -TestID 'OSV-NUGET-AMBIGUOUS-NUSPEC'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    $metadata = $metadataNodes[0]
    $ids = @($metadata.ChildNodes | Where-Object { $_.LocalName -eq 'id' })
    $versions = @($metadata.ChildNodes | Where-Object { $_.LocalName -eq 'version' })
    if ($ids.Count -ne 1 -or $versions.Count -ne 1 -or -not $ids[0].InnerText.Trim() -or -not $versions[0].InnerText.Trim()) {
        $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType -Severity MEDIUM -Confidence HIGH `
            -Issue ".nuspec <metadata> has $($ids.Count) <id> and $($versions.Count) <version> element(s); exactly one non-empty value of each is required." `
            -TestID 'OSV-NUGET-AMBIGUOUS-NUSPEC'))
        return [PSCustomObject]@{ Dependencies = @(); Findings = $findings.ToArray() }
    }
    $id = $ids[0].InnerText.Trim(); $ver = $versions[0].InnerText.Trim()
    $deps.Add((New-ParsedDependency -Name $id -Version $ver -Ecosystem NuGet -ManifestFile $ManifestFile `
        -DepLabel "$id $ver" -SourceRole package))
    $dependencyNodes = @($metadata.SelectNodes('.//*[local-name()="dependency"]'))
    foreach ($node in $dependencyNodes) {
        $depId = $node.GetAttribute('id'); $range = $node.GetAttribute('version')
        if (-not $depId) { continue }
        if ($range -match '^\[([^,\]\[]+)\]$') {
            $depVer = $Matches[1]
            $deps.Add((New-ParsedDependency -Name $depId -Version $depVer -Ecosystem NuGet -ManifestFile $ManifestFile `
                -DepLabel "$depId $depVer"))
        } else {
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue "NuGet dependency '$depId' is not exact-pinned ('$range') - OSV skipped." `
                -TestID 'OSV-NUGET-UNPINNED'))
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Read-TomlDependencyArray {
    <# Read a bounded manifest's string array, not a general TOML document.
       Brackets/comments only delimit tokens outside quotes. Unsupported TOML
       string forms fail explicitly; never turn a truncated array into success. #>
    param([string]$Text, [int]$StartIndex)
    $values = [Collections.Generic.List[string]]::new()
    $i = $StartIndex + 1 # opening bracket was matched by the caller
    $expectValue = $true
    while ($i -lt $Text.Length) {
        $ch = $Text[$i]
        if ([char]::IsWhiteSpace($ch)) { $i++; continue }
        if ($ch -eq '#') {
            while ($i -lt $Text.Length -and $Text[$i] -ne "`n") { $i++ }
            continue
        }
        if ($ch -eq ']') { return ,$values.ToArray() }
        if (-not $expectValue) {
            if ($ch -ne ',') { throw 'Expected a comma between dependency strings.' }
            $expectValue = $true; $i++; continue
        }
        if ($ch -ne '"' -and $ch -ne "'") { throw 'Expected a quoted dependency string.' }
        $quote = $ch
        $start = $i
        if ($i + 2 -lt $Text.Length -and $Text[$i + 1] -eq $quote -and $Text[$i + 2] -eq $quote) {
            throw 'Multiline TOML dependency strings are not supported by this parser.'
        }
        $i++
        $closed = $false
        while ($i -lt $Text.Length) {
            $ch = $Text[$i]
            if ($ch -eq "`r" -or $ch -eq "`n") { throw 'Unterminated dependency string.' }
            if ($quote -eq '"' -and $ch -eq '\') {
                # Skip the escaped character while locating the closing quote.
                # JSON below validates/decodes the shared basic-string escapes.
                $i += 2; continue
            }
            if ($ch -eq $quote) { $closed = $true; break }
            $i++
        }
        if (-not $closed) { throw 'Unterminated dependency string.' }
        $value = if ($quote -eq "'") { $Text.Substring($start + 1, $i - $start - 1) }
                 else { ConvertFrom-Json -InputObject $Text.Substring($start, $i - $start + 1) -ErrorAction Stop }
        $values.Add([string]$value)
        $expectValue = $false
        $i++
    }
    throw 'Unterminated dependency array.'
}

function Convert-TomlLockMetadata {
    param([string]$Text, [string]$ManifestFile, [string]$UnitType, [string]$Kind)
    $deps = [Collections.Generic.List[object]]::new()
    $findings = [Collections.Generic.List[object]]::new()
    if ($Kind -in @('poetry-lock','uv-lock')) {
        $blocks = @([regex]::Split($Text, '(?m)^\s*\[\[package\]\]\s*$') | Select-Object -Skip 1)
        foreach ($block in $blocks) {
            $nm = [regex]::Match($block, '(?m)^\s*name\s*=\s*["'']([^"'']+)["'']\s*$')
            $vm = [regex]::Match($block, '(?m)^\s*version\s*=\s*["'']([^"'']+)["'']\s*$')
            if ($nm.Success -and $vm.Success) {
                $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $nm.Groups[1].Value) `
                    -Version $vm.Groups[1].Value -Ecosystem PyPI -ManifestFile $ManifestFile `
                    -DepLabel "$($nm.Groups[1].Value) $($vm.Groups[1].Value)"))
            }
        }
        if ($blocks.Count -gt 0 -and $deps.Count -eq 0) {
            $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue 'TOML lock file contains package blocks that could not be resolved to exact name/version pairs.' `
                -TestID 'OSV-PYPI-MALFORMED'))
        }
    } else {
        # Find array starts, then scan strings with quote/escape/comment state.
        # A non-greedy closing-bracket regex loses requirements with extras.
        foreach ($array in [regex]::Matches($Text, '(?m)^[\t ]*(?:optional-)?dependencies[\t ]*=[\t ]*\[')) {
            try {
                $requirements = Read-TomlDependencyArray -Text $Text -StartIndex ($array.Index + $array.Length - 1)
            } catch {
                $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                    -Issue "Malformed or unsupported pyproject dependency array: $($_.Exception.Message)" `
                    -TestID 'OSV-PYPI-MALFORMED'))
                continue
            }
            foreach ($requirement in $requirements) {
                $spec = ($requirement -split ';',2)[0].Trim()
                $plain = ([regex]::Replace($spec, '\[[^\]]*\]', '')).Trim()
                if ($plain -match '^([A-Za-z0-9][A-Za-z0-9._-]*)\s*===?\s*([^=\s]+)$' -and $Matches[2] -notmatch '\*') {
                    $name = $Matches[1]; $ver = $Matches[2]
                    $deps.Add((New-ParsedDependency -Name (Get-Pep503NormalizedName -Name $name) -Version $ver `
                        -Ecosystem PyPI -ManifestFile $ManifestFile -DepLabel "$name $ver"))
                } else {
                    $label = if ($plain -match '^([A-Za-z0-9][A-Za-z0-9._-]*)') { $Matches[1] } else { $plain }
                    $findings.Add((New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                        -Issue "pyproject dependency '$label' is not exact-pinned ('$spec') - OSV skipped." `
                        -TestID 'OSV-PYPI-UNPINNED'))
                }
            }
        }
    }
    [PSCustomObject]@{ Dependencies = $deps.ToArray(); Findings = $findings.ToArray() }
}

function Convert-DependencyMetadataContent {
    <# Parse one already-bounded candidate.  No filesystem or network access. #>
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$ManifestFile,
        [string]$UnitType = 'archive'
    )
    try { $text = Convert-DependencyBytesToText -Bytes $Bytes }
    catch {
        return [PSCustomObject]@{ Dependencies = @(); Findings = @(
            New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType `
                -Issue "Dependency metadata text decoding failed: $_" -TestID 'MTS-ARCHIVE-METADATA-ERROR') }
    }
    switch ($Kind) {
        'requirements'    { return Convert-RequirementsMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType }
        'npm-lock'        { return Convert-NpmLockMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType }
        'pipfile-lock'    { return Convert-PipfileLockMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType }
        'python-metadata' { return Convert-PythonPackageMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType }
        'nuspec'          { return Convert-NuspecMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType }
        'pyproject'       { return Convert-TomlLockMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType -Kind $Kind }
        'poetry-lock'     { return Convert-TomlLockMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType -Kind $Kind }
        'uv-lock'         { return Convert-TomlLockMetadata -Text $text -ManifestFile $ManifestFile -UnitType $UnitType -Kind $Kind }
        default {
            return [PSCustomObject]@{ Dependencies = @(); Findings = @(
                New-DependencyParseFinding -File $ManifestFile -UnitType $UnitType -Severity INFO `
                    -Issue "Unsupported dependency metadata kind '$Kind'." -TestID 'MTS-ARCHIVE-METADATA-UNSUPPORTED') }
        }
    }
}

function Read-ArchiveMetadataStreamBytes {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][long]$Limit,
        [Parameter(Mandatory)][PSCustomObject]$Budget
    )
    $ms = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(65536)
        while ($true) {
            $manifestRemaining = $Limit - $ms.Length
            if ($manifestRemaining -le 0) { throw "stream exceeds the $Limit-byte limit" }
            $budgetRemaining = $Budget.MaxDecodedBytes - $Budget.DecodedBytes
            if ($budgetRemaining -le 0) { throw 'decoded metadata byte budget reached while reading stream' }
            $readLimit = [Math]::Min($buffer.Length, [Math]::Min($manifestRemaining, $budgetRemaining))
            $read = $Stream.Read($buffer, 0, [int]$readLimit)
            if ($read -le 0) { break }
            # Charge bytes as they are read, including on a later exception.
            # A lying archive header therefore cannot repeatedly consume decode
            # work without advancing the scan-wide budget.
            $Budget.DecodedBytes += $read
            $ms.Write($buffer, 0, $read)
        }
        return $ms.ToArray()
    } finally { $ms.Dispose() }
}

function Save-ArchiveMetadataNestedStream {
    param([IO.Stream]$Stream, [string]$Destination, [long]$Length, [PSCustomObject]$Budget)
    if ($Length -gt ($Budget.MaxTempBytes - $Budget.TempBytes)) { throw 'metadata temporary-byte budget would be exceeded' }
    $out = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $saved = $false
    try {
        $buffer = [byte[]]::new(65536); $written = 0L
        while ($true) {
            if ($Length -ge 0 -and $written -eq $Length) { break }
            $remaining = $Budget.MaxTempBytes - $Budget.TempBytes
            if ($remaining -le 0) { throw 'metadata temporary-byte budget reached' }
            $readLimit = [Math]::Min($buffer.Length, $remaining)
            if ($Length -ge 0) { $readLimit = [Math]::Min($readLimit, $Length - $written) }
            $read = $Stream.Read($buffer, 0, [int]$readLimit)
            if ($read -le 0) { break }
            # Charge before writing so an I/O failure or declared-length
            # mismatch cannot leave bytes on disk outside the scan-wide cap.
            $Budget.TempBytes += $read
            $written += $read
            $out.Write($buffer, 0, $read)
        }
        if ($Length -ge 0 -and $written -ne $Length) {
            throw "nested container was truncated (declared $Length bytes, read $written)"
        }
        $saved = $true
        return $written
    } finally {
        $out.Dispose()
        if (-not $saved) { [IO.File]::Delete($Destination) }
    }
}

function Invoke-ArchiveMetadataDependencyScan {
    <#
        Read recognized metadata from a blocked ZIP/TAR tree, parse exact
        dependency identities, and use the shared OSV client.  Returns findings;
        never throws and never mutates the Unit or its StagingPath.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject]$Budget
    )

    $findings = [Collections.Generic.List[object]]::new()
    $candidates = [Collections.Generic.List[object]]::new()
    $allDeps = [Collections.Generic.List[object]]::new()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) "mts-metadata-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    function Test-LimitTime {
        return ($Budget.ElapsedMilliseconds + $timer.ElapsedMilliseconds) -ge $Budget.MaxMilliseconds
    }
    function Add-Limit([string]$file, [string]$reason) {
        $findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity INFO -Confidence HIGH `
            -UnitType archive -File $file -Issue "Archive metadata scan stopped at a safety limit: $reason." `
            -TestID 'MTS-ARCHIVE-METADATA-LIMIT' `
            -Recommendation 'Dependency metadata beyond this limit was not audited; inspect it manually before admitting the submission.'))
    }
    function Add-Error([string]$file, [string]$reason) {
        $findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity INFO -Confidence LOW `
            -UnitType archive -File $file -Issue "Archive metadata scan could not inspect this content: $reason." `
            -TestID 'MTS-ARCHIVE-METADATA-ERROR' `
            -Recommendation 'Absence of vulnerability findings here is absence of coverage, not evidence the content is safe.'))
    }
    function Add-Candidate([string]$logical, [string]$kind, [byte[]]$bytes) {
        $candidates.Add([PSCustomObject]@{ LogicalPath = $logical; Kind = $kind; Bytes = $bytes })
        return $true
    }

    function Read-Container([string]$containerPath, [string]$logicalContainer, [int]$depth, [string]$knownKind = '') {
        if (Test-LimitTime) { Add-Limit $logicalContainer "processing-time cap ($($Budget.MaxMilliseconds) ms) reached"; return }
        if ($depth -gt $Budget.MaxDepth) { Add-Limit $logicalContainer "nested-container depth cap ($($Budget.MaxDepth)) reached"; return }
        $containerKind = if ($knownKind) { $knownKind } else { Get-ArchiveMetadataContainerKind -EntryName $containerPath }
        if (-not $containerKind) { Add-Error $logicalContainer 'unsupported nested container format'; return }

        $localCandidates = [Collections.Generic.List[object]]::new()
        $localNested = [Collections.Generic.List[object]]::new()
        $seen = @{}
        $duplicates = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        try {
            if ($containerKind -eq 'zip') {
                $zip = [IO.Compression.ZipFile]::OpenRead($containerPath)
                try {
                    foreach ($entry in $zip.Entries) {
                        if (Test-LimitTime) { Add-Limit $logicalContainer "processing-time cap ($($Budget.MaxMilliseconds) ms) reached"; break }
                        if ($Budget.Entries -ge $Budget.MaxEntries) { Add-Limit $logicalContainer "entry cap ($($Budget.MaxEntries)) reached"; break }
                        $Budget.Entries++
                        $name = ($entry.FullName -replace '\\','/').TrimStart('/')
                        if (-not $name -or $name.EndsWith('/')) { continue }
                        $key = $name.ToLowerInvariant()
                        if ($seen.ContainsKey($key)) { [void]$duplicates.Add($key); continue }
                        $seen[$key] = $true
                        $logical = "$logicalContainer!$name"
                        if (Test-ArchiveMetadataUnsafeName -EntryName $entry.FullName) {
                            Add-Error $logical 'path-traversal or rooted entry name'; continue
                        }
                        $zipMode = (([int64]$entry.ExternalAttributes -band 0xFFFFFFFF) -shr 16) -band 0xF000
                        if ($zipMode -eq 0xA000) { Add-Error $logical 'ZIP symlink entry is never followed'; continue }
                        if ($entry.IsEncrypted) { Add-Error $logical 'encrypted ZIP entry cannot be read'; continue }
                        $kind = Get-DependencyMetadataKind -EntryName $name
                        $nestedKind = Get-ArchiveMetadataContainerKind -EntryName $name
                        if (-not $kind -and -not $nestedKind) { continue }
                        $maxBytes = if ($kind) { $Budget.MaxManifestBytes } else { $Budget.MaxTempBytes - $Budget.TempBytes }
                        if ($entry.Length -gt $maxBytes) { Add-Limit $logical "entry size $($entry.Length) exceeds its $maxBytes-byte limit"; continue }
                        if ($entry.Length -ge $Budget.CompressionRatioFloor -and $entry.CompressedLength -gt 0 -and
                            ([double]$entry.Length / [double]$entry.CompressedLength) -gt $Budget.MaxCompressionRatio) {
                            Add-Limit $logical "compression ratio exceeds $($Budget.MaxCompressionRatio)x"; continue
                        }
                        try {
                            $stream = $entry.Open()
                            try {
                                if ($kind) {
                                    if ($Budget.Candidates -ge $Budget.MaxCandidates) { Add-Limit $logical "candidate cap ($($Budget.MaxCandidates)) reached"; break }
                                    if (($Budget.DecodedBytes + $entry.Length) -gt $Budget.MaxDecodedBytes) { Add-Limit $logical "decoded metadata byte cap ($($Budget.MaxDecodedBytes)) reached"; continue }
                                    $bytes = Read-ArchiveMetadataStreamBytes -Stream $stream `
                                        -Limit ($Budget.MaxManifestBytes + 1L) -Budget $Budget
                                    $Budget.Candidates++
                                    $localCandidates.Add([PSCustomObject]@{ Key=$key; Logical=$logical; Kind=$kind; Bytes=$bytes })
                                } elseif ($depth -lt $Budget.MaxDepth) {
                                    $tmp = Join-Path $tempRoot ([guid]::NewGuid().ToString('N'))
                                    [void](Save-ArchiveMetadataNestedStream -Stream $stream -Destination $tmp -Length $entry.Length -Budget $Budget)
                                    $localNested.Add([PSCustomObject]@{ Key=$key; Logical=$logical; Path=$tmp; Kind=$nestedKind })
                                } else { Add-Limit $logical "nested-container depth cap ($($Budget.MaxDepth)) reached" }
                            } finally { $stream.Dispose() }
                        } catch { Add-Error $logical $_.Exception.Message }
                    }
                } finally { $zip.Dispose() }
            } else {
                $file = [IO.File]::OpenRead($containerPath); $gzip = $null; $reader = $null
                try {
                    $isGzip = $containerKind -eq 'tar-gzip'
                    $source = if ($isGzip) { $gzip = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionMode]::Decompress); $gzip } else { $file }
                    $reader = [System.Formats.Tar.TarReader]::new($source, $true)
                    $containerStreamBytes = 0L
                    while ($entry = $reader.GetNextEntry()) {
                        if (Test-LimitTime) { Add-Limit $logicalContainer "processing-time cap ($($Budget.MaxMilliseconds) ms) reached"; break }
                        if ($Budget.Entries -ge $Budget.MaxEntries) { Add-Limit $logicalContainer "entry cap ($($Budget.MaxEntries)) reached"; break }
                        $Budget.Entries++
                        $entryLength = [long]$entry.Length
                        if (($Budget.StreamBytes + $entryLength) -gt $Budget.MaxStreamBytes) { Add-Limit $logicalContainer "decompressed stream traversal cap ($($Budget.MaxStreamBytes)) reached"; break }
                        $Budget.StreamBytes += $entryLength
                        $containerStreamBytes += $entryLength
                        if ($isGzip -and $containerStreamBytes -ge $Budget.CompressionRatioFloor -and $file.Length -gt 0 -and
                            ([double]$containerStreamBytes / [double]$file.Length) -gt $Budget.MaxCompressionRatio) {
                            Add-Limit $logicalContainer "gzip expansion ratio exceeds $($Budget.MaxCompressionRatio)x"; break
                        }
                        $name = ([string]$entry.Name -replace '\\','/').TrimStart('/')
                        if (-not $name) { continue }
                        $key = $name.ToLowerInvariant()
                        if ($seen.ContainsKey($key)) { [void]$duplicates.Add($key); continue }
                        $seen[$key] = $true
                        $logical = "$logicalContainer!$name"
                        if (Test-ArchiveMetadataUnsafeName -EntryName ([string]$entry.Name)) { Add-Error $logical 'path-traversal or rooted entry name'; continue }
                        $regular = $entry.EntryType -in @([System.Formats.Tar.TarEntryType]::RegularFile, [System.Formats.Tar.TarEntryType]::V7RegularFile)
                        if (-not $regular) {
                            if ($entry.EntryType -in @([System.Formats.Tar.TarEntryType]::SymbolicLink, [System.Formats.Tar.TarEntryType]::HardLink)) {
                                Add-Error $logical "link entry type '$($entry.EntryType)' is never followed"
                            }
                            continue
                        }
                        $kind = Get-DependencyMetadataKind -EntryName $name
                        $nestedKind = Get-ArchiveMetadataContainerKind -EntryName $name
                        if (-not $kind -and -not $nestedKind) { continue }
                        if (-not $entry.DataStream) { Add-Error $logical 'regular TAR entry has no readable data stream'; continue }
                        $maxBytes = if ($kind) { $Budget.MaxManifestBytes } else { $Budget.MaxTempBytes - $Budget.TempBytes }
                        if ($entryLength -gt $maxBytes) { Add-Limit $logical "entry size $entryLength exceeds its $maxBytes-byte limit"; continue }
                        try {
                            if ($kind) {
                                if ($Budget.Candidates -ge $Budget.MaxCandidates) { Add-Limit $logical "candidate cap ($($Budget.MaxCandidates)) reached"; break }
                                if (($Budget.DecodedBytes + $entryLength) -gt $Budget.MaxDecodedBytes) { Add-Limit $logical "decoded metadata byte cap ($($Budget.MaxDecodedBytes)) reached"; continue }
                                $bytes = Read-ArchiveMetadataStreamBytes -Stream $entry.DataStream `
                                    -Limit ($Budget.MaxManifestBytes + 1L) -Budget $Budget
                                $Budget.Candidates++
                                $localCandidates.Add([PSCustomObject]@{ Key=$key; Logical=$logical; Kind=$kind; Bytes=$bytes })
                            } elseif ($depth -lt $Budget.MaxDepth) {
                                $tmp = Join-Path $tempRoot ([guid]::NewGuid().ToString('N'))
                                [void](Save-ArchiveMetadataNestedStream -Stream $entry.DataStream -Destination $tmp -Length $entryLength -Budget $Budget)
                                $localNested.Add([PSCustomObject]@{ Key=$key; Logical=$logical; Path=$tmp; Kind=$nestedKind })
                            } else { Add-Limit $logical "nested-container depth cap ($($Budget.MaxDepth)) reached" }
                        } catch { Add-Error $logical $_.Exception.Message }
                    }
                } finally {
                    if ($reader) { $reader.Dispose() }
                    if ($gzip) { $gzip.Dispose() }
                    $file.Dispose()
                }
            }
        } catch { Add-Error $logicalContainer $_.Exception.Message }

        foreach ($duplicate in $duplicates) {
            Add-Error "$logicalContainer!$duplicate" 'duplicate archive entry name is ambiguous; every copy was skipped'
        }
        foreach ($candidate in $localCandidates) {
            if ($duplicates.Contains($candidate.Key)) { continue }
            if (-not (Add-Candidate $candidate.Logical $candidate.Kind $candidate.Bytes)) { break }
        }
        foreach ($nested in $localNested) {
            if ($duplicates.Contains($nested.Key)) { Remove-Item -LiteralPath $nested.Path -Force -ErrorAction SilentlyContinue; continue }
            Read-Container $nested.Path $nested.Logical ($depth + 1) $nested.Kind
        }
    }

    try {
        Read-Container $Path $RelativePath 1
        foreach ($candidate in $candidates) {
            if (Test-LimitTime) { Add-Limit $candidate.LogicalPath "processing-time cap ($($Budget.MaxMilliseconds) ms) reached"; break }
            if ($Budget.Dependencies -ge $Budget.MaxDependencies) { Add-Limit $candidate.LogicalPath "dependency record cap ($($Budget.MaxDependencies)) reached"; break }
            $parsed = Convert-DependencyMetadataContent -Kind $candidate.Kind -Bytes $candidate.Bytes `
                -ManifestFile $candidate.LogicalPath -UnitType archive
            foreach ($f in @($parsed.Findings)) { $findings.Add($f) }
            foreach ($dep in @($parsed.Dependencies)) {
                if ($Budget.Dependencies -ge $Budget.MaxDependencies) { Add-Limit $candidate.LogicalPath "dependency record cap ($($Budget.MaxDependencies)) reached"; break }
                $Budget.Dependencies++; $allDeps.Add($dep)
            }
        }
        $resolved = @($allDeps.ToArray())
        if ($candidates.Count -gt 0) {
            $modeText = if ($Context.Mode -eq 'offline') { 'OSV lookup was skipped because the scan is offline' }
                        else { "$($resolved.Count) exact package/dependency record(s) were submitted to OSV" }
            $findings.Add((New-Finding -Tool 'OsvScan' -Category 'parser' -Severity INFO -Confidence HIGH `
                -UnitType archive -File $RelativePath `
                -Issue "Dependency metadata was inspected without extracting the archive; $($candidates.Count) manifest(s) were read and $modeText. Payload files and unsupported metadata were not inspected by this fallback." `
                -TestID 'MTS-ARCHIVE-METADATA-PARTIAL' `
                -Recommendation 'Review this together with MTS-ARCHIVE-BUDGET-EXCEEDED; full archive-content coverage is still incomplete.'))
        }
        if ($resolved.Count -gt 0) {
            if ($Context.Mode -eq 'offline') {
                foreach ($group in ($resolved | Group-Object ManifestFile)) {
                    $findings.Add((New-OsvOfflineFinding -Tool 'OsvScan' -UnitType archive -File $group.Name -TestId 'OSV-ARCHIVE-METADATA-OFFLINE'))
                }
            } else {
                foreach ($f in @(Get-OsvDependencyFindings -Tool 'OsvScan' -UnitType archive -Dependencies $resolved `
                        -TimeoutSec 30 -ErrorTestId 'OSV-QUERY-ERR')) { $findings.Add($f) }
            }
        }
    } catch { Add-Error $RelativePath $_.Exception.Message }
    finally {
        $timer.Stop(); $Budget.ElapsedMilliseconds += $timer.ElapsedMilliseconds
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $findings.ToArray()
}
