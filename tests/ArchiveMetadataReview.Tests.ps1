#Requires -Version 7.4
<# Regression coverage for the follow-up review of PR #40. #>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $script:Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet = $true
    $script:MetaDir = Join-Path $PSScriptRoot 'fixtures/corpus/archive_metadata'
    $script:Analyzers = Join-Path $script:Root 'src/analyzers'

    function Invoke-ReviewParser([string]$Kind, [string]$Text, [int]$MaxRecords = 5000) {
        Convert-DependencyMetadataContent -Kind $Kind -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)) -ManifestFile 'fixture' -MaxRecords $MaxRecords
    }
    function New-ReviewZip([string]$EntryName, [string]$Text) {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.zip')
        $zip = [IO.Compression.ZipFile]::Open($path, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $writer = [IO.StreamWriter]::new($zip.CreateEntry($EntryName).Open())
            try { $writer.Write($Text) } finally { $writer.Dispose() }
        } finally { $zip.Dispose() }
        return $path
    }
    $script:V1Lock = @'
{"lockfileVersion":1,"dependencies":{"parent":{"version":"1.0.0","dependencies":{"lodash":{"version":"4.17.4","dependencies":{"@scope/leaf":{"version":"2.0.0"}}}}}}}
'@
}

Describe 'npm v1 nested dependency coverage' {
    It 'walks transitive and scoped identities at multiple depths' {
        $parsed = Invoke-ReviewParser npm-lock $script:V1Lock
        @($parsed.Dependencies.Name) | Should -Be @('parent', 'lodash', '@scope/leaf')
        @($parsed.Dependencies.Version) | Should -Be @('1.0.0', '4.17.4', '2.0.0')
        @($parsed.Findings).Count | Should -Be 0
    }

    It 'retains children of a malformed parent and reports the missing identity' {
        $parsed = Invoke-ReviewParser npm-lock '{"dependencies":{"parent":{"dependencies":{"lodash":{"version":"4.17.4"}}}}}'
        @($parsed.Dependencies.Name) | Should -Be @('lodash')
        @($parsed.Findings | Where-Object TestID -eq 'OSV-NPM-MALFORMED').Count | Should -Be 1
    }

    It 'applies the shared record cap before walking further into the tree' {
        $parsed = Invoke-ReviewParser npm-lock $script:V1Lock 2
        @($parsed.Dependencies.Name) | Should -Be @('parent', 'lodash')
        $parsed.RecordCount | Should -Be 2
        $parsed.LimitReached | Should -BeTrue
    }

    It 'rejects malformed dependency maps explicitly' -ForEach @(
        @{ Text='[]' }, @{ Text='{"dependencies":[]}' },
        @{ Text='{"dependencies":{"broken":{"version":"1","dependencies":[]}}}' }
    ) {
        $parsed = Invoke-ReviewParser npm-lock $Text
        @($parsed.Findings | Where-Object TestID -eq 'OSV-NPM-MALFORMED').Count | Should -Be 1
    }

    It 'uses the v2/v3 package map without duplicating its compatibility tree' {
        $parsed = Invoke-ReviewParser npm-lock '{"lockfileVersion":2,"packages":{"node_modules/lodash":{"version":"4.17.4"}},"dependencies":{"lodash":{"version":"4.17.4"}}}'
        @($parsed.Dependencies).Count | Should -Be 1
    }

    It 'queries transitive identities through both ordinary and archive paths' {
        $script:Queries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:Queries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $path = Join-Path $TestDrive 'package-lock.json'
        Set-Content -LiteralPath $path -Value $script:V1Lock
        $unit = (New-Unit -File (Get-Item $path) -ScanRoot $TestDrive).Unit
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        @(& $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' })) | Out-Null
        $zip = New-ReviewZip 'package-lock.json' $script:V1Lock
        @(Invoke-ArchiveMetadataDependencyScan -Path $zip -RelativePath 'lock.zip' -Context ([PSCustomObject]@{ Mode='online' }) -Budget (New-ArchiveMetadataBudget)) | Out-Null
        $script:Queries.Count | Should -Be 6
        @($script:Queries | Where-Object { $_.package.name -eq 'lodash' -and $_.version -eq '4.17.4' }).Count | Should -Be 2
    }
}

Describe 'Python metadata header boundaries' {
    It 'ignores body decoys but retains folded header requirements' -ForEach @(
        @{ Newline="`n" }, @{ Newline="`r`n" }
    ) {
        $text = @('Name: Pillow','Version: 9.5.0','Requires-Dist: urllib3',' (==1.26.5)','','Name: benign','Version: 999','Requires-Dist: bogus==999') -join $Newline
        $parsed = Invoke-ReviewParser python-metadata $text
        @($parsed.Dependencies.Name) | Should -Be @('pillow', 'urllib3')
        @($parsed.Findings).Count | Should -Be 0
    }

    It 'does not borrow an identity from a body following empty headers' {
        $parsed = Invoke-ReviewParser python-metadata "`nName: body-only`nVersion: 1"
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-AMBIGUOUS-METADATA').Count | Should -Be 1
    }

    It 'still rejects genuine duplicate identity headers' {
        $parsed = Invoke-ReviewParser python-metadata "Name: one`nName: two`nVersion: 1`n`nDescription"
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-AMBIGUOUS-METADATA').Count | Should -Be 1
    }

    It 'keeps description text out of wheel and egg fallback queries' -ForEach @(
        @{ Entry='Pillow.dist-info/METADATA' }, @{ Entry='EGG-INFO/PKG-INFO' }
    ) {
        $script:Queries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:Queries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $zip = New-ReviewZip $Entry "Name: Pillow`nVersion: 9.5.0`n`nName: benign`nVersion: 999`nRequires-Dist: bogus==999"
        @(Invoke-ArchiveMetadataDependencyScan -Path $zip -RelativePath 'package.zip' -Context ([PSCustomObject]@{ Mode='online' }) -Budget (New-ArchiveMetadataBudget)) | Out-Null
        $script:Queries.Count | Should -Be 1
        $script:Queries[0].package.name | Should -Be 'pillow'
    }
}

Describe 'TOML equivalent dotted dependency keys' {
    It 'normalizes equivalent dotted/table declarations' -ForEach @(
        @{ Text="[project]`noptional-dependencies.security = ['requests==2.31.0']" },
        @{ Text="project.optional-dependencies.security = ['requests==2.31.0']" },
        @{ Text="[project]`n'optional-dependencies'.'security.extra' = ['requests==2.31.0']" },
        @{ Text='"project"."optional-dependencies"."security" = ["requests==2.31.0"]' },
        @{ Text="[project.optional-dependencies]`n'security.extra' = ['requests==2.31.0']" },
        @{ Text="project.dependencies = ['requests==2.31.0']" }
    ) {
        $parsed = Invoke-ReviewParser pyproject $Text
        @($parsed.Dependencies.Name) | Should -Be @('requests')
        @($parsed.Findings).Count | Should -Be 0
    }

    It 'does not mistake literal dots or tool tables for project dependency paths' -ForEach @(
        @{ Text="[project]`n'optional-dependencies.security' = ['bogus==999']" },
        @{ Text="[tool.example]`nproject.optional-dependencies.security = ['bogus==999']" }
    ) {
        $parsed = Invoke-ReviewParser pyproject $Text
        @($parsed.Dependencies).Count | Should -Be 0
    }

    It 'queries dotted optional pins on both ordinary and fallback paths' {
        $script:Queries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:Queries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $text = "[project]`noptional-dependencies.security = ['requests==2.31.0']"
        $path = Join-Path $TestDrive 'pyproject.toml'
        Set-Content -LiteralPath $path -Value $text
        $unit = (New-Unit -File (Get-Item $path) -ScanRoot $TestDrive).Unit
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        @(& $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' })) | Out-Null
        $zip = New-ReviewZip 'pyproject.toml' $text
        @(Invoke-ArchiveMetadataDependencyScan -Path $zip -RelativePath 'project.zip' -Context ([PSCustomObject]@{ Mode='online' }) -Budget (New-ArchiveMetadataBudget)) | Out-Null
        $script:Queries.Count | Should -Be 2
        @($script:Queries | Where-Object { $_.package.name -eq 'requests' -and $_.version -eq '2.31.0' }).Count | Should -Be 2
    }
}

Describe 'Container identity and recovery work accounting' {
    It 'preserves the TAR format despite its PK filename prefix' {
        $path = Join-Path $script:MetaDir 'pk_prefix.tar'
        Test-ZipFileMagic -Path $path | Should -BeTrue
        Get-ArchiveMetadataContainerKind -EntryName 'decoy.tar' -Path $path | Should -Be 'tar'
        Get-ArchiveMetadataContainerKind -EntryName 'spool' -Path $path -KnownKind tar | Should -Be 'tar'
        Get-ArchiveMetadataContainerKind -EntryName 'spool' -Path $path -KnownKind tar-gzip | Should -Be 'tar-gzip'
    }

    It 'audits TAR manifests despite a conflicting ZIP prefix, directly and nested' -ForEach @(
        @{ File='pk_prefix.tar' }, @{ File='nested_pk_prefix.zip' }
    ) {
        $budget = New-ArchiveMetadataBudget
        $findings = @(Invoke-ArchiveMetadataDependencyScan -Path (Join-Path $script:MetaDir $File) -RelativePath $File -Context ([PSCustomObject]@{ Mode='offline' }) -Budget $budget)
        $budget.Candidates | Should -Be 1
        $budget.Dependencies | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR').Count | Should -Be 0
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').Count | Should -Be 1
    }

    It 'bounds enumeration work even when recovery candidates are excluded' -ForEach @(
        @{ Format='zip' }, @{ Format='tar' }
    ) {
        $path = if ($Format -eq 'zip') { New-ReviewZip 'requirements-a.txt' 'Pillow==9.5.0' }
                else { Join-Path $script:MetaDir 'stopped_metadata.tgz' }
        $excluded = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [void]$excluded.Add('recovery!requirements-a.txt')
        $budget = New-ArchiveMetadataBudget; $budget.MaxEntries = 1
        @(Invoke-ArchiveMetadataDependencyScan -Path $path -RelativePath 'recovery' -Context ([PSCustomObject]@{ Mode='offline' }) -Budget $budget -ExcludedPaths $excluded) | Out-Null
        $budget.Entries | Should -Be 1
        $budget.Candidates | Should -Be 0
        $later = New-ReviewZip 'requirements.txt' 'requests==2.31.0'
        $findings = @(Invoke-ArchiveMetadataDependencyScan -Path $later -RelativePath 'later' -Context ([PSCustomObject]@{ Mode='offline' }) -Budget $budget)
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT').Count | Should -BeGreaterThan 0
        $budget.Entries | Should -Be 1
        $budget.Candidates | Should -Be 0
    }
}
