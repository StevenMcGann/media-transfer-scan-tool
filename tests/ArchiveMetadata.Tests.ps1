#Requires -Version 7.4
<# Pester 5 coverage for issue #39's metadata-only archive fallback. #>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $script:Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet = $true
    $script:MetaDir = Join-Path $PSScriptRoot 'fixtures/corpus/archive_metadata'
    $script:Analyzers = Join-Path $script:Root 'src/analyzers'
    $script:Out = Join-Path $env:TEMP "mts-arcmeta-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:RunMetadata([string]$Name, [PSCustomObject]$Budget = $null, [string]$Mode = 'offline') {
        if (-not $Budget) { $Budget = New-ArchiveMetadataBudget }
        $context = [PSCustomObject]@{ Mode = $Mode }
        $path = Join-Path $script:MetaDir $Name
        @(Invoke-ArchiveMetadataDependencyScan -Path $path -RelativePath $Name -Context $context -Budget $Budget)
    }
}

AfterAll {
    Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Archive metadata fallback - nested wheel identity and dependencies' {
    It 'reads a nested wheel METADATA without extracting its payload tree' {
        $budget = New-ArchiveMetadataBudget
        $findings = RunMetadata 'nested_vulnerable_wheel.zip' $budget
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED' | Where-Object Issue -Match 'requests').Count | Should -Be 1
        ($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').File |
            Should -Match 'nested_vulnerable_wheel\.zip!packages/Pillow-9\.5\.0-py3-none-any\.whl!Pillow-9\.5\.0\.dist-info/METADATA'
        $budget.Candidates | Should -Be 1
        $budget.Dependencies | Should -Be 2 # wheel identity + exact urllib3 Requires-Dist
        $budget.TempBytes | Should -BeGreaterThan 0
    }

    It 'submits both the wheel identity and its exact dependency to the shared OSV client' {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $findings = RunMetadata 'nested_vulnerable_wheel.zip' (New-ArchiveMetadataBudget) 'online'
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'pillow' -and $_.version -eq '9.5.0' }).Count | Should -Be 1
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'urllib3' -and $_.version -eq '1.26.5' }).Count | Should -Be 1
    }

    It 'turns a vulnerable wheel identity into the normal vuln-dependency finding model' {
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            @($Queries | ForEach-Object {
                if ($_.package.name -eq 'pillow') {
                    [PSCustomObject]@{ vulns = @([PSCustomObject]@{ id = 'GHSA-METADATA-FIXTURE' }) }
                } else { [PSCustomObject]@{} }
            })
        }
        Mock Get-OsvVulnDetails {
            [PSCustomObject]@{
                id = 'GHSA-METADATA-FIXTURE'; summary = 'fixture wheel vulnerability'
                database_specific = [PSCustomObject]@{ severity = 'HIGH' }
                affected = @([PSCustomObject]@{
                    package = [PSCustomObject]@{ name = 'Pillow'; ecosystem = 'PyPI' }
                    ranges = @()
                })
            }
        }
        $findings = RunMetadata 'nested_vulnerable_wheel.zip' (New-ArchiveMetadataBudget) 'online'
        $vuln = @($findings | Where-Object TestID -eq 'GHSA-METADATA-FIXTURE')
        $vuln.Count | Should -Be 1
        $vuln[0].Category | Should -Be 'vuln-dependency'
        $vuln[0].File | Should -Match '\.whl!Pillow-9\.5\.0\.dist-info/METADATA$'
    }

    It 'does not create or assign a normal StagingPath' {
        $file = Get-Item -LiteralPath (Join-Path $script:MetaDir 'nested_vulnerable_wheel.zip')
        $unit = (New-Unit -File $file -ScanRoot $script:MetaDir).Unit
        $unit.StagingPath | Should -BeNullOrEmpty
        RunMetadata 'nested_vulnerable_wheel.zip' | Out-Null
        $unit.StagingPath | Should -BeNullOrEmpty
    }
}

Describe 'Archive metadata fallback - ZIP, TAR, and manifest formats' {
    It 'audits canonical egg identity directly and through a nested spool' -ForEach @(
        @{ Name = 'Pillow-9.5.0-py3.egg' }, @{ Name = 'nested_egg.zip' }
    ) {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $findings = RunMetadata $Name (New-ArchiveMetadataBudget) 'online'
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'pillow' -and $_.version -eq '9.5.0' }).Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR').Count | Should -Be 0
    }

    It 'audits all pyproject pins after quoted extras and ignores brackets and quotes in comments' {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        RunMetadata 'pyproject_extras.zip' (New-ArchiveMetadataBudget) 'online' | Out-Null
        @($script:CapturedQueries).Count | Should -Be 3
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'requests' -and $_.version -eq '2.31.0' }).Count | Should -Be 1
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'urllib3' -and $_.version -eq '1.26.5' }).Count | Should -Be 1
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'pillow' -and $_.version -eq '9.5.0' }).Count | Should -Be 1
    }

    It 'reads METADATA from both compressed and uncompressed tar archives' -ForEach @(
        @{ Name = 'metadata.tgz' }, @{ Name = 'metadata.tar' }
    ) {
        $findings = RunMetadata $Name
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').Count | Should -Be 1
    }

    It 'carries the known gzip-TAR kind through extensionless nested spools' -ForEach @(
        @{ Name = 'nested_targz.zip' }, @{ Name = 'nested_targz.tar' }
    ) {
        $findings = RunMetadata $Name
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE' |
            Where-Object File -Match 'dependencies\.tar\.gz!Pillow-9\.5\.0\.dist-info/METADATA$').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR').Count | Should -Be 0
    }

    It 'parses every supported manifest family and reports non-exact declarations' {
        $budget = New-ArchiveMetadataBudget
        $findings = RunMetadata 'supported_manifests.zip' $budget
        $budget.Candidates | Should -Be 7
        $budget.Dependencies | Should -Be 8
        @($findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 2
        @($findings | Where-Object TestID -eq 'OSV-NUGET-UNPINNED').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').Count | Should -Be 7
    }

    It 'classifies the newly supported loose manifest names for the normal analyzer path' -ForEach @(
        @{ Name='requirements-prod.txt'; Type='python-requirements' },
        @{ Name='Pipfile.lock'; Type='python-requirements' },
        @{ Name='pyproject.toml'; Type='python-requirements' },
        @{ Name='poetry.lock'; Type='python-requirements' },
        @{ Name='uv.lock'; Type='python-requirements' },
        @{ Name='npm-shrinkwrap.json'; Type='npm' },
        @{ Name='Example.nuspec'; Type='nuget' }
    ) {
        $dir = Join-Path $script:Out "classify-$(Get-Random)"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $path = Join-Path $dir $Name
            Set-Content -LiteralPath $path -Value '' -Encoding utf8
            (New-Unit -File (Get-Item $path) -ScanRoot $dir).Unit.Type | Should -Be $Type
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not let ZIP magic under a .nuspec suffix take the NuGet semantic-container exception' {
        $file = Get-Item -LiteralPath (Join-Path $script:MetaDir 'renamed_archive.nuspec')
        $classified = New-Unit -File $file -ScanRoot $script:MetaDir
        $classified.Unit.Type | Should -Be 'archive'
        @($classified.Findings | Where-Object TestID -eq 'MTS-DISGUISE-001').Count | Should -Be 1
        Test-IsArchiveUnit -Unit $classified.Unit | Should -BeTrue
    }
}

Describe 'Shared pyproject parser - quoted dependency arrays' {
    It 'keeps quoted brackets, marker quotes and escaped quotes inside one requirement' -ForEach @(
        @{ Declaration = 'dependencies = ["requests[security]==2.31.0", "urllib3==1.26.5"]' },
        @{ Declaration = 'dependencies = [''requests[security]==2.31.0; python_version >= "3.8"'', ''urllib3==1.26.5'']' },
        @{ Declaration = 'dependencies = ["requests[security]==2.31.0; python_version >= \"3.8\"", "urllib3==1.26.5"]' }
    ) {
        $parsed = Convert-TomlLockMetadata -Text "[project]`n$Declaration" -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 2
        $parsed.Dependencies[0].Name | Should -Be 'requests'
        $parsed.Dependencies[0].Version | Should -Be '2.31.0'
        $parsed.Dependencies[1].Name | Should -Be 'urllib3'
        @($parsed.Findings).Count | Should -Be 0
    }

    It 'reports malformed or unsupported arrays instead of silently claiming coverage' -ForEach @(
        @{ Declaration = 'dependencies = ["requests[security]==2.31.0"' },
        @{ Declaration = 'dependencies = ["requests[security]==2.31.0]' },
        @{ Declaration = 'dependencies = ["requests==2.31.0" "urllib3==1.26.5"]' },
        @{ Declaration = 'dependencies = [123]' },
        @{ Declaration = 'dependencies = ["""requests==2.31.0"""]' }
    ) {
        $parsed = Convert-TomlLockMetadata -Text "[project]`n$Declaration" -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 1
    }

    It 'accepts an empty array and reports unpinned requirements with extras' {
        $parsed = Convert-TomlLockMetadata -Text "[project]`ndependencies = []" -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings).Count | Should -Be 0
        $parsed = Convert-TomlLockMetadata -Text ("[project]`n" + 'dependencies = ["requests[security]>=2"]') -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 1
    }

    It 'recognizes both canonical and distribution-named egg metadata' -ForEach @(
        @{ EntryName = 'EGG-INFO/PKG-INFO' },
        @{ EntryName = 'nested/egg-info/pkg-info' },
        @{ EntryName = 'Pillow.egg-info/PKG-INFO' }
    ) {
        Get-DependencyMetadataKind -EntryName $EntryName | Should -Be 'python-metadata'
    }
}

Describe 'OsvScan - normally extracted egg identity' {
    It 'selects OsvScan for package identities but not Python source variants' -ForEach @(
        @{ Name='example.py'; Type='python'; Expected=0 },
        @{ Name='notebook.ipynb'; Type='python'; Expected=0 },
        @{ Name='disguised.txt'; Type='python'; Expected=0 },
        @{ Name='Example.WHL'; Type='python'; Expected=1 },
        @{ Name='example.egg'; Type='python'; Expected=1 },
        @{ Name='requirements.txt'; Type='python-requirements'; Expected=1 },
        @{ Name='package-lock.json'; Type='npm'; Expected=1 },
        @{ Name='example.nuspec'; Type='nuget'; Expected=1 }
    ) {
        $analyzer = [PSCustomObject](& (Join-Path $script:Analyzers 'OsvScan.ps1'))
        $unit = [PSCustomObject]@{ Name=$Name; Type=$Type }
        @(Select-AnalyzersForUnit -Enabled @($analyzer) -Unit $unit).Count | Should -Be $Expected
    }

    It 'reports missing Python source coverage for loose files and archive members when only OsvScan is enabled' {
        $scanDir = Join-Path $TestDrive 'osv-only-source'
        New-Item -ItemType Directory -Path $scanDir | Out-Null
        Set-Content -LiteralPath (Join-Path $scanDir 'example.py') -Value 'print("fixture")'
        $zipPath = Join-Path $scanDir 'source.zip'
        $zip = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $zip.CreateEntry('nested.py')
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write('print("fixture")') } finally { $writer.Dispose() }
        } finally { $zip.Dispose() }
        $registry = @(Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers)
        $disabled = @($registry | Where-Object { $_.Name -notin @('OsvScan', 'FileHash') } | ForEach-Object Name)
        $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline -DisableAnalyzers $disabled
        $loose = $result.Units | Where-Object Name -eq 'example.py'
        @($loose.Findings | Where-Object TestID -eq 'MTS-NO-ANALYZER').Count | Should -Be 1
        $archive = $result.Units | Where-Object Name -eq 'source.zip'
        @($archive.Findings | Where-Object TestID -eq 'MTS-ARCHIVE-MEMBER-UNINSPECTED').Count | Should -Be 1
    }

    It 'retains package-identity coverage with only OsvScan enabled' {
        $scanDir = Join-Path $TestDrive 'osv-only-egg'
        New-Item -ItemType Directory -Path $scanDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'Pillow-9.5.0-py3.egg') -Destination $scanDir
        $registry = @(Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers)
        $disabled = @($registry | Where-Object { $_.Name -notin @('OsvScan', 'FileHash') } | ForEach-Object Name)
        $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline -DisableAnalyzers $disabled
        $unit = $result.Units | Select-Object -First 1
        @($unit.Findings | Where-Object TestID -eq 'MTS-NO-ANALYZER').Count | Should -Be 0
        @($unit.Findings | Where-Object TestID -eq 'OSV-PYPI-OFFLINE').Count | Should -Be 1
    }

    It 'submits the canonical egg identity to OSV after normal extraction' {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $stage = Join-Path $TestDrive 'egg-stage'
        [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $script:MetaDir 'Pillow-9.5.0-py3.egg'), $stage)
        $unit = (New-Unit -File (Get-Item (Join-Path $script:MetaDir 'Pillow-9.5.0-py3.egg')) -ScanRoot $script:MetaDir).Unit
        $unit.StagingPath = $stage
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        $findings = @(& $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' }))
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'pillow' -and $_.version -eq '9.5.0' }).Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-PYPI-AMBIGUOUS-METADATA').Count | Should -Be 0
    }

    It 'reports missing egg identity rather than using a vendored wheel identity' {
        Mock Invoke-OsvQueryBatch { throw 'No identity should be queried' }
        $stage = Join-Path $TestDrive 'egg-without-identity'
        $vendored = Join-Path $stage 'vendor/Other.dist-info'
        New-Item -ItemType Directory -Path $vendored -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $vendored 'METADATA') -Value "Name: Other`nVersion: 1.0"
        $unit = (New-Unit -File (Get-Item (Join-Path $script:MetaDir 'Pillow-9.5.0-py3.egg')) -ScanRoot $script:MetaDir).Unit
        $unit.StagingPath = $stage
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        $findings = @(& $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' }))
        @($findings | Where-Object TestID -eq 'OSV-PYPI-AMBIGUOUS-METADATA').Count | Should -Be 1
        Should -Invoke Invoke-OsvQueryBatch -Times 0
    }

    It 'uses the same extras-safe parser for a loose pyproject manifest' {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $manifest = Join-Path $TestDrive 'pyproject.toml'
        Set-Content -LiteralPath $manifest -Value '[project]','dependencies = ["requests[security]==2.31.0", "urllib3==1.26.5"]'
        $unit = (New-Unit -File (Get-Item $manifest) -ScanRoot $TestDrive).Unit
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        & $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' }) | Out-Null
        @($script:CapturedQueries).Count | Should -Be 2
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'requests' -and $_.version -eq '2.31.0' }).Count | Should -Be 1
    }
}

Describe 'TOML coverage - optional groups and mixed-validity locks' {
    It 'tracks optional tables and ignores dependency examples and unrelated tool tables' {
        $text = @'
[project]
description = """
[project.optional-dependencies]
fake = ["decoy==1.0"]
"""
dependencies = ["Pillow==9.5.0"]
[project.optional-dependencies] # actual optional groups
security = [
  "requests[security]==2.31.0", # ] not an array terminator
]
'docs' = ['urllib3==1.26.5; python_version >= "3.8"', "Sphinx>=7"]
[tool.example]
dependencies = ["not-a-project-dependency==1.0"]
other = ["also-not-a-dependency==2.0"]
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies.Name | Sort-Object) | Should -Be @('pillow', 'requests', 'urllib3')
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 1
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 0
    }

    It 'accepts quoted optional table names and group keys' {
        $text = @'
["project" . 'optional-dependencies']
"security-extra" = ["requests[security]==2.31.0"]
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 1
        $parsed.Dependencies[0].Name | Should -Be 'requests'
    }

    It 'does not lose real declarations after a quoted multiline-string terminator' {
        $text = @'
[project]
description = """Example ending in a quoted word: "word""""
dependencies = ["Pillow==9.5.0"]
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 1
        @($parsed.Findings).Count | Should -Be 0
    }

    It 'reports a truncated description that would hide later optional groups' {
        $text = @'
[project]
description = """unfinished
[project.optional-dependencies]
security = ["requests==2.31.0"]
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 1
    }

    It 'reports an optional group that is not a string array while preserving later valid groups' {
        $text = @'
[project.optional-dependencies]
bad = { version = "1" }
good = ["Pillow==9.5.0"]
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'pyproject.toml' -UnitType python-requirements -Kind pyproject
        @($parsed.Dependencies).Count | Should -Be 1
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 1
    }

    It 'reports each malformed package block while retaining valid blocks' -ForEach @(
        @{ Kind='poetry-lock'; File='poetry.lock' }, @{ Kind='uv-lock'; File='uv.lock' }
    ) {
        $text = @'
[[package]]
name = "missing-version"
[[package]]
name = "Pillow"
version = "9.5.0"
[[package]]
version = "1.0"
'@
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile $File -UnitType python-requirements -Kind $Kind
        @($parsed.Dependencies).Count | Should -Be 1
        $parsed.Dependencies[0].Name | Should -Be 'pillow'
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 2
    }

    It 'preserves every missing-block warning when all package blocks are invalid' -ForEach @(
        @{ Kind='poetry-lock' }, @{ Kind='uv-lock' }
    ) {
        $text = "[[package]]`nname = 'missing-version'`n[[package]]`nversion = '1.0'"
        $parsed = Convert-TomlLockMetadata -Text $text -ManifestFile 'lock' -UnitType python-requirements -Kind $Kind
        @($parsed.Dependencies).Count | Should -Be 0
        @($parsed.Findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 2
    }

    It 'queries optional-only dependencies and reports incomplete locks inside a blocked archive' {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $findings = RunMetadata 'optional_and_mixed_locks.zip' (New-ArchiveMetadataBudget) 'online'
        @($script:CapturedQueries | Where-Object { $_.package.name -eq 'requests' -and $_.version -eq '2.31.0' }).Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be 4
        @($findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 1
    }

    It 'uses the same TOML coverage rules on normal loose manifests' -ForEach @(
        @{ File='pyproject.toml'; Name='requests'; Malformed=0 },
        @{ File='poetry.lock'; Name='pillow'; Malformed=2 },
        @{ File='uv.lock'; Name='pillow'; Malformed=2 }
    ) {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $stage = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $script:MetaDir 'optional_and_mixed_locks.zip'), $stage)
        $unit = (New-Unit -File (Get-Item (Join-Path $stage $File)) -ScanRoot $stage).Unit
        $analyzer = & (Join-Path $script:Analyzers 'OsvScan.ps1')
        $findings = @(& $analyzer.Invoke $unit ([PSCustomObject]@{ Mode='online' }))
        @($script:CapturedQueries | Where-Object { $_.package.name -eq $Name }).Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-PYPI-MALFORMED').Count | Should -Be $Malformed
    }
}

Describe 'Archive metadata fallback - fail-closed limits and malformed containers' {
    It 'bounds dependency and diagnostic creation inside every manifest parser' -ForEach @(
        @{ Kind='requirements'; Text="first==1`nsecond`nthird==3`nfourth" },
        @{ Kind='npm-lock'; Text='{"packages":{"node_modules/a":{"version":"1"},"node_modules/b":{"version":"2"},"node_modules/c":{"version":"3"}}}' },
        @{ Kind='pipfile-lock'; Text='{"default":{"a":"==1","b":"*"},"develop":{"c":"==3"}}' },
        @{ Kind='python-metadata'; Text="Name: Example`nVersion: 1`nRequires-Dist: a (>=1)`nRequires-Dist: b (==2)" },
        @{ Kind='nuspec'; Text='<package><metadata><id>Example</id><version>1</version><dependencies><dependency id="a" version="[1,2)"/><dependency id="b" version="[2]"/></dependencies></metadata></package>' },
        @{ Kind='pyproject'; Text="[project]`ndependencies = ['a==1','b>=2','c==3']" },
        @{ Kind='poetry-lock'; Text="[[package]]`nname = 'a'`nversion = '1'`n[[package]]`nname = 'bad'`n[[package]]`nname = 'c'`nversion = '3'" },
        @{ Kind='uv-lock'; Text="[[package]]`nname = 'a'`nversion = '1'`n[[package]]`nname = 'bad'`n[[package]]`nname = 'c'`nversion = '3'" }
    ) {
        $parsed = Convert-DependencyMetadataContent -Kind $Kind -Bytes ([Text.Encoding]::UTF8.GetBytes($Text)) -ManifestFile 'fixture' -MaxRecords 2
        $parsed.RecordCount | Should -Be 2
        $parsed.LimitReached | Should -BeTrue
        (@($parsed.Dependencies).Count + @($parsed.Findings).Count) | Should -Be 3 # two records + one limit diagnostic
        @($parsed.Findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT').Count | Should -Be 1
    }

    It 'does not allocate unbounded findings from dense unpinned manifests across sibling archives' {
        $budget = New-ArchiveMetadataBudget
        $budget.MaxDependencies = 7
        $findings = RunMetadata 'dense_requirements.zip' $budget
        @($findings | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 7
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT').Count | Should -Be 1
        $budget.ParseRecords | Should -Be 7
        $budget.Dependencies | Should -Be 0
        Mock Convert-DependencyMetadataContent { throw 'An exhausted record budget must not parse again' }
        $later = RunMetadata 'dense_requirements.zip' $budget
        @($later | Where-Object TestID -eq 'OSV-PYPI-UNPINNED').Count | Should -Be 0
        @($later | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT').Count | Should -Be 1
        Should -Invoke Convert-DependencyMetadataContent -Times 0
        $budget.ParseRecords | Should -Be 7
    }

    It 'caps ordinary manifest parsing by default, not only archive fallbacks' {
        $text = "unpinned`n" * 10000
        $parsed = Convert-DependencyMetadataContent -Kind requirements -Bytes ([Text.Encoding]::UTF8.GetBytes($text)) -ManifestFile 'requirements.txt'
        $parsed.RecordCount | Should -Be 5000
        @($parsed.Findings).Count | Should -Be 5001
        $parsed.LimitReached | Should -BeTrue
    }

    It 'skips duplicate manifest names instead of trusting a decoy' {
        $budget = New-ArchiveMetadataBudget
        $findings = RunMetadata 'duplicate_metadata.zip' $budget
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR' | Where-Object Issue -Match 'duplicate').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 0
        $budget.Dependencies | Should -Be 0
    }

    It 'refuses traversal-named metadata even though no extraction is attempted' {
        $findings = RunMetadata 'traversal_metadata.zip'
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR' | Where-Object Issue -Match 'path-traversal').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 0
    }

    It 'never follows ZIP symlinks or TAR special entries that look like manifests' -ForEach @(
        @{ Name='symlink_metadata.zip'; Expected='symlink' },
        @{ Name='special_metadata.tar'; Expected='SymbolicLink' }
    ) {
        $findings = RunMetadata $Name
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR' |
            Where-Object Issue -Match $Expected).Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 0
    }

    It 'reports encrypted ZIP metadata explicitly without trying to read it' {
        $findings = RunMetadata 'encrypted_metadata.zip'
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR' |
            Where-Object Issue -Match 'encrypted ZIP entry').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 0
    }

    It 'reports oversized metadata as an explicit limit, never partial success' {
        $findings = RunMetadata 'oversized_metadata.zip'
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT').Count | Should -BeGreaterThan 0
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 0
    }

    It 'reports a corrupt archive as an explicit metadata error' {
        $findings = RunMetadata 'corrupt.zip'
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-ERROR').Count | Should -Be 1
    }

    It 'enforces the entry-count cap before candidate processing can grow unbounded' {
        $budget = New-ArchiveMetadataBudget; $budget.MaxEntries = 1
        $findings = RunMetadata 'supported_manifests.zip' $budget
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT' | Where-Object Issue -Match 'entry cap').Count | Should -Be 1
        $budget.Entries | Should -Be 1
    }

    It 'enforces a deterministic processing-time cap' {
        $budget = New-ArchiveMetadataBudget; $budget.MaxMilliseconds = 0
        $findings = RunMetadata 'supported_manifests.zip' $budget
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT' | Where-Object Issue -Match 'processing-time').Count | Should -BeGreaterThan 0
    }

    It 'shares the candidate budget across sibling blocked archives' {
        $budget = New-ArchiveMetadataBudget; $budget.MaxCandidates = 1
        RunMetadata 'metadata.tar' $budget | Out-Null
        $second = RunMetadata 'metadata.tgz' $budget
        $budget.Candidates | Should -Be 1
        @($second | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT' | Where-Object Issue -Match 'candidate cap').Count | Should -Be 1
    }

    It 'continues past a candidate that cannot fit the remaining decoded-byte budget' -ForEach @(
        @{ Name = 'decoded_skip.zip' }, @{ Name = 'decoded_skip.tar' }
    ) {
        $budget = New-ArchiveMetadataBudget; $budget.MaxDecodedBytes = 32
        $findings = RunMetadata $Name $budget
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-LIMIT' |
            Where-Object Issue -Match 'decoded metadata byte cap').Count | Should -Be 1
        $budget.Candidates | Should -Be 1
        $budget.Dependencies | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE' |
            Where-Object File -Match 'requirements-z\.txt$').Count | Should -Be 1
    }

    It 'charges bytes incrementally and deletes a rejected nested spool' {
        $budget = New-ArchiveMetadataBudget
        $destination = Join-Path $script:Out "failed-spool-$(Get-Random)"
        $bytes = [Text.Encoding]::UTF8.GetBytes('truncated-stream')
        $stream = [IO.MemoryStream]::new($bytes, $false)
        try {
            { Save-ArchiveMetadataNestedStream -Stream $stream -Destination $destination `
                    -Length ($bytes.LongLength + 10) -Budget $budget } | Should -Throw '*was truncated*'
            $budget.TempBytes | Should -Be $bytes.LongLength
            Test-Path -LiteralPath $destination | Should -BeFalse
        } finally {
            $stream.Dispose()
            [IO.File]::Delete($destination)
        }
    }

    It 'accepts a valid nested spool that exactly fills the temporary-byte budget' {
        $bytes = [Text.Encoding]::UTF8.GetBytes('exact-budget')
        $budget = New-ArchiveMetadataBudget; $budget.MaxTempBytes = $bytes.LongLength
        $destination = Join-Path $script:Out "exact-spool-$(Get-Random)"
        $stream = [IO.MemoryStream]::new($bytes, $false)
        try {
            Save-ArchiveMetadataNestedStream -Stream $stream -Destination $destination `
                -Length $bytes.LongLength -Budget $budget | Should -Be $bytes.LongLength
            $budget.TempBytes | Should -Be $bytes.LongLength
            Test-Path -LiteralPath $destination | Should -BeTrue
        } finally {
            $stream.Dispose()
            [IO.File]::Delete($destination)
        }
    }

    It 'charges actual decoded bytes when a stream exceeds the remaining scan-wide budget' {
        $bytes = [Text.Encoding]::UTF8.GetBytes('lying-stream-payload')
        $budget = New-ArchiveMetadataBudget; $budget.MaxDecodedBytes = 8
        $stream = [IO.MemoryStream]::new($bytes, $false)
        try {
            { Read-ArchiveMetadataStreamBytes -Stream $stream -Limit 64 -Budget $budget } |
                Should -Throw '*decoded metadata byte budget*'
            $budget.DecodedBytes | Should -Be 8
        } finally { $stream.Dispose() }
    }

    It 'removes every dedicated nested-container spool directory' {
        $before = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'mts-metadata-*' -ErrorAction SilentlyContinue).Count
        RunMetadata 'nested_vulnerable_wheel.zip' | Out-Null
        $after = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'mts-metadata-*' -ErrorAction SilentlyContinue).Count
        $after | Should -Be $before
    }
}

Describe 'Archive metadata fallback - engine integration' {
    It 'recovers metadata after streaming TAR stops without re-auditing the staged prefix' -ForEach @(
        @{ Name='stopped_metadata.tgz'; Members=1; Bytes=1GB; Partial=1 },
        @{ Name='stopped_metadata.tgz'; Members=5000; Bytes=40; Partial=1 },
        @{ Name='nested_stopped_tar.zip'; Members=2; Bytes=1GB; Partial=1 },
        @{ Name='stopped_nested_wheel.tgz'; Members=1; Bytes=1GB; Partial=2 }
    ) {
        $script:CapturedQueries = @()
        Mock Invoke-OsvQueryBatch {
            param($Queries, $TimeoutSec)
            $script:CapturedQueries += @($Queries)
            @($Queries | ForEach-Object { [PSCustomObject]@{} })
        }
        $scanDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $scanDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir $Name) -Destination $scanDir
        $oldBytes = $script:ArchiveTreeMaxBytes
        $oldMembers = $script:ArchiveTreeMaxMembers
        $oldHeadroom = $script:ArchiveTreeSafeHeadroomBytes
        try {
            $script:ArchiveTreeMaxBytes = $Bytes
            $script:ArchiveTreeMaxMembers = $Members
            $script:ArchiveTreeSafeHeadroomBytes = 0
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode online
            $findings = @($result.Units | ForEach-Object { $_.Findings })
            @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED').Count | Should -BeGreaterThan 0
            @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be $Partial
            @($script:CapturedQueries | Where-Object { $_.package.name -eq 'pillow' }).Count | Should -Be 1
            @($script:CapturedQueries | Where-Object { $_.package.name -eq 'urllib3' }).Count | Should -Be 1
            if ($Name -eq 'stopped_nested_wheel.tgz') {
                @($script:CapturedQueries | Where-Object { $_.package.name -eq 'requests' }).Count | Should -Be 1
            }
            @($findings | Where-Object TestID -eq 'MTS-ANALYZER-ERR').Count | Should -Be 0
        } finally {
            $script:ArchiveTreeMaxBytes = $oldBytes
            $script:ArchiveTreeMaxMembers = $oldMembers
            $script:ArchiveTreeSafeHeadroomBytes = $oldHeadroom
        }
    }

    It 'does not recover stopped-TAR metadata when OsvScan is disabled' {
        $scanDir = Join-Path $TestDrive 'disabled-stopped-tar'
        New-Item -ItemType Directory -Path $scanDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'stopped_metadata.tgz') -Destination $scanDir
        $oldMembers = $script:ArchiveTreeMaxMembers
        try {
            $script:ArchiveTreeMaxMembers = 1
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline -DisableAnalyzers OsvScan
            $findings = @($result.Units | ForEach-Object { $_.Findings })
            @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED').Count | Should -Be 1
            @($findings | Where-Object TestID -like 'MTS-ARCHIVE-METADATA-*').Count | Should -Be 0
        } finally { $script:ArchiveTreeMaxMembers = $oldMembers }
    }

    It 'does not run metadata recovery after a hard TAR traversal rejection' {
        Mock Invoke-OsvQueryBatch { throw 'A hard-rejected TAR must not be audited' }
        $scanDir = Join-Path $TestDrive 'hard-rejected-tar'
        New-Item -ItemType Directory -Path $scanDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'rejected_metadata.tgz') -Destination $scanDir
        $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode online
        $findings = @($result.Units | ForEach-Object { $_.Findings })
        @($findings | Where-Object TestID -eq 'MTS-EXTRACT-TRAVERSAL').Count | Should -Be 1
        @($findings | Where-Object TestID -like 'MTS-ARCHIVE-METADATA-*').Count | Should -Be 0
        Should -Invoke Invoke-OsvQueryBatch -Times 0
    }

    It 'does not stage a bare gzip stream that is not a TAR container' {
        $file = Get-Item -LiteralPath (Join-Path $script:MetaDir 'bare_payload.gz')
        $unit = (New-Unit -File $file -ScanRoot $script:MetaDir).Unit
        $unit.Type | Should -Be 'archive'
        Test-IsArchiveUnit -Unit $unit | Should -BeFalse

        $budget = New-ArchiveTreeBudget
        $context = [PSCustomObject]@{ WorkDir = $script:Out }
        $expanded = Expand-UnitInPlace -Unit $unit -Context $context -Budget $budget
        $expanded.IsArchive | Should -BeFalse
        $budget.NextStageIndex | Should -Be 0

        $directOutput = Join-Path $script:Out "bare-gzip-$(Get-Random)"
        $direct = Expand-SubmissionArchive -InputFile $file.FullName -OutputDir $directOutput
        $direct.Success | Should -BeFalse
        Test-Path -LiteralPath $directOutput | Should -BeFalse
    }

    It 'member-dispatches ZIP payloads renamed with a .nuspec suffix' {
        $scanDir = Join-Path $script:Out "renamed-nuspec-$(Get-Random)"
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'renamed_archive.nuspec') -Destination $scanDir
        try {
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers `
                -ReportsDir $script:Out -Mode offline
            $unit = $result.Units | Select-Object -First 1
            $unit.Type | Should -Be 'archive'
            @($unit.Findings | Where-Object TestID -eq 'MTS-DISGUISE-001').Count | Should -Be 1
            @($unit.Findings | Where-Object TestID -eq 'SHELL-REMOTE-EXEC' |
                Where-Object File -Match 'renamed_archive\.nuspec!payload[\\/]risky\.sh$').Count | Should -BeGreaterThan 0
        } finally { Remove-Item -LiteralPath $scanDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'runs after a top-level archive is budget-blocked and never invokes normal extraction' {
        $scanDir = Join-Path $script:Out "blocked-$(Get-Random)"
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'nested_vulnerable_wheel.zip') -Destination $scanDir
        $oldBytes = $script:ArchiveTreeMaxBytes
        try {
            $script:ArchiveTreeMaxBytes = 0
            Mock Expand-SubmissionArchive { throw 'normal extraction must not run' }
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers `
                -ReportsDir $script:Out -Mode offline
            $unit = $result.Units | Select-Object -First 1
            @($unit.Findings | Where-Object TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED').Count | Should -Be 1
            @($unit.Findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
            Should -Invoke Expand-SubmissionArchive -Times 0
        } finally {
            $script:ArchiveTreeMaxBytes = $oldBytes
            Remove-Item -LiteralPath $scanDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not run the fallback when OsvScan is disabled' {
        $scanDir = Join-Path $script:Out "disabled-$(Get-Random)"
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'nested_vulnerable_wheel.zip') -Destination $scanDir
        $oldBytes = $script:ArchiveTreeMaxBytes
        try {
            $script:ArchiveTreeMaxBytes = 0
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers `
                -ReportsDir $script:Out -Mode offline -DisableAnalyzers OsvScan
            $unit = $result.Units | Select-Object -First 1
            @($unit.Findings | Where-Object TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED').Count | Should -Be 1
            @($unit.Findings | Where-Object TestID -Like 'MTS-ARCHIVE-METADATA-*').Count | Should -Be 0
        } finally {
            $script:ArchiveTreeMaxBytes = $oldBytes
            Remove-Item -LiteralPath $scanDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }


    It 'runs for a nested wheel refused by the semantic-container budget gate' {
        $scanDir = Join-Path $script:Out "nested-blocked-$(Get-Random)"
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:MetaDir 'nested_budget_blocked_wheel.zip') -Destination $scanDir
        $oldBytes = $script:ArchiveTreeMaxBytes
        try {
            $script:ArchiveTreeMaxBytes = 100KB
            $result = Invoke-Scan -Path $scanDir -Profile core -AnalyzerDir $script:Analyzers `
                -ReportsDir $script:Out -Mode offline
            $unit = $result.Units | Select-Object -First 1
            $blocked = @($unit.Findings | Where-Object {
                $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.File -match '\.whl$' })
            $blocked.Count | Should -Be 1
            @($unit.Findings | Where-Object {
                $_.TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL' -and $_.File -match '\.whl$' }).Count | Should -Be 1
            @($unit.Findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE' |
                Where-Object File -Match '\.whl!Pillow-9\.5\.0\.dist-info/METADATA$').Count | Should -Be 1
        } finally {
            $script:ArchiveTreeMaxBytes = $oldBytes
            Remove-Item -LiteralPath $scanDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
