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
    It 'reads METADATA from both compressed and uncompressed tar archives' -ForEach @(
        @{ Name = 'metadata.tgz' }, @{ Name = 'metadata.tar' }
    ) {
        $findings = RunMetadata $Name
        @($findings | Where-Object TestID -eq 'MTS-ARCHIVE-METADATA-PARTIAL').Count | Should -Be 1
        @($findings | Where-Object TestID -eq 'OSV-ARCHIVE-METADATA-OFFLINE').Count | Should -Be 1
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
}

Describe 'Archive metadata fallback - fail-closed limits and malformed containers' {
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

    It 'removes every dedicated nested-container spool directory' {
        $before = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'mts-metadata-*' -ErrorAction SilentlyContinue).Count
        RunMetadata 'nested_vulnerable_wheel.zip' | Out-Null
        $after = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'mts-metadata-*' -ErrorAction SilentlyContinue).Count
        $after | Should -Be $before
    }
}

Describe 'Archive metadata fallback - engine integration' {
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
