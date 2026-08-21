#Requires -Version 7.4
<#
    Pester 5 tests for scan-root path resolution (issue #27).

    Resolve-Path's .Path on a UNC root returns a provider-qualified string
    ('Microsoft.PowerShell.Core\FileSystem::\\server\share\...'), which is longer
    than the plain FullName of the files underneath it — the old length-based
    Substring in Classify.ps1 then threw. The engine now uses .ProviderPath, and
    the relative path is computed with [IO.Path]::GetRelativePath.

    UNC coverage uses the local admin share (\\localhost\C$), which is not
    reachable everywhere (non-elevated sessions, TEMP on a non-shared drive, some
    CI images). Rather than skip silently — a green run that guards nothing — the
    skip announces itself as a warning, and setting MTS_REQUIRE_UNC_TESTS=1 turns
    an unreachable share into a hard failure for environments where the coverage
    is expected to run.

    The 'Source guard' block needs no UNC path at all: it fails if the
    .Path/.ProviderPath regression is reintroduced anywhere in shipped source, so
    the regression stays guarded even where the UNC cases cannot run.
#>

BeforeDiscovery {
    # Discovery phase, NOT BeforeAll: -Skip is evaluated while Pester is building
    # the test tree, so a value set in BeforeAll would still be $null here and the
    # UNC cases would run (and fail on a null path) instead of skipping.
    $script:UncRoot       = $null
    $script:UncSkipReason = $null

    if ($env:TEMP -match '^([A-Za-z]):\\') {
        $driveLetter = $Matches[1]
        $candidate   = "\\localhost\$driveLetter`$"
        if (Test-Path -LiteralPath $candidate -PathType Container -ErrorAction SilentlyContinue) {
            $script:UncRoot = $candidate
        } else {
            $script:UncSkipReason = "admin share '$candidate' is not reachable (needs an elevated session)"
        }
    } else {
        $script:UncSkipReason = "TEMP ('$env:TEMP') is not on a drive letter, so no admin-share path can be derived"
    }

    $script:SkipUnc = -not $script:UncRoot

    if ($script:SkipUnc) {
        $msg = "UNC coverage for issue #27 is NOT running: $script:UncSkipReason. " +
               'The local cases and the source guard still run. Set MTS_REQUIRE_UNC_TESTS=1 to make this a failure.'
        Write-Warning $msg
        if ($env:MTS_REQUIRE_UNC_TESTS -in @('1', 'true', 'yes')) {
            throw "MTS_REQUIRE_UNC_TESTS is set but $script:UncSkipReason"
        }
    }
}

BeforeAll {
    $script:Root  = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet = $true

    $script:Work = Join-Path $env:TEMP "mts-path-$(Get-Random)"
    New-Item -ItemType Directory -Path (Join-Path $script:Work 'nested/deeper') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:Work 'top.txt')             -Value 'top'
    Set-Content -LiteralPath (Join-Path $script:Work 'nested/deeper/x.txt') -Value 'deep'

    # UNC view of $script:Work via the same admin share the discovery probe found.
    $script:Unc = $null
    if ($script:Work -match '^([A-Za-z]):\\(.*)$') {
        $candidate = "\\localhost\$($Matches[1])`$\$($Matches[2])"
        if (Test-Path -LiteralPath $candidate -PathType Container -ErrorAction SilentlyContinue) {
            $script:Unc = $candidate
        }
    }

    $script:ExpectedRel = Join-Path 'nested' (Join-Path 'deeper' 'x.txt')
}
AfterAll { Remove-Item $script:Work -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'New-Unit relative paths' {
    It 'computes a nested relative path from a local root' {
        $f = Get-Item (Join-Path $script:Work 'nested/deeper/x.txt')
        (New-Unit -File $f -ScanRoot $script:Work).Unit.RelativePath | Should -Be $script:ExpectedRel
    }
    It 'is unaffected by a trailing separator on the root' {
        $f = Get-Item (Join-Path $script:Work 'top.txt')
        (New-Unit -File $f -ScanRoot ($script:Work + '\')).Unit.RelativePath | Should -Be 'top.txt'
    }
    It 'computes a relative path from a UNC root without throwing' -Skip:$script:SkipUnc {
        $f = Get-Item -LiteralPath (Join-Path $script:Unc 'nested/deeper/x.txt')
        (New-Unit -File $f -ScanRoot $script:Unc).Unit.RelativePath | Should -Be $script:ExpectedRel
    }
}

Describe 'Scan-root resolution' {
    It 'strips the PowerShell provider prefix from a UNC root' -Skip:$script:SkipUnc {
        $resolved = (Resolve-Path -LiteralPath $script:Unc).ProviderPath
        $resolved | Should -Not -Match 'FileSystem::'
        $resolved | Should -BeLike '\\*'
    }
    It 'scans a UNC root end to end' -Skip:$script:SkipUnc {
        $out = Join-Path $env:TEMP "mts-path-out-$(Get-Random)"
        try {
            $r = Invoke-Scan -Path $script:Unc -Profile core `
                    -AnalyzerDir (Join-Path $script:Root 'src/analyzers') `
                    -ReportsDir $out -Mode offline
            $r.ScanRoot       | Should -Not -Match 'FileSystem::'
            @($r.Units).Count | Should -BeGreaterThan 0
            # Result units expose the scan-root-relative path as .Path
            @($r.Units | Where-Object { $_.Path -eq $script:ExpectedRel }).Count | Should -Be 1
        } finally { Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Source guard — provider-qualified path regressions' {
    <#
        Issue #27 was caused by two Resolve-Path call sites drifting: fixing only
        the entry point left Invoke-Scan re-resolving and re-adding the prefix. A
        third site added later would reintroduce it. This guard is environment-
        independent — it runs everywhere the UNC cases cannot.
    #>
    It 'uses no Resolve-Path ... .Path in shipped source' {
        $searchRoots = @('src', 'bundle') |
            ForEach-Object { Join-Path $script:Root $_ } |
            Where-Object   { Test-Path -LiteralPath $_ }

        $offenders = foreach ($dir in $searchRoots) {
            Get-ChildItem -LiteralPath $dir -Recurse -File -Filter *.ps1 -ErrorAction SilentlyContinue |
                # The vendored venv ships its own scripts — not ours to police.
                Where-Object { $_.FullName -notmatch '[\\/]\.scan-venv[\\/]' } |
                ForEach-Object {
                    $file = $_
                    $n = 0
                    foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
                        $n++
                        if ($line -match 'Resolve-Path' -and $line -match '\)\s*\.Path\b') {
                            '{0}:{1}: {2}' -f $file.Name, $n, $line.Trim()
                        }
                    }
                }
        }

        $offenders | Should -BeNullOrEmpty -Because @'
Resolve-Path returns a provider-qualified string (Microsoft.PowerShell.Core\FileSystem::\\server\share\...)
for a UNC root, which breaks any path arithmetic downstream (issue #27). Use .ProviderPath instead of .Path
'@
    }

    It 'finds the guard is actually capable of failing' {
        # Guards the guard: a regex that silently matches nothing would make the
        # test above pass forever. Prove it fires on a known-bad line.
        $bad = '    $scanRoot = (Resolve-Path -LiteralPath $Path).Path'
        ($bad -match 'Resolve-Path' -and $bad -match '\)\s*\.Path\b') | Should -BeTrue
    }
}
