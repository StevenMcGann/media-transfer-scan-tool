#Requires -Version 7.4
<#
    Pester 5 tests for recursive archive-member dispatch (issue #31): a
    generic 'archive' unit's extracted members are classified by content
    (New-Unit, reused as-is — catches disguised scripts for free) and
    dispatched through the normal analyzer set, with findings folded back
    onto the PARENT archive under the existing 'archive!inner/path' label —
    never added as new top-level Units. Semantic containers (wheels/eggs,
    .nupkg, PyTorch .pt/.pth) are extracted the same way but are NOT
    member-dispatched; see the zero-false-coverage-warning tests below and
    the Engine.ps1 header comment for the full design.

    All offline — no network, no tool provisioning needed (ShellCheck/
    PSScriptAnalyzer's OWN pure-PowerShell pattern layers fire without their
    external tool installed, same as every other offline archive/shell/
    powershell test in this suite).
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:Corpus    = Join-Path $PSScriptRoot 'fixtures/corpus'
    $script:ArcMemDir = Join-Path $script:Corpus 'archive_member'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-arcmem-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:ScanDir($RelPath, [string[]]$DisableAnalyzers = @()) {
        Invoke-Scan -Path (Join-Path $script:Corpus $RelPath) -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline `
            -DisableAnalyzers $DisableAnalyzers
    }
    function script:AllFindings($Result) {
        @($Result.Units | ForEach-Object { $_.Findings } | Where-Object { $_ })
    }
    # Archive-member File labels use the OS-native path separator (consistent
    # with GetRelativePath elsewhere in the engine — never forced to '/').
    $script:S = [IO.Path]::DirectorySeparatorChar

    # One shared baseline scan of the whole archive_member corpus (ShellCheck
    # etc. enabled, default profile) — most tests just select the unit/findings
    # they need from it. Tests needing a DIFFERENT -DisableAnalyzers or a
    # direct Invoke-ArchiveMemberDispatch call run their own scan/call.
    $script:R = Invoke-Scan -Path $script:ArcMemDir -Profile core `
        -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    function script:UnitOf([string]$Name) { $script:R.Units | Where-Object { $_.Name -eq $Name } }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

# ─────────────────────────────────────────────────────────────────────────────
Describe 'Archive-member dispatch — unit-count and schema preservation' {
    It 'does not add extracted archive members as top-level Units' {
        # Six fixture zips in archive_member/, several with 2+ members each —
        # the Units array must still have exactly one entry per SUBMITTED file.
        $R.Units.Count | Should -Be 6
        @($R.Units | Where-Object { $_.Name -match '\.(sh|js|py|txt|json|pkl)$' }).Count | Should -Be 0
    }

    It 'folds member findings onto the parent archive using the archive!inner/path label' {
        $u = UnitOf 'disguised_and_scripts.zip'
        $u | Should -Not -BeNullOrEmpty
        @($u.Findings | Where-Object { $_.File -eq "disguised_and_scripts.zip!scripts${S}tool.sh" }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Archive-member dispatch — disguised script inside a zip' {
    It 'content-classifies payload.txt (no shebang, innocent extension) and flags the disguise' {
        $u = UnitOf 'disguised_and_scripts.zip'
        $disguise = @($u.Findings | Where-Object {
            $_.TestID -eq 'MTS-DISGUISE-002' -and $_.File -eq "disguised_and_scripts.zip!notes${S}payload.txt" })
        $disguise.Count | Should -Be 1
        $disguise[0].Severity | Should -Be 'HIGH'   # innocent .txt hiding a script — same rule as top-level disguise fixtures
    }

    It 'also flags the real remote-fetch-and-execute shell script in the same archive' {
        $u = UnitOf 'disguised_and_scripts.zip'
        @($u.Findings | Where-Object {
            $_.TestID -eq 'SHELL-REMOTE-EXEC' -and $_.File -eq "disguised_and_scripts.zip!scripts${S}tool.sh" }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Archive-member dispatch — JS with no package.json' {
    It 'scans a .js member for risky patterns without requiring a manifest' {
        $u = UnitOf 'js_no_pkg.zip'
        $u | Should -Not -BeNullOrEmpty
        @($u.Findings | Where-Object { $_.TestID -eq 'NPM-LIFECYCLE-SCRIPT' }).Count | Should -Be 0   # no package.json exists
        @($u.Findings | Where-Object {
            $_.TestID -eq 'NPM-JS-CHILD-PROCESS' -and $_.File -eq 'js_no_pkg.zip!app.js' }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Archive-member dispatch — nested archive within limits' {
    It 'opens and scans a nested archive''s content (two levels deep), not just flags the nesting' {
        $u = UnitOf 'two_level_nested.zip'
        $u | Should -Not -BeNullOrEmpty
        $hit = @($u.Findings | Where-Object { $_.TestID -eq 'SHELL-B64-EXEC' })
        $hit.Count | Should -Be 1
        $hit[0].File | Should -Be "two_level_nested.zip!inner.zip!deep${S}risky.sh"
    }

    It 'still flags decompression-bomb/zip-slip/symlink hazards for a NESTED extraction, not just the top level' {
        $u = UnitOf 'nested_bomb.zip'
        $bomb = @($u.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-BOMB' })
        $bomb.Count | Should -Be 1
        $bomb[0].File | Should -Match '^nested_bomb\.zip!inner_bomb\.zip'
    }
}

Describe 'Archive-member dispatch — depth cap and cumulative budget (direct)' {
    BeforeAll {
        $script:StageOut = Join-Path $env:TEMP "mts-arcmem-stage-$(Get-Random)"
        $script:Extraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'no_dupes.zip') -OutputDir $script:StageOut
        $script:NestedStageOut = Join-Path $env:TEMP "mts-arcmem-nested-stage-$(Get-Random)"
        $script:NestedExtraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'two_level_nested.zip') -OutputDir $script:NestedStageOut
        $script:TestContext = [PSCustomObject]@{
            Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $env:TEMP
            ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
        }
        $script:TestEnabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) |
            Where-Object { $_.DefaultEnabled })
    }
    AfterAll {
        Remove-Item $script:StageOut -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $script:NestedStageOut -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'does not open a nested archive past the depth cap' {
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'no_dupes.zip'; Path = 'no_dupes.zip'
                                    RelativePath = 'no_dupes.zip'; StagingPath = $script:Extraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth ($budget.MaxDepth + 1)
        @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-DEPTH-CAP' }).Count | Should -Be 1
        # Nothing was opened at all -- no member findings of any kind.
        @($findings | Where-Object { $_.TestID -ne 'MTS-ARCHIVE-DEPTH-CAP' }).Count | Should -Be 0
    }

    It 'stops and reports skipped members once the shared cumulative budget is exhausted' {
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'no_dupes.zip'; Path = 'no_dupes.zip'
                                    RelativePath = 'no_dupes.zip'; StagingPath = $script:Extraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        $budget.MaxMembers = 1   # no_dupes.zip has 2 members -- only the first is processed
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth 1
        $exceeded = @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' })
        $exceeded.Count | Should -Be 1
        $exceeded[0].Issue | Should -Match '1 member'
        $budget.MemberCount | Should -Be 1
    }

    It 'is a SHARED budget across sibling top-level archives, not reset per archive' {
        # Two archives dispatched with the SAME $Budget object must share one
        # cumulative counter -- an attacker cannot bypass the cap by splitting
        # content across many individually-small archives. no_dupes.zip has
        # exactly 2 members, so MaxMembers=2 lets the FIRST archive exactly
        # exhaust the shared budget without tripping its own exceeded note.
        $budget = New-ArchiveTreeBudget
        $budget.MaxMembers = 2
        $unit1 = [PSCustomObject]@{ Type = 'archive'; Name = 'a.zip'; Path = 'a.zip'
                                     RelativePath = 'a.zip'; StagingPath = $script:Extraction.StagingPath }
        $unit2 = [PSCustomObject]@{ Type = 'archive'; Name = 'b.zip'; Path = 'b.zip'
                                     RelativePath = 'b.zip'; StagingPath = $script:Extraction.StagingPath }
        $f1 = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit1 -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth 1
        $f2 = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit2 -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth 1
        # First archive consumes the whole shared budget (its own 2 members);
        # the second gets NOTHING processed and its own budget-exceeded note
        # naming both of ITS members as skipped.
        @($f1 | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
        $secondExceeded = @($f2 | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' })
        $secondExceeded.Count | Should -Be 1
        $secondExceeded[0].Issue | Should -Match '2 member'
        $budget.MemberCount | Should -Be 2   # unchanged by unit2 -- nothing more was ever counted
    }

    It 'checks the depth cap BEFORE extraction, not after (review follow-up)' {
        # two_level_nested.zip = outer.zip{inner.zip{deep/risky.sh}} -- two real
        # levels. MaxDepth=1 means recursing into inner.zip would run at depth 2,
        # over the cap. The BUG: the old code called Expand-UnitInPlace on
        # inner.zip UNCONDITIONALLY, THEN discovered the cap only once the
        # recursive Invoke-ArchiveMemberDispatch call started -- inner.zip was
        # decompressed regardless of what the finding claimed. Proof this is
        # fixed: nothing traceable to INSIDE inner.zip appears anywhere, only a
        # depth-cap note for inner.zip itself (plus its own FileHash, since the
        # FILE is still hashed -- only its extraction is skipped).
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'two_level_nested.zip'; Path = 'two_level_nested.zip'
                                    RelativePath = 'two_level_nested.zip'; StagingPath = $script:NestedExtraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        $budget.MaxDepth = 1
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth 1

        @($findings | Where-Object {
            $_.TestID -eq 'MTS-ARCHIVE-DEPTH-CAP' -and $_.File -eq 'two_level_nested.zip!inner.zip' }).Count |
            Should -Be 1
        # Nothing about inner.zip's OWN contents (e.g. deep/risky.sh) exists anywhere.
        @($findings | Where-Object { $_.File -like 'two_level_nested.zip!inner.zip!*' }).Count | Should -Be 0
        @($findings | Where-Object { $_.TestID -eq 'SHELL-B64-EXEC' }).Count | Should -Be 0
        # The inner.zip FILE itself is still hashed -- dispatch still runs on the
        # un-extracted unit; only Expand-UnitInPlace (the extraction) is skipped.
        @($findings | Where-Object {
            $_.TestID -eq 'MTS-HASH-001' -and $_.File -eq 'two_level_nested.zip!inner.zip' }).Count |
            Should -Be 1
        # Decisive proof extraction itself never ran: BOTH the old and new code
        # produce the SAME depth-cap finding here (the old code's recursive call
        # still hits its own top-of-function guard before WALKING inner.zip's
        # members) -- the only observable difference is whether inner.zip was
        # ever decompressed at all. Expand-UnitInPlace claims a stage-dir slot
        # (NextStageIndex++) every time it runs; zero claimed slots means
        # Expand-SubmissionArchive was never called for inner.zip.
        $budget.NextStageIndex | Should -Be 0
    }

    It 'never lets ExpandedBytes exceed MaxBytes -- look-ahead, not post-hoc (review follow-up)' {
        # The BUG: the old check was `ExpandedBytes -ge MaxBytes`, evaluated
        # BEFORE adding the CURRENT member's size -- so the one member whose
        # OWN size crosses the cap was still accepted (the total only exceeded
        # the cap AFTER acceptance). Set MaxBytes to one byte less than the sum
        # of no_dupes.zip's two members combined: the old check would accept
        # both (each check ran against a total that hadn't crossed the cap
        # YET); the fix must exclude at least the second.
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'no_dupes.zip'; Path = 'no_dupes.zip'
                                    RelativePath = 'no_dupes.zip'; StagingPath = $script:Extraction.StagingPath }
        $totalBytes = (Get-ChildItem -LiteralPath $script:Extraction.StagingPath -Recurse -File |
            Measure-Object -Property Length -Sum).Sum
        $budget = New-ArchiveTreeBudget
        $budget.MaxBytes = $totalBytes - 1
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:TestContext `
            -Enabled $script:TestEnabled -Budget $budget -Depth 1

        $budget.ExpandedBytes | Should -BeLessOrEqual $budget.MaxBytes
        @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 1
    }
}

Describe 'Archive-member dispatch — shared budget checked BEFORE top-level extraction (review follow-up)' {
    It 'does not extract a top-level archive once an EARLIER archive in the same scan already exhausted the shared budget' {
        # The BUG: Invoke-ArchiveMemberDispatch only throttles MEMBER processing
        # inside an ALREADY-extracted archive -- nothing previously stopped the
        # top-level scan loop from unconditionally decompressing every
        # top-level archive first. A submission of many individually-small,
        # individually-valid archives could exhaust disk before the shared
        # budget got a chance to block anything.
        #
        # Two copies of the SAME single-member archive: with MaxMembers=1,
        # whichever is processed FIRST exactly exhausts the budget (1 member,
        # no overshoot -- completes cleanly); the SECOND must be blocked before
        # Expand-UnitInPlace ever runs on it (order-independent assertions,
        # since Get-ChildItem enumeration order isn't guaranteed).
        $srcDir = Join-Path $env:TEMP "mts-p1-src-$(Get-Random)"
        New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
        Copy-Item (Join-Path $script:ArcMemDir 'shell_only.zip') (Join-Path $srcDir 'first.zip')
        Copy-Item (Join-Path $script:ArcMemDir 'shell_only.zip') (Join-Path $srcDir 'second.zip')
        $out2 = Join-Path $env:TEMP "mts-p1-out-$(Get-Random)"
        New-Item -ItemType Directory -Path $out2 -Force | Out-Null
        $origMaxMembers = $script:ArchiveTreeMaxMembers
        try {
            $script:ArchiveTreeMaxMembers = 1
            $r2 = Invoke-Scan -Path $srcDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $out2 -Mode offline

            $opened  = @($r2.Units | Where-Object { @($_.Findings | Where-Object { $_.File -match '!' }).Count -gt 0 })
            $blocked = @($r2.Units | Where-Object { @($_.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count -gt 0 })

            $opened.Count  | Should -Be 1
            $blocked.Count | Should -Be 1
            $opened[0].Name | Should -Not -Be $blocked[0].Name

            # The blocked archive shows NO evidence its contents were ever touched.
            @($blocked[0].Findings | Where-Object { $_.File -match '!' }).Count | Should -Be 0
            $blockedFinding = @($blocked[0].Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' })
            $blockedFinding.Count | Should -Be 1
            $blockedFinding[0].Issue | Should -Match 'not opened'
            # The top-level per-unit MTS-NO-ANALYZER check must not ALSO fire --
            # the budget-exceeded finding already explains the gap.
            @($blocked[0].Findings | Where-Object { $_.TestID -eq 'MTS-NO-ANALYZER' }).Count | Should -Be 0
        } finally {
            $script:ArchiveTreeMaxMembers = $origMaxMembers
            Remove-Item $srcDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-member dispatch — no duplicate findings (parent vs. member pass)' {
    It 'flags the npm postinstall hook exactly once' {
        $u = UnitOf 'no_dupes.zip'
        $u | Should -Not -BeNullOrEmpty
        @($u.Findings | Where-Object { $_.TestID -eq 'NPM-LIFECYCLE-SCRIPT' }).Count | Should -Be 1
    }
    It 'flags the malicious pickle exactly once' {
        $u = UnitOf 'no_dupes.zip'
        @($u.Findings | Where-Object { $_.TestID -eq 'PICKLE-REDUCE' }).Count | Should -Be 1
    }
}

Describe 'Archive-member dispatch — semantic containers are NOT member-dispatched' {
    It 'produces zero false archive-coverage warnings for wheels and notebooks' {
        # Regression guard mirrored from tests/Vba.Tests.ps1's existing pin: a
        # wheel/notebook's whole StagingPath is genuinely read by its own
        # analyzer (PythonRules/PipAudit/Bandit) -- recursing into it as an
        # 'archive' would duplicate those findings, so wheels/eggs/nupkg/
        # PyTorch .pt/.pth are extracted but never member-dispatched (Type is
        # 'python'/'nuget'/'model', never 'archive' — see Classify.ps1's
        # KnownZipContainerTypes routing).
        $out = Join-Path $env:TEMP "mts-arcmem-semantic-$(Get-Random)"
        try {
            foreach ($corpus in @('python', 'notebook')) {
                $res = Invoke-Scan -Path (Join-Path $PSScriptRoot "fixtures/corpus/$corpus") `
                    -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $out -Mode offline
                @($res.Units | ForEach-Object { $_.Findings } |
                    Where-Object { $_.TestID -in @('MTS-NO-ANALYZER', 'MTS-ARCHIVE-MEMBER-UNINSPECTED') }).Count |
                    Should -Be 0 -Because "$corpus units are analyzed via their own whole-staging-tree analyzer, not member dispatch"
            }
        } finally { Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Archive-member dispatch — disabled analyzer produces the aggregate finding' {
    It 'reports no coverage gap for a .sh member when ShellCheck is enabled (baseline)' {
        $u = UnitOf 'shell_only.zip'
        @($u.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-MEMBER-UNINSPECTED' }).Count | Should -Be 0
    }

    It 'produces ONE aggregate MTS-ARCHIVE-MEMBER-UNINSPECTED finding when the only analyzer for a member type is disabled' {
        # Disabling ShellCheck removes the ONLY analyzer that declares 'shell'
        # (Select-AnalyzersForUnit reacts to enable/disable dynamically, unlike
        # a static descriptor-based inference — the exact bug class issue #31
        # was split out to fix; see the issue's "why the obvious fix does not
        # work" section).
        $r2 = ScanDir 'archive_member/shell_only.zip' -DisableAnalyzers @('ShellCheck')
        $u2 = $r2.Units | Where-Object { $_.Name -eq 'shell_only.zip' }
        $gap = @($u2.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-MEMBER-UNINSPECTED' })
        $gap.Count | Should -Be 1
        $gap[0].Issue | Should -Match 'run\.sh'
        $gap[0].Severity | Should -Be 'INFO'
        # The top-level per-unit MTS-NO-ANALYZER check must NOT also fire on
        # the archive unit itself -- member dispatch already took over
        # coverage-gap reporting for it (see Engine.ps1).
        @($u2.Findings | Where-Object { $_.TestID -eq 'MTS-NO-ANALYZER' }).Count | Should -Be 0
    }
}

Describe 'Archive-member dispatch — staging cleanup' {
    It 'leaves no staging directory behind after a scan involving nested extraction' {
        $tempBefore = @(Get-ChildItem $env:TEMP -Directory -Filter 'mts-staging-*' -ErrorAction SilentlyContinue).Count
        ScanDir 'archive_member/two_level_nested.zip' | Out-Null
        $tempAfter = @(Get-ChildItem $env:TEMP -Directory -Filter 'mts-staging-*' -ErrorAction SilentlyContinue).Count
        $tempAfter | Should -Be $tempBefore
    }
}
