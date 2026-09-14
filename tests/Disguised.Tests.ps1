#Requires -Version 7.4
<#
    Pester 5 tests for v0.2 disguised-script detection — content-signature
    classification (signal #3) of scripts hidden in innocent extensions with no
    shebang, plus the false-positive guard on plain prose.
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')   # loads Classify + engine
    $script:Quiet = $true
    $script:Dis   = Join-Path $PSScriptRoot 'fixtures/corpus/disguised'

    function script:Classify([string]$Name) {
        New-Unit -File (Get-Item (Join-Path $script:Dis $Name)) -ScanRoot $script:Dis
    }
}

Describe 'Content-signature detection (no shebang)' {
    It 'detects PowerShell hidden in a .txt' {
        $r = Classify 'readme.txt'
        $r.Unit.DetectedType | Should -Be 'powershell'
        @($r.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' }).Count | Should -Be 1
        ($r.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' })[0].Severity | Should -Be 'HIGH'
    }
    It 'detects bash hidden in a .log' {
        $r = Classify 'output.log'
        $r.Unit.DetectedType | Should -Be 'shell'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
    It 'detects Python hidden in a .dat' {
        $r = Classify 'data.dat'
        $r.Unit.DetectedType | Should -Be 'python'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
    It 'detects a batch script hidden in a .txt' {
        $r = Classify 'notes2.txt'
        $r.Unit.DetectedType | Should -Be 'batch'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Hashed-indicator scoring' {
    It 'counts two distinct download tokens as two signals, not one shared rule' {
        # The fixture's ONLY PowerShell signals are two different download methods
        # under the same PS-DOWNLOAD rule. Deduplicating by TestID scored it 1,
        # left it 'unsupported', and never routed it to the PowerShell analyzer
        # (PR #50 review). Each distinct token digest must count.
        $pairDir = Join-Path $PSScriptRoot 'fixtures/corpus/disguised_pair'
        $r = New-Unit -File (Get-Item (Join-Path $pairDir 'cradle.txt')) -ScanRoot $pairDir
        $r.Unit.DetectedType | Should -Be 'powershell'
        @($r.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' }).Count | Should -Be 1
    }
}

Describe 'False-positive guard' {
    It 'does NOT flag plain English prose as a disguised script' {
        $r = Classify 'memo.txt'
        @($r.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count | Should -Be 0
        $r.Unit.DetectedType | Should -Be 'unsupported'
    }
}

Describe 'Get-ContentSignature — unit behavior' {
    It 'returns null for binary content (NUL bytes)' {
        $bin = Join-Path $env:TEMP "mts-bin-$(Get-Random).dat"
        [System.IO.File]::WriteAllBytes($bin, [byte[]](0,1,2,3,0,255,10,0))
        Get-ContentSignature -Path $bin | Should -BeNullOrEmpty
        Remove-Item $bin -Force
    }
    It 'requires >= 2 distinct signature hits (single keyword is not enough)' {
        $f = Join-Path $env:TEMP "mts-weak-$(Get-Random).txt"
        'The report will print() the totals.' | Set-Content $f -Encoding utf8
        Get-ContentSignature -Path $f | Should -BeNullOrEmpty
        Remove-Item $f -Force
    }

    It 'detects BOM-marked UTF-16 and UTF-32 PowerShell hidden in text files' {
        $tempDir = Join-Path $env:TEMP "mts-wide-disguise-$(Get-Random)"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        try {
            $sourceText = [IO.File]::ReadAllText(
                (Join-Path $script:Dis 'readme.txt'), [Text.Encoding]::UTF8)
            $cleanText = [IO.File]::ReadAllText(
                (Join-Path $script:Dis 'memo.txt'), [Text.Encoding]::UTF8)
            $encodings = @(
                @{ Name = 'utf16le'; Encoding = [Text.UnicodeEncoding]::new($false, $true) }
                @{ Name = 'utf16be'; Encoding = [Text.UnicodeEncoding]::new($true, $true) }
                @{ Name = 'utf32le'; Encoding = [Text.UTF32Encoding]::new($false, $true) }
                @{ Name = 'utf32be'; Encoding = [Text.UTF32Encoding]::new($true, $true) }
            )
            foreach ($case in $encodings) {
                [IO.File]::WriteAllText(
                    (Join-Path $tempDir "payload-$($case.Name).txt"), $sourceText, $case.Encoding)
                [IO.File]::WriteAllText(
                    (Join-Path $tempDir "memo-$($case.Name).txt"), $cleanText, $case.Encoding)
            }

            $result = Invoke-Scan -Path $tempDir -Profile core `
                -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $tempDir -Mode offline
            foreach ($case in $encodings) {
                $payload = $result.Units | Where-Object { $_.Name -eq "payload-$($case.Name).txt" }
                $payload.Type | Should -Be 'powershell'
                @($payload.Findings | Where-Object { $_.TestID -eq 'MTS-DISGUISE-002' }).Count |
                    Should -Be 1
                @($payload.Findings | Where-Object { $_.TestID -eq 'PS-IEX' }).Count |
                    Should -BeGreaterThan 0
                @($payload.Findings | Where-Object { $_.TestID -eq 'PS-DOWNLOAD' }).Count |
                    Should -BeGreaterThan 0

                $memo = $result.Units | Where-Object { $_.Name -eq "memo-$($case.Name).txt" }
                $memo.Type | Should -Be 'unsupported'
                @($memo.Findings | Where-Object { $_.Category -eq 'disguised-file' }).Count |
                    Should -Be 0
            }
        } finally {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Engine — disguised scripts routed and flagged end to end' {
    It 'flags all five disguised scripts and clears the prose control under core' {
        $out = Join-Path $env:TEMP "mts-dis-out-$(Get-Random)"
        $result = Invoke-Scan -Path $script:Dis -Profile core `
            -AnalyzerDir (Join-Path $Root 'src/analyzers') -ReportsDir $out -Mode offline
        $disguised = @($result.Units | ForEach-Object { $_.Findings } |
                       Where-Object { $_.Category -eq 'disguised-file' })
        # readme.txt (PS), output.log (shell), data.dat (python), notes2.txt (batch),
        # macro.txt (VBA, issue #25). memo.txt is the prose control and must not fire.
        $disguised.Count | Should -Be 5
        ($result.Units | Where-Object { $_.Name -eq 'memo.txt' }).Type | Should -Be 'unsupported'
        Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
    }
}
