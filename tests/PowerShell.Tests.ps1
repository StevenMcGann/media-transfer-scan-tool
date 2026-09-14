#Requires -Version 7.4
<#
    Pester 5 tests for the PSScriptAnalyzer analyzer.
    Layers 2 (custom rules) + 3 (Authenticode) run with no provisioning.
    Layer 1 (PSScriptAnalyzer module) is exercised in the Online describe block.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:PsDir     = Join-Path $PSScriptRoot 'fixtures/corpus/powershell'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-ps-out-$(Get-Random)"
    $script:PsHelper  = Join-Path $Root 'src/helpers/scan_powershell.py'
    $script:PythonExe = Find-Python
    if (-not $script:PythonExe) {
        $devPython = Join-Path $Root 'src/.scan-venv/Scripts/python.exe'
        if (Test-Path -LiteralPath $devPython -PathType Leaf) { $script:PythonExe = $devPython }
    }
    $script:PowerShellEncodings = @(
        @{ Name = 'utf8';    Encoding = [Text.UTF8Encoding]::new($false) }
        @{ Name = 'utf8bom'; Encoding = [Text.UTF8Encoding]::new($true) }
        @{ Name = 'utf16le'; Encoding = [Text.UnicodeEncoding]::new($false, $true) }
        @{ Name = 'utf16be'; Encoding = [Text.UnicodeEncoding]::new($true, $true) }
        @{ Name = 'utf32le'; Encoding = [Text.UTF32Encoding]::new($false, $true) }
        @{ Name = 'utf32be'; Encoding = [Text.UTF32Encoding]::new($true, $true) }
    )
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null
    $script:PsDescriptor = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers |
        Where-Object { $_.Name -eq 'PSScriptAnalyzer' }

    function script:PsCount($Result, $Name, [scriptblock]$Pred) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings | Where-Object $Pred).Count
    }
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'PowerShell custom rules + signature (no provisioning)' {
    BeforeAll {
        $script:R = Invoke-Scan -Path $script:PsDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }

    It 'classifies .ps1 as powershell' {
        ($R.Units | Where-Object { $_.Name -eq 'clean.ps1' }).Type | Should -Be 'powershell'
    }
    It 'flags IEX + DownloadString cradle (PS-IEX)' {
        PsCount $R 'downloader.ps1' { $_.TestID -eq 'PS-IEX' } | Should -BeGreaterThan 0
        PsCount $R 'downloader.ps1' { $_.TestID -eq 'PS-DOWNLOAD' } | Should -BeGreaterThan 0
    }
    It 'flags -EncodedCommand and hidden window' {
        PsCount $R 'encoded.ps1' { $_.TestID -eq 'PS-ENCODED-COMMAND' } | Should -BeGreaterThan 0
        PsCount $R 'encoded.ps1' { $_.TestID -eq 'PS-HIDDEN-WINDOW' } | Should -BeGreaterThan 0
    }
    It 'flags AMSI tampering and base64 decode' {
        PsCount $R 'amsi.ps1' { $_.TestID -eq 'PS-AMSI-TAMPER' } | Should -BeGreaterThan 0
        PsCount $R 'amsi.ps1' { $_.TestID -eq 'PS-BASE64-DECODE' } | Should -BeGreaterThan 0
    }
    It 'flags Defender tampering' {
        PsCount $R 'defender.ps1' { $_.TestID -eq 'PS-DEFENDER-TAMPER' } | Should -BeGreaterThan 0
    }
    It 'records an Authenticode signature status for each script' {
        PsCount $R 'clean.ps1' { $_.Tool -eq 'Authenticode' } | Should -BeGreaterThan 0
    }
    It 'produces no risky-code findings for a clean script' {
        PsCount $R 'clean.ps1' { $_.Category -eq 'risky-code' } | Should -Be 0
    }
}

Describe 'PowerShell token-hash rule paths' {
    It 'keeps the Python and PowerShell digest sets synchronized' {
        $helperText = Get-Content -LiteralPath $script:PsHelper -Raw
        $helperDigests = @([regex]::Matches($helperText, '(?<![A-F0-9])[A-F0-9]{64}(?![A-F0-9])') |
            ForEach-Object Value | Sort-Object -Unique)
        $fallbackDigests = @($script:MtsPowerShellRiskTokenDigests | Sort-Object -Unique)

        @(Compare-Object -ReferenceObject $fallbackDigests -DifferenceObject $helperDigests) |
            Should -BeNullOrEmpty
    }

    It 'requires valid command separators between paired option tokens' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $fixtureText = [IO.File]::ReadAllText(
            (Join-Path $script:PsDir 'encoded.ps1'), [Text.Encoding]::UTF8)
        $fixtureTokens = @($script:MtsPowerShellTokenPattern.Matches($fixtureText))
        $head = ''
        $tail = ''
        for ($i = 0; $i -lt ($fixtureTokens.Count - 1); $i++) {
            $ruleDigest = Get-MtsTokenDigest -Token $fixtureTokens[$i].Value
            if (-not $script:MtsPowerShellIndicatorRules.Contains($ruleDigest)) { continue }
            $rule = $script:MtsPowerShellIndicatorRules[$ruleDigest]
            if ($rule.Context -eq 'Pair' -and
                (Get-MtsTokenDigest -Token $fixtureTokens[$i + 1].Value) -eq $rule.PairDigest) {
                $head = $fixtureTokens[$i].Value
                $tail = $fixtureTokens[$i + 1].Value
                break
            }
        }
        $head | Should -Not -BeNullOrEmpty
        $tail | Should -Not -BeNullOrEmpty

        $cases = @(
            @{ Name = 'space';        Text = "$head $tail";       Expected = 1 }
            @{ Name = 'colon';        Text = "${head}:$tail";     Expected = 1 }
            @{ Name = 'quoted';       Text = "$head '$tail'";     Expected = 1 }
            @{ Name = 'assignment';   Text = "$head = $tail";     Expected = 0 }
            @{ Name = 'quoted-key';   Text = "'$head' = '$tail'"; Expected = 0 }
            @{ Name = 'collection';   Text = "'$head', '$tail'";  Expected = 0 }
            @{ Name = 'statement';    Text = "$head; $tail";     Expected = 0 }
            @{ Name = 'next-line';    Text = "$head`n$tail";     Expected = 0 }
            @{ Name = 'continuation'; Text = "$head ```n  $tail"; Expected = 1 }
        )

        foreach ($case in $cases) {
            $fallback = @(Find-MtsPowerShellRiskIndicator -Text $case.Text |
                Where-Object { $_.Rule.TestID -eq 'PS-HIDDEN-WINDOW' })
            $fallback.Count | Should -Be $case.Expected -Because "$($case.Name) fallback syntax"

            $target = Join-Path $script:Out "pair-$($case.Name).ps1"
            $output = Join-Path $script:Out "pair-$($case.Name).json"
            [IO.File]::WriteAllText($target, $case.Text, [Text.UTF8Encoding]::new($false))
            & $script:PythonExe $script:PsHelper $target $output
            $LASTEXITCODE | Should -Be 0
            $helperResult = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            @($helperResult.findings | Where-Object { $_.testId -eq 'PS-HIDDEN-WINDOW' }).Count |
                Should -Be $case.Expected -Because "$($case.Name) helper syntax"
        }
    }

    It 'the Python helper preserves the custom-rule findings' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }
        $output = Join-Path $script:Out 'python-helper.json'
        foreach ($file in Get-ChildItem -LiteralPath $script:PsDir -File -Filter '*.ps1') {
            & $script:PythonExe $script:PsHelper $file.FullName $output
            $LASTEXITCODE | Should -Be 0

            $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            $result.scanned | Should -Be 1
            $expected = @(Find-MtsPowerShellRiskIndicator -Text (
                Get-Content -LiteralPath $file.FullName -Raw) |
                ForEach-Object { "$($_.Line):$($_.Rule.TestID)" } |
                Sort-Object)
            $actual = @($result.findings |
                ForEach-Object { "$($_.line):$($_.testId)" } |
                Sort-Object)
            @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual) |
                Should -BeNullOrEmpty -Because "the Python and PowerShell paths must agree for $($file.Name)"
        }
    }

    It 'decodes BOM-marked PowerShell before hashing through the preferred analyzer path' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $descriptor = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers |
            Where-Object { $_.Name -eq 'PSScriptAnalyzer' }
        $context = [PSCustomObject]@{
            Tools = @{}
            Venv = [PSCustomObject]@{ Python = $script:PythonExe }
            HelperDir = Split-Path $script:PsHelper -Parent
            TimeoutSeconds = 30
        }
        $sourcePath = Join-Path $script:PsDir 'amsi.ps1'
        $sourceText = [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8)
        $expected = @(Find-MtsPowerShellRiskIndicator -Text $sourceText |
            ForEach-Object { "$($_.Line):$($_.Rule.TestID)" } |
            Sort-Object)

        foreach ($case in $script:PowerShellEncodings) {
            $encodedPath = Join-Path $script:Out "amsi-$($case.Name).ps1"
            $output = Join-Path $script:Out "amsi-$($case.Name).json"
            [IO.File]::WriteAllText($encodedPath, $sourceText, $case.Encoding)

            & $script:PythonExe $script:PsHelper $encodedPath $output
            $LASTEXITCODE | Should -Be 0
            $helperResult = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            $helperResult.scanned | Should -Be 1
            $helperFindings = @($helperResult.findings |
                ForEach-Object { "$($_.line):$($_.testId)" } |
                Sort-Object)
            @(Compare-Object -ReferenceObject $expected -DifferenceObject $helperFindings) |
                Should -BeNullOrEmpty -Because "$($case.Name) must preserve helper findings"

            $unit = [PSCustomObject]@{
                Path = $encodedPath; RelativePath = "amsi-$($case.Name).ps1"
                Type = 'powershell'; Name = "amsi-$($case.Name).ps1"
            }
            $analyzerFindings = @(& $descriptor.Invoke $unit $context |
                Where-Object { $_.Tool -eq 'PowerShellRules' } |
                ForEach-Object { "$($_.Line):$($_.TestID)" } |
                Sort-Object)
            @(Compare-Object -ReferenceObject $expected -DifferenceObject $analyzerFindings) |
                Should -BeNullOrEmpty -Because "$($case.Name) must preserve analyzer findings"
        }
    }

    It 'accepts clean BOM-marked PowerShell as a successful zero-finding scan' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $sourceText = [IO.File]::ReadAllText(
            (Join-Path $script:PsDir 'clean.ps1'), [Text.Encoding]::UTF8)
        foreach ($case in $script:PowerShellEncodings | Where-Object { $_.Name -ne 'utf8' }) {
            $encodedPath = Join-Path $script:Out "clean-$($case.Name).ps1"
            $output = Join-Path $script:Out "clean-$($case.Name).json"
            [IO.File]::WriteAllText($encodedPath, $sourceText, $case.Encoding)

            & $script:PythonExe $script:PsHelper $encodedPath $output
            $LASTEXITCODE | Should -Be 0
            $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
            $result.scanned | Should -Be 1
            @($result.findings).Count | Should -Be 0
        }
    }

    It 'the safe PowerShell fallback preserves the custom-rule findings' {
        $target = Join-Path $script:PsDir 'defender.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'defender.ps1'; Type = 'powershell'; Name = 'defender.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = $null; HelperDir = (Join-Path $script:Out 'missing-helpers')
            TimeoutSeconds = 30
        }

        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'PS-DEFENDER-TAMPER' }).Count | Should -BeGreaterThan 0
    }

    It 'reports a helper timeout without retrying the hostile input in-process' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $helperDir = Join-Path $script:Out 'timeout-helper'
        New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $helperDir 'scan_powershell.py'),
            "import time`ntime.sleep(30)`n",
            [Text.UTF8Encoding]::new($false))
        $target = Join-Path $script:PsDir 'amsi.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'amsi.ps1'; Type = 'powershell'; Name = 'amsi.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = [PSCustomObject]@{ Python = $script:PythonExe }
            HelperDir = $helperDir; TimeoutSeconds = 1
        }

        $timer = [Diagnostics.Stopwatch]::StartNew()
        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        $timer.Stop()
        @($result | Where-Object { $_.TestID -eq 'MTS-ANALYZER-TIMEOUT' }).Count | Should -Be 1
        @($result | Where-Object { $_.TestID -eq 'PS-AMSI-TAMPER' }).Count | Should -Be 0
        $timer.Elapsed.TotalSeconds | Should -BeLessThan 10
    }

    It 'reports a blocked helper without retrying the hostile input in-process' {
        $helperDir = Join-Path $script:Out 'blocked-helper'
        New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $helperDir 'scan_powershell.py'),
            "raise SystemExit(0)`n",
            [Text.UTF8Encoding]::new($false))
        $target = Join-Path $script:PsDir 'amsi.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'amsi.ps1'; Type = 'powershell'; Name = 'amsi.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}
            Venv = [PSCustomObject]@{ Python = (Join-Path $script:Out 'blocked-python.exe') }
            HelperDir = $helperDir; TimeoutSeconds = 5
        }

        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'MTS-TOOL-BLOCKED' }).Count | Should -Be 1
        @($result | Where-Object { $_.TestID -eq 'PS-AMSI-TAMPER' }).Count | Should -Be 0
    }

    It 'reports malformed helper output without retrying the hostile input in-process' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $helperDir = Join-Path $script:Out 'malformed-helper'
        New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $helperDir 'scan_powershell.py'),
            "from pathlib import Path`nimport sys`nPath(sys.argv[2]).write_text('{', encoding='utf-8')`n",
            [Text.UTF8Encoding]::new($false))
        $target = Join-Path $script:PsDir 'amsi.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'amsi.ps1'; Type = 'powershell'; Name = 'amsi.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = [PSCustomObject]@{ Python = $script:PythonExe }
            HelperDir = $helperDir; TimeoutSeconds = 5
        }

        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'MTS-PSSRULES-FAILED' }).Count | Should -Be 1
        @($result | Where-Object { $_.TestID -eq 'PS-AMSI-TAMPER' }).Count | Should -Be 0
    }

    It 'treats helper failure states as authoritative instead of falling back' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $cases = @(
            @{
                Name = 'nonzero'; Expected = 'MTS-PSSRULES-FAILED'; Script = @'
raise SystemExit(3)
'@
            }
            @{
                Name = 'scanned-zero'; Expected = 'MTS-PSSRULES-FAILED'; Script = @'
from pathlib import Path
import sys
Path(sys.argv[2]).write_text('{"scanned":0,"findings":[],"error":"could not read input"}', encoding='utf-8')
'@
            }
            @{
                Name = 'valid-empty'; Expected = ''; Script = @'
from pathlib import Path
import sys
Path(sys.argv[2]).write_text('{"scanned":1,"findings":[]}', encoding='utf-8')
'@
            }
        )
        $target = Join-Path $script:PsDir 'amsi.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'amsi.ps1'; Type = 'powershell'; Name = 'amsi.ps1'
        }

        foreach ($case in $cases) {
            $helperDir = Join-Path $script:Out "$($case.Name)-helper"
            New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $helperDir 'scan_powershell.py'),
                $case.Script,
                [Text.UTF8Encoding]::new($false))
            $context = [PSCustomObject]@{
                Tools = @{}; Venv = [PSCustomObject]@{ Python = $script:PythonExe }
                HelperDir = $helperDir; TimeoutSeconds = 5
            }

            $result = @(& $script:PsDescriptor.Invoke $unit $context)
            @($result | Where-Object { $_.TestID -eq 'PS-AMSI-TAMPER' }).Count |
                Should -Be 0 -Because "$($case.Name) must not invoke the fallback"
            @($result | Where-Object { $_.TestID -like 'MTS-PSSRULES-*' }).Count |
                Should -Be ([int][bool]$case.Expected) -Because "$($case.Name) must preserve protocol semantics"
            if ($case.Expected) {
                @($result | Where-Object { $_.TestID -eq $case.Expected }).Count | Should -Be 1
            }
        }
    }

    It 'rejects a file above the static-rule byte limit before launching a helper' {
        $target = Join-Path $script:Out 'oversized.ps1'
        [IO.File]::WriteAllBytes($target, [byte[]]::new($script:MtsPowerShellRuleMaxBytes + 1))
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'oversized.ps1'; Type = 'powershell'; Name = 'oversized.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = [PSCustomObject]@{ Python = (Join-Path $script:Out 'must-not-run.exe') }
            HelperDir = Split-Path $script:PsHelper -Parent; TimeoutSeconds = 5
        }

        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'MTS-PSSRULES-LIMIT' }).Count | Should -Be 1
        @($result | Where-Object { $_.TestID -eq 'MTS-TOOL-BLOCKED' }).Count | Should -Be 0
    }

    It 'bounds the no-Python fallback by bytes and reports the coverage gap' {
        $target = Join-Path $script:Out 'fallback-oversized.ps1'
        [IO.File]::WriteAllBytes($target, [byte[]]::new($script:MtsPowerShellFallbackMaxBytes + 1))
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'fallback-oversized.ps1'; Type = 'powershell'; Name = 'fallback-oversized.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = $null; HelperDir = (Join-Path $script:Out 'missing-helpers')
            TimeoutSeconds = 5
        }

        $result = @(& $script:PsDescriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'MTS-PSSRULES-LIMIT' }).Count | Should -Be 1
    }

    It 'bounds fallback token and finding density with an explicit reason' {
        $tokenReason = ''
        $tokenResults = @(Find-MtsPowerShellRiskIndicator -Text 'one two three four five six' `
            -MaxTokens 5 -LimitReason ([ref]$tokenReason))
        $tokenResults.Count | Should -Be 0
        $tokenReason | Should -Match 'candidate-token limit'

        $source = [IO.File]::ReadAllText(
            (Join-Path $script:PsDir 'defender.ps1'), [Text.Encoding]::UTF8)
        $findingReason = ''
        $findingResults = @(Find-MtsPowerShellRiskIndicator -Text (($source + "`n") * 2 -join '') `
            -MaxResults 1 -LimitReason ([ref]$findingReason))
        $findingResults.Count | Should -Be 1
        $findingReason | Should -Match 'finding limit'

        $lastRiskMatch = @(Find-MtsPowerShellRiskIndicator -Text $source)[-1]
        $riskToken = $script:MtsPowerShellTokenPattern.Match($source, $lastRiskMatch.Index).Value
        $exactReason = ''
        $exactResults = @(Find-MtsPowerShellRiskIndicator -Text $riskToken `
            -MaxResults 1 -LimitReason ([ref]$exactReason))
        $exactResults.Count | Should -Be 1
        $exactReason | Should -BeNullOrEmpty
    }

    It 'bounds Python helper token and finding density with explicit findings' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $tokenPath = Join-Path $script:Out 'token-dense.ps1'
        $output = Join-Path $script:Out 'token-dense.json'
        $tokenText = [string]::new('x', 1000002).Replace('xx', 'a ')
        [IO.File]::WriteAllText($tokenPath, $tokenText, [Text.UTF8Encoding]::new($false))
        & $script:PythonExe $script:PsHelper $tokenPath $output
        $LASTEXITCODE | Should -Be 0
        $tokenResult = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        @($tokenResult.findings | Where-Object { $_.testId -eq 'MTS-PSSRULES-LIMIT' }).Count | Should -Be 1

        $source = [IO.File]::ReadAllText(
            (Join-Path $script:PsDir 'defender.ps1'), [Text.Encoding]::UTF8)
        $findingPath = Join-Path $script:Out 'finding-dense.ps1'
        $findingText = (($source + "`n") * 1001 -join '')
        [IO.File]::WriteAllText($findingPath, $findingText, [Text.UTF8Encoding]::new($false))
        & $script:PythonExe $script:PsHelper $findingPath $output
        $LASTEXITCODE | Should -Be 0
        $findingResult = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        @($findingResult.findings | Where-Object { $_.testId -eq 'MTS-PSSRULES-LIMIT' }).Count | Should -Be 1
        @($findingResult.findings).Count | Should -BeLessOrEqual 1001

        $lastRiskMatch = @(Find-MtsPowerShellRiskIndicator -Text $source)[-1]
        $riskToken = $script:MtsPowerShellTokenPattern.Match($source, $lastRiskMatch.Index).Value
        $exactText = (($riskToken + ' ') * 999 -join '') + $riskToken
        [IO.File]::WriteAllText($findingPath, $exactText, [Text.UTF8Encoding]::new($false))
        & $script:PythonExe $script:PsHelper $findingPath $output
        $LASTEXITCODE | Should -Be 0
        $exactResult = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        @($exactResult.findings).Count | Should -Be 1000
        @($exactResult.findings | Where-Object { $_.testId -eq 'MTS-PSSRULES-LIMIT' }).Count | Should -Be 0
    }

    It 'accepts exactly the Python helper byte limit and rejects one byte more' {
        if (-not $script:PythonExe) {
            Set-ItResult -Skipped -Because 'Python 3 is unavailable'
            return
        }

        $target = Join-Path $script:Out 'helper-byte-boundary.ps1'
        $output = Join-Path $script:Out 'helper-byte-boundary.json'
        [IO.File]::WriteAllBytes($target, [byte[]]::new(5000000))
        & $script:PythonExe $script:PsHelper $target $output
        $LASTEXITCODE | Should -Be 0
        (Get-Content -LiteralPath $output -Raw | ConvertFrom-Json).scanned | Should -Be 1

        [IO.File]::WriteAllBytes($target, [byte[]]::new(5000001))
        & $script:PythonExe $script:PsHelper $target $output
        $LASTEXITCODE | Should -Be 1
        $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
        $result.scanned | Should -Be 0
        $result.error | Should -Match 'size limit'
    }

    It 'shipped PowerShell source contains no plaintext high-risk indicator tokens' {
        $leaks = [Collections.Generic.List[string]]::new()
        foreach ($file in Get-ChildItem (Join-Path $Root 'src') -Recurse -File -Filter '*.ps1') {
            if ($file.FullName -like '*\.scan-venv\*') { continue }
            $text = Get-Content -LiteralPath $file.FullName -Raw
            foreach ($match in @(Find-MtsPowerShellRiskIndicator -Text $text)) {
                $leaks.Add("$($file.FullName):$($match.Index):$($match.Digest)")
            }
        }
        $leaks | Should -BeNullOrEmpty
    }
}

Describe 'PowerShell — PSScriptAnalyzer module' -Tag 'Online' {
    It 'PSScriptAnalyzer flags the IEX downloader and needs no Python venv' {
        # Provisioning a psmodule-only analyzer must NOT require Python.
        $reg = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers
        $sel = Resolve-EnabledAnalyzers -Registry $reg -Profile core `
                   -EnableAnalyzers @() -DisableAnalyzers @('PipAudit','BinaryInspection','OleVbaScan','ShellCheck','FileHash')
        $prov = Invoke-Provisioning -EnabledAnalyzers $sel.Enabled `
            -VenvDir (Join-Path $env:TEMP "mts-ps-venv-$(Get-Random)") -Mode online
        $prov.Venv | Should -BeNullOrEmpty   # no pip tools -> no venv created
        $prov.Tools['PSScriptAnalyzer'].Available | Should -BeTrue

        $result = Invoke-Scan -Path $script:PsDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -ProvisionResult $prov
        # PSScriptAnalyzer flags Invoke-Expression (PSAvoidUsingInvokeExpression) etc.
        @($result.Units | ForEach-Object { $_.Findings } |
          Where-Object { $_.Tool -eq 'PSScriptAnalyzer' -and $_.TestID -like 'PS*' }).Count |
            Should -BeGreaterThan 0
    }
}
