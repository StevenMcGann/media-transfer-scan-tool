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
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

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

    It 'the safe PowerShell fallback preserves the custom-rule findings' {
        $descriptor = Import-AnalyzerRegistry -AnalyzerDir $script:Analyzers |
            Where-Object { $_.Name -eq 'PSScriptAnalyzer' }
        $target = Join-Path $script:PsDir 'defender.ps1'
        $unit = [PSCustomObject]@{
            Path = $target; RelativePath = 'defender.ps1'; Type = 'powershell'; Name = 'defender.ps1'
        }
        $context = [PSCustomObject]@{
            Tools = @{}; Venv = $null; HelperDir = (Join-Path $script:Out 'missing-helpers')
            TimeoutSeconds = 30
        }

        $result = @(& $descriptor.Invoke $unit $context)
        @($result | Where-Object { $_.TestID -eq 'PS-DEFENDER-TAMPER' }).Count | Should -BeGreaterThan 0
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
