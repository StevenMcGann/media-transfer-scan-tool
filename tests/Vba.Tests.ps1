#Requires -Version 7.4
<#
    Pester 5 tests for VB-family support (issue #25):
      - Classifier routes exported VBA modules and VBScript to the `vba` unit type
      - VbaRules  (pure PowerShell rules — no venv, no pip package, no network)
      - Engine coverage-gap finding for unit types no analyzer claims

    VbaRules needs no provisioning at all, so these run offline with no venv —
    unlike the Office path, which needs oletools for its deep pass.
#>

BeforeAll {
    $script:Root      = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:VbaDir    = Join-Path $PSScriptRoot 'fixtures/corpus/vba'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-vba-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:UnitOf($Result, $Name) {
        $Result.Units | Where-Object { $_.Name -eq $Name }
    }
    function script:CountWhere($Result, $Name, [scriptblock]$Pred) {
        @((UnitOf $Result $Name).Findings | Where-Object $Pred).Count
    }
    function script:HasTest($Result, $Name, $TestId) {
        (CountWhere $Result $Name { $_.TestID -eq $TestId }) -gt 0
    }

    $script:R = Invoke-Scan -Path $script:VbaDir -Profile core `
        -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
}
AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Classifier — VB family routing' {
    It 'classifies an exported VBA module (.bas) as vba' {
        (UnitOf $R 'clean.bas').Type | Should -Be 'vba'
    }
    It 'classifies a VBA class module (.cls) as vba' {
        (UnitOf $R 'obfuscated.cls').Type | Should -Be 'vba'
    }
    It 'classifies VBScript (.vbs) as vba' {
        (UnitOf $R 'launcher.vbs').Type | Should -Be 'vba'
    }
    It 'classifies encoded VBScript (.vbe) as vba' {
        (UnitOf $R 'encoded.vbe').Type | Should -Be 'vba'
    }
}

Describe 'VbaRules — high-signal detection' {
    It 'flags an auto-executing entry point' {
        HasTest $R 'autoexec.bas' 'VBA-AUTOEXEC' | Should -BeTrue
    }
    It 'flags shell automation object creation' {
        HasTest $R 'autoexec.bas' 'VBA-WSCRIPT-SHELL' | Should -BeTrue
    }
    It 'escalates auto-exec plus payload to CRITICAL' {
        CountWhere $R 'autoexec.bas' {
            $_.TestID -eq 'VBA-AUTOEXEC-PAYLOAD' -and $_.Severity -eq 'CRITICAL'
        } | Should -BeGreaterThan 0
    }
    It 'flags a network fetch primitive' {
        HasTest $R 'downloader.bas' 'VBA-DOWNLOAD' | Should -BeTrue
    }
    It 'escalates download-plus-execute to CRITICAL' {
        CountWhere $R 'downloader.bas' {
            $_.TestID -eq 'VBA-DOWNLOAD-EXEC' -and $_.Severity -eq 'CRITICAL'
        } | Should -BeGreaterThan 0
    }
    It 'flags a native Win32 API declaration' {
        HasTest $R 'downloader.bas' 'VBA-NATIVE-DECLARE' | Should -BeTrue
    }
    It 'rates shellcode-injection APIs CRITICAL' {
        CountWhere $R 'shellcode.bas' {
            $_.TestID -eq 'VBA-SHELLCODE-API' -and $_.Severity -eq 'CRITICAL'
        } | Should -BeGreaterThan 0
    }
    It 'flags Chr() chain obfuscation' {
        HasTest $R 'obfuscated.cls' 'VBA-OBFUSCATION-CHR' | Should -BeTrue
    }
    It 'flags StrReverse obfuscation' {
        HasTest $R 'obfuscated.cls' 'VBA-OBFUSCATION-STRREVERSE' | Should -BeTrue
    }
    It 'flags hidden/encoded PowerShell launched from VBScript' {
        HasTest $R 'launcher.vbs' 'VBA-POWERSHELL-ENC' | Should -BeTrue
    }
    It 'reports encoded .vbe as an explicit coverage gap, not a clean result' {
        HasTest $R 'encoded.vbe' 'VBA-ENCODED-SOURCE' | Should -BeTrue
    }
}

Describe 'VbaRules — precision' {
    It 'produces no risky-code or macro findings for a clean module' {
        CountWhere $R 'clean.bas' { $_.Category -in @('risky-code', 'macro') } | Should -Be 0
    }
    It 'does not escalate a module that only downloads or only executes' {
        # shellcode.bas allocates memory but never fetches — the download-exec
        # combination must not fire on it.
        HasTest $R 'shellcode.bas' 'VBA-DOWNLOAD-EXEC' | Should -BeFalse
    }
    It 'reports one finding per rule per line' {
        # downloader.bas names URLDownloadToFile three times on two lines (Declare,
        # Alias, call site); the same rule must not report the same line twice.
        $lines = @((UnitOf $R 'downloader.bas').Findings |
                    Where-Object { $_.TestID -eq 'VBA-DOWNLOAD' } |
                    ForEach-Object { $_.Line })
        $lines.Count | Should -Be (@($lines | Sort-Object -Unique).Count)
    }
    It 'attaches a line number to source-level findings' {
        @((UnitOf $R 'autoexec.bas').Findings |
            Where-Object { $_.TestID -eq 'VBA-AUTOEXEC' -and $_.Line -gt 0 }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Classifier — VBA hidden under an innocent extension' {
    BeforeAll {
        $script:DisResult = Invoke-Scan -Path (Join-Path $PSScriptRoot 'fixtures/corpus/disguised') `
            -Profile core -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }
    It 'detects VBA content in a .txt by content signature' {
        (UnitOf $DisResult 'macro.txt').Type | Should -Be 'vba'
    }
    It 'raises the disguised-file finding' {
        CountWhere $DisResult 'macro.txt' { $_.TestID -eq 'MTS-DISGUISE-002' } | Should -BeGreaterThan 0
    }
    It 'still applies the VBA rules to the disguised file' {
        HasTest $DisResult 'macro.txt' 'VBA-AUTOEXEC' | Should -BeTrue
    }
    It 'does not reclassify the other disguised fixtures as vba' {
        # The VB content signature must not steal units from the PowerShell/shell/
        # python/batch signatures it sits alongside.
        @($DisResult.Units | Where-Object { $_.Name -ne 'macro.txt' -and $_.Type -eq 'vba' }).Count |
            Should -Be 0
    }
}

Describe 'Engine — no silent coverage gaps' {
    BeforeAll {
        $script:GapDir = Join-Path $env:TEMP "mts-gap-$(Get-Random)"
        New-Item -ItemType Directory -Path $script:GapDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:GapDir 'notes.md')  -Value '# just a readme'
        Set-Content -LiteralPath (Join-Path $script:GapDir 'setup.bat') -Value "@echo off`r`ngoto :eof"
        Set-Content -LiteralPath (Join-Path $script:GapDir 'clean.bas') -Value "Option Explicit`r`nSub A()`r`nEnd Sub"
        $script:GapResult = Invoke-Scan -Path $script:GapDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }
    AfterAll { Remove-Item $script:GapDir -Recurse -Force -ErrorAction SilentlyContinue }

    It 'flags an unsupported file as uninspected rather than leaving it silent' {
        CountWhere $GapResult 'notes.md' { $_.TestID -eq 'MTS-NO-ANALYZER' } | Should -BeGreaterThan 0
    }
    It 'flags a classified type that has no enabled analyzer (batch)' {
        (UnitOf $GapResult 'setup.bat').Type | Should -Be 'batch'
        CountWhere $GapResult 'setup.bat' { $_.TestID -eq 'MTS-NO-ANALYZER' } | Should -BeGreaterThan 0
    }
    It 'keeps the gap finding at INFO so it does not inflate the exit code' {
        CountWhere $GapResult 'notes.md' {
            $_.TestID -eq 'MTS-NO-ANALYZER' -and $_.Severity -ne 'INFO'
        } | Should -Be 0
    }
    It 'does not flag a type an analyzer does cover' {
        CountWhere $GapResult 'clean.bas' { $_.TestID -eq 'MTS-NO-ANALYZER' } | Should -Be 0
    }
}
