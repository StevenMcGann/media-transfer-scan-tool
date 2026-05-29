#Requires -Version 7.4
<#
    Pester 5 tests for v0.3 document analyzers:
      - PdfTriage   (pure PowerShell keyword triage — no provisioning)
      - OleVbaScan  (scan_office.py stdlib zip checks via a venv python)
#>

BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $Root 'src/Invoke-MediaTransferScan.ps1')
    $script:Quiet     = $true
    $script:PdfDir    = Join-Path $PSScriptRoot 'fixtures/corpus/pdf'
    $script:OfficeDir = Join-Path $PSScriptRoot 'fixtures/corpus/office'
    $script:Analyzers = Join-Path $Root 'src/analyzers'
    $script:Out       = Join-Path $env:TEMP "mts-doc-out-$(Get-Random)"
    New-Item -ItemType Directory -Path $script:Out -Force | Out-Null

    function script:UnitFindings($Result, $Name) {
        @(($Result.Units | Where-Object { $_.Name -eq $Name }).Findings)
    }
    # Count findings matching a predicate, robust to zero matches (AutomationNull).
    function script:CountWhere($Result, $Name, [scriptblock]$Pred) {
        @(UnitFindings $Result $Name | Where-Object $Pred).Count
    }
}

AfterAll { Remove-Item $script:Out -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'PDF triage (pure PowerShell, no provisioning)' {
    BeforeAll {
        # PdfTriage + FileHash need no tools; PipAudit/BinaryInspection/OleVbaScan
        # don't claim 'pdf', so a no-provision engine scan covers PDF units cleanly.
        $script:PdfResult = Invoke-Scan -Path $script:PdfDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out -Mode offline
    }

    It 'classifies .pdf via %PDF magic bytes' {
        ($PdfResult.Units | Where-Object { $_.Name -eq 'pdf_js.pdf' }).Type | Should -Be 'pdf'
    }
    It 'flags embedded JavaScript (/JS + /JavaScript)' {
        CountWhere $PdfResult 'pdf_js.pdf' { $_.TestID -eq 'PDF-JAVASCRIPT' } | Should -BeGreaterThan 0
    }
    It 'flags a /Launch action' {
        CountWhere $PdfResult 'pdf_launch.pdf' { $_.TestID -eq 'PDF-LAUNCH' } | Should -BeGreaterThan 0
    }
    It 'flags an embedded file' {
        CountWhere $PdfResult 'pdf_embedded.pdf' { $_.TestID -eq 'PDF-EMBEDDED-FILE' } | Should -BeGreaterThan 0
    }
    It 'notes an encrypted PDF' {
        CountWhere $PdfResult 'pdf_encrypted.pdf' { $_.TestID -eq 'PDF-ENCRYPTED' } | Should -BeGreaterThan 0
    }
    It 'catches JavaScript obfuscated with PDF name hex escapes' {
        CountWhere $PdfResult 'pdf_obfuscated.pdf' { $_.TestID -eq 'PDF-JAVASCRIPT' } | Should -BeGreaterThan 0
    }
    It 'produces no active-content findings for a clean PDF' {
        CountWhere $PdfResult 'pdf_clean.pdf' { $_.Category -eq 'active-content' } | Should -Be 0
    }
    It 'flags a fake .pdf that does not start with %PDF' {
        CountWhere $PdfResult 'pdf_fake.pdf' { $_.TestID -eq 'PDF-INVALID-FORMAT' } | Should -BeGreaterThan 0
    }
}

Describe 'Office triage (scan_office.py stdlib checks via venv python)' {
    BeforeAll {
        $py = Find-Python
        if (-not $py) { Set-ItResult -Skipped -Because 'Python not found'; return }
        # Bare venv (no oletools) — the zip-based checks are stdlib; deep VBA via
        # oletools is exercised on real docs. No pip bootstrap => no network needed.
        $script:Venv = Initialize-ScannerVenv -PythonCmd $py -VenvDir (Join-Path $env:TEMP "mts-office-venv-$(Get-Random)")
        $script:Prov = [PSCustomObject]@{ Venv = $script:Venv; Tools = @{} }
        $script:OfficeResult = Invoke-Scan -Path $script:OfficeDir -Profile core `
            -AnalyzerDir $script:Analyzers -ReportsDir $script:Out `
            -HelperDir (Join-Path $Root 'src/helpers') -ProvisionResult $script:Prov -Mode offline
    }
    AfterAll {
        if ($script:Venv) { Remove-Item $script:Venv.Root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'classifies .docx/.docm as office (OOXML zip container)' {
        ($OfficeResult.Units | Where-Object { $_.Name -eq 'office_macro.docm' }).Type | Should -Be 'office'
    }
    It 'flags a macro-enabled document (vbaProject.bin present)' {
        CountWhere $OfficeResult 'office_macro.docm' { $_.TestID -eq 'OFFICE-VBA-PRESENT' } | Should -BeGreaterThan 0
    }
    It 'flags a DDE/DDEAUTO field' {
        CountWhere $OfficeResult 'office_dde.docx' { $_.TestID -eq 'OFFICE-DDE' } | Should -BeGreaterThan 0
    }
    It 'flags remote-template injection' {
        CountWhere $OfficeResult 'office_template.docx' { $_.TestID -eq 'OFFICE-REMOTE-TEMPLATE' } | Should -BeGreaterThan 0
    }
    It 'produces no macro/active-content findings for a clean document' {
        CountWhere $OfficeResult 'office_clean.docx' { $_.Category -in @('macro','active-content') } | Should -Be 0
    }
}
