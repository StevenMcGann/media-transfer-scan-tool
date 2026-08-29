#Requires -Version 7.4
<#
    PdfTriage analyzer — static keyword triage of PDF files.

    Pure PowerShell, NO third-party PDF library: it counts the suspicious PDF
    keywords that indicate active content (pdfid-style). This is deliberate —
    a heavy PDF parser is itself attack surface, and keyword triage needs none.
    The PDF is read as bytes and never rendered; no JavaScript is executed.

    Flags: /JS /JavaScript (script), /OpenAction /AA /Launch (auto/launch actions),
    /EmbeddedFile (hidden payload), /URI (link), /RichMedia, and /Encrypt
    (encrypted — content may be uninspectable).

    Tier: core (these keywords are targeted, high-signal active-content markers).
#>
@{
    Name           = 'PdfTriage'
    Version        = '0.1.0'
    UnitTypes      = @('pdf')
    RequiredTools  = @()          # pure PowerShell — no provisioning needed
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        if (-not (Test-Path -LiteralPath $Unit.Path -PathType Leaf)) { return @() }

        try {
            $bytes = [System.IO.File]::ReadAllBytes($Unit.Path)
        } catch {
            return @(New-Finding -Tool 'PdfTriage' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'pdf' -File $Unit.RelativePath `
                -Issue "Could not read PDF: $_" -TestID 'MTS-PDF-ERR')
        }

        # Decode as latin1 so every byte maps 1:1 to a char for scanning.
        $text = [System.Text.Encoding]::GetEncoding('iso-8859-1').GetString($bytes)

        if (-not $text.StartsWith('%PDF')) {
            return @(New-Finding -Tool 'PdfTriage' -Category 'parser' -Severity 'HIGH' `
                -Confidence 'HIGH' -UnitType 'pdf' -File $Unit.RelativePath `
                -Issue 'File classified as PDF but does not begin with %PDF — possibly disguised or corrupt.' `
                -TestID 'PDF-INVALID-FORMAT' `
                -Recommendation 'Reject — content does not match the declared PDF format.')
        }

        # Deobfuscate PDF name hex escapes (/#4A#61... → /Java...) so obfuscated
        # keywords are still counted, exactly as pdfid normalizes names.
        $deob = [regex]::Replace($text, '#([0-9A-Fa-f]{2})', {
            param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16) })

        # keyword -> @{ Sev; Conf; TestID; Cat; Issue }
        $keywords = @(
            @{ K = '/JavaScript';  Sev = 'HIGH';   Cat = 'active-content'; TestID = 'PDF-JAVASCRIPT';   Msg = 'embedded JavaScript' }
            @{ K = '/JS';          Sev = 'HIGH';   Cat = 'active-content'; TestID = 'PDF-JAVASCRIPT';   Msg = 'embedded JavaScript (/JS)' }
            @{ K = '/OpenAction';  Sev = 'HIGH';   Cat = 'active-content'; TestID = 'PDF-OPENACTION';   Msg = 'action triggered automatically on open' }
            @{ K = '/AA';          Sev = 'HIGH';   Cat = 'active-content'; TestID = 'PDF-AUTO-ACTION';  Msg = 'additional (automatic) actions' }
            @{ K = '/Launch';      Sev = 'HIGH';   Cat = 'active-content'; TestID = 'PDF-LAUNCH';       Msg = 'launch action (can run external programs)' }
            @{ K = '/EmbeddedFile';Sev = 'MEDIUM'; Cat = 'active-content'; TestID = 'PDF-EMBEDDED-FILE'; Msg = 'embedded file (possible hidden payload)' }
            @{ K = '/RichMedia';   Sev = 'MEDIUM'; Cat = 'active-content'; TestID = 'PDF-RICHMEDIA';    Msg = 'rich media (Flash/video) content' }
            @{ K = '/URI';         Sev = 'LOW';    Cat = 'active-content'; TestID = 'PDF-URI';          Msg = 'external URI link' }
            @{ K = '/Encrypt';     Sev = 'INFO';   Cat = 'parser';        TestID = 'PDF-ENCRYPTED';     Msg = 'encrypted PDF — some content may be uninspectable' }
        )

        $findings = [System.Collections.Generic.List[object]]::new()
        # Avoid double-counting /JS inside /JavaScript: count /JavaScript first, then
        # /JS occurrences that are not part of /JavaScript.
        $jsFull = ([regex]::Matches($deob, [regex]::Escape('/JavaScript'))).Count
        foreach ($kw in $keywords) {
            if ($kw.K -eq '/JS') {
                $allJs = ([regex]::Matches($deob, '/JS(?![a-zA-Z])')).Count
                $count = $allJs
            } elseif ($kw.K -eq '/JavaScript') {
                $count = $jsFull
            } else {
                $count = ([regex]::Matches($deob, [regex]::Escape($kw.K))).Count
            }
            if ($count -gt 0) {
                $findings.Add((New-Finding -Tool 'PdfTriage' -Category $kw.Cat -Severity $kw.Sev `
                    -Confidence 'MEDIUM' -UnitType 'pdf' -File $Unit.RelativePath `
                    -Issue ("PDF contains {0} ({1} occurrence(s) of {2})." -f $kw.Msg, $count, $kw.K) `
                    -TestID $kw.TestID `
                    -Recommendation 'Review the active content; PDFs that auto-run JS or launch programs are high-risk.'))
            }
        }

        Write-Log -Level INFO -Message "PdfTriage: $($findings.Count) keyword finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
