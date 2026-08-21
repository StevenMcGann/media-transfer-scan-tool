#Requires -Version 7.4
<#
    VbaRules analyzer — curated, high-signal static analysis of VB-family source
    (issue #25). Covers exported VBA modules (.bas/.cls/.frm/.vba) and VBScript
    and its wrappers (.vbs/.vbe/.wsf/.hta), plus VB content the classifier detects
    under a disguised extension.

    Pure PowerShell, no helper and no pip package — deliberately, following the
    PdfTriage precedent rather than the OleVbaScan one. VB source is text; regex
    rules need no interpreter. That means this layer works air-gapped and with no
    provisioning at all, where the Office path degrades to OFFICE-OLEVBA-UNAVAIL
    when oletools is missing.

    Scope boundary: this analyzes STANDALONE VB source. Macros embedded inside
    Office containers stay with OleVbaScan (vbaProject.bin presence, DDE, remote
    template, olevba keywords). Running these same rules over module source
    extracted from a container is the follow-up phase, not this one.

    Reported severity mirrors the PythonRules philosophy: individual primitives are
    rated on their own merit, and the combinations that only make sense in a
    dropper (auto-exec + payload, download + execute) escalate to CRITICAL.

    All analysis is STATIC — the file is read as text. Nothing is executed, no
    Office application is launched, no macro is run.

    Tier: core (default-on). These are attacker-grade indicators, not style rules.
#>
@{
    Name           = 'VbaRules'
    Version        = '0.1.0'
    UnitTypes      = @('vba')
    RequiredTools  = @()
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $target = $Unit.Path
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { return @() }

        $findings = [System.Collections.Generic.List[object]]::new()
        $ext      = [IO.Path]::GetExtension($Unit.Name).ToLowerInvariant()

        # .vbe is Microsoft Script Encoder output — obfuscated by design, so the
        # rules below cannot see the real source. Say so rather than returning a
        # clean result (no silent coverage gaps).
        if ($ext -eq '.vbe') {
            $findings.Add((New-Finding -Tool 'VbaRules' -Category 'parser' -Severity 'MEDIUM' `
                -Confidence 'HIGH' -UnitType 'vba' -File $Unit.RelativePath `
                -Issue 'Encoded VBScript (.vbe) — source is obfuscated by the Script Encoder and cannot be statically analyzed.' `
                -TestID 'VBA-ENCODED-SOURCE' `
                -Recommendation 'Treat as opaque: an encoded script in a transfer is itself a reason to reject or escalate to manual review.'))
        }

        try {
            $text = [IO.File]::ReadAllText($target, [System.Text.Encoding]::UTF8)
        } catch {
            Write-Log -Level WARN -Message "VbaRules: could not read $($Unit.RelativePath): $_"
            return @(New-Finding -Tool 'VbaRules' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'vba' -File $Unit.RelativePath `
                -Issue "VB source could not be read: $_" -TestID 'MTS-VBA-ERR')
        }

        # .hta and .wsf are language-NEUTRAL wrappers: they host JScript just as
        # readily as VBScript. Routing them to this analyzer by extension alone
        # would mean a JScript dropper — `new ActiveXObject("WScript.Shell").Run(...)`,
        # which matches none of the VB rules below — is claimed by VbaRules, found
        # clean, and suppressed from the engine's MTS-NO-ANALYZER notice. Silent, and
        # falsely reassuring. Say so instead.
        if ($ext -in @('.hta', '.wsf')) {
            $declaresNonVb = $text -match '(?i)language\s*=\s*["'']?\s*(jscript|javascript|ecmascript)'
            $hasVbMarker   = $text -match '(?i)(language\s*=\s*["'']?\s*vbscript|\bCreateObject\s*\(|\bWScript\.\w|(?m)^\s*(Public\s+|Private\s+)?Sub\s+\w+|(?m)^\s*Dim\s+\w+)'
            if ($declaresNonVb -or -not $hasVbMarker) {
                $lang = if ($declaresNonVb) { 'JScript/JavaScript' } else { 'a non-VB or undetermined' }
                $findings.Add((New-Finding -Tool 'VbaRules' -Category 'parser' -Severity 'MEDIUM' `
                    -Confidence 'HIGH' -UnitType 'vba' -File $Unit.RelativePath `
                    -Issue ("Script wrapper hosts $lang content, which the VB rules do NOT analyze — the embedded script was not inspected.") `
                    -TestID 'VBA-NON-VB-SCRIPT' `
                    -Recommendation ('.hta/.wsf can host any scripting engine. Absence of VB findings here is ' +
                                     'absence of coverage: review the embedded script by hand, and treat an ' +
                                     'executable wrapper in a transfer as suspicious on its own.')))
            }
        }

        # Single-pattern rules. Category must come from the frozen contract enum
        # (docs/contract.md) — 'macro', 'risky-code', 'parser'; no new categories.
        $patterns = @(
            @{ Re  = '(?im)^\s*(Public\s+|Private\s+)?Sub\s+(Auto_?Open|Auto_?Close|Auto_?Exec|AutoNew|Document_Open|Document_Close|Document_New|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|Worksheet_Activate)\b'
               Sev = 'HIGH'; Cat = 'macro'; Conf = 'HIGH'
               Msg = 'Auto-executing entry point — runs on open/close without user action'
               TID = 'VBA-AUTOEXEC'
               Rec = 'Auto-exec entry points are the standard macro-dropper trigger. Review what the procedure does.' }

            # 'Shell "cmd"' / 'Shell("cmd")'. The lookbehind keeps WScript.Shell and
            # Shell.Application (their own rule below) from double-reporting here.
            @{ Re  = '(?i)(?<![\w.])Shell\s*[\("'']'
               Sev = 'HIGH'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Shell() process launch'
               TID = 'VBA-SHELL' }

            @{ Re  = '(?i)CreateObject\s*\(\s*["''](WScript\.Shell|Shell\.Application)["'']'
               Sev = 'HIGH'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Shell automation object created (WScript.Shell / Shell.Application) — arbitrary command execution'
               TID = 'VBA-WSCRIPT-SHELL' }

            @{ Re  = '(?i)(URLDownloadToFile|MSXML2\.(XMLHTTP|ServerXMLHTTP)|WinHttp\.WinHttpRequest|InternetExplorer\.Application)'
               Sev = 'HIGH'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Network fetch primitive — downloads remote content'
               TID = 'VBA-DOWNLOAD' }

            @{ Re  = '(?i)ADODB\.Stream'
               Sev = 'MEDIUM'; Cat = 'risky-code'; Conf = 'MEDIUM'
               Msg = 'ADODB.Stream — writes arbitrary bytes to disk (common pairing with a download)'
               TID = 'VBA-STREAM-WRITE' }

            @{ Re  = '(?i)\bpowershell(\.exe)?\b[^\r\n]{0,120}?\s-(enc\b|encodedcommand\b|e\s|nop\b|noprofile\b|w\s+hidden|windowstyle\s+hidden)'
               Sev = 'HIGH'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Hidden/encoded PowerShell invocation'
               TID = 'VBA-POWERSHELL-ENC'
               Rec = 'Decode the -EncodedCommand payload before making a disposition decision.' }

            @{ Re  = '(?im)^\s*(Public\s+|Private\s+)?Declare\s+(PtrSafe\s+)?(Sub|Function)\s+\w+\s+Lib\s+["'']'
               Sev = 'MEDIUM'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Declares a native Win32 API import — VB source reaching outside the VB runtime'
               TID = 'VBA-NATIVE-DECLARE' }

            @{ Re  = '(?i)\b(VirtualAlloc|VirtualProtect|RtlMoveMemory|CreateThread|CreateRemoteThread|WriteProcessMemory|SetWindowsHookEx|NtAllocateVirtualMemory)\b'
               Sev = 'CRITICAL'; Cat = 'risky-code'; Conf = 'HIGH'
               Msg = 'Memory-allocation / thread-creation API — the standard VBA shellcode-injection primitive'
               TID = 'VBA-SHELLCODE-API'
               Rec = 'There is no benign reason for document macro code to allocate executable memory. Reject.' }

            @{ Re  = '(?i)(\bRegWrite\b|CurrentVersion\\+Run)'
               Sev = 'MEDIUM'; Cat = 'risky-code'; Conf = 'MEDIUM'
               Msg = 'Registry write / Run-key reference — persistence mechanism'
               TID = 'VBA-REGISTRY-PERSIST' }

            @{ Re  = '(?i)\bStrReverse\s*\('
               Sev = 'MEDIUM'; Cat = 'risky-code'; Conf = 'MEDIUM'
               Msg = 'StrReverse() — string obfuscation, commonly hides an object or URL name'
               TID = 'VBA-OBFUSCATION-STRREVERSE' }

            @{ Re  = '(?i)\bCallByName\s*\('
               Sev = 'MEDIUM'; Cat = 'risky-code'; Conf = 'MEDIUM'
               Msg = 'CallByName() — late-bound dynamic dispatch, hides the called member from static review'
               TID = 'VBA-OBFUSCATION-CALLBYNAME' }

            @{ Re  = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
               Sev = 'LOW'; Cat = 'risky-code'; Conf = 'LOW'
               Msg = 'Hardcoded IPv4 address — possible C2 endpoint'
               TID = 'VBA-HARDCODED-IP' }
        )

        foreach ($p in $patterns) {
            # 'Rec' is optional per rule; ContainsKey, not $p.Rec — Set-StrictMode
            # -Version Latest throws on a missing hashtable member.
            $rec = if ($p.ContainsKey('Rec')) { $p['Rec'] } else { '' }
            # One finding per rule per line. A single 'Declare ... URLDownloadToFile
            # Alias "URLDownloadToFileA"' would otherwise report the same rule three
            # times for one declaration — noise in a triage report.
            $seenLines = [System.Collections.Generic.HashSet[int]]::new()
            foreach ($m in [regex]::Matches($text, $p.Re)) {
                $lineNum = ($text.Substring(0, $m.Index) -split '\r?\n').Count
                if (-not $seenLines.Add($lineNum)) { continue }
                $findings.Add((New-Finding -Tool 'VbaRules' -Category $p.Cat `
                    -Severity $p.Sev -Confidence $p.Conf -UnitType 'vba' `
                    -File $Unit.RelativePath -Line $lineNum `
                    -Issue $p.Msg -TestID $p.TID -Recommendation $rec))
            }
        }

        # Chr()/ChrW() chains: one is ordinary string building, a run of them is a
        # hand-assembled string hiding from exactly this kind of review. Counted
        # per file rather than reported per match.
        $chrCount = [regex]::Matches($text, '(?i)\bChr[W$]?\s*\(').Count
        if ($chrCount -ge 5) {
            $findings.Add((New-Finding -Tool 'VbaRules' -Category 'risky-code' `
                -Severity 'MEDIUM' -Confidence 'MEDIUM' -UnitType 'vba' `
                -File $Unit.RelativePath `
                -Issue "Character-code obfuscation: $chrCount Chr()/ChrW() calls assemble strings at runtime." `
                -TestID 'VBA-OBFUSCATION-CHR'))
        }

        # ── Combination escalation (PythonRules §combination precedent) ───────
        # Individually these are defensible; together they describe a dropper.
        $ids        = @($findings | ForEach-Object { $_.TestID })
        $hasAutoExec = $ids -contains 'VBA-AUTOEXEC'
        $hasExec     = @('VBA-SHELL', 'VBA-WSCRIPT-SHELL', 'VBA-POWERSHELL-ENC', 'VBA-SHELLCODE-API') |
                        Where-Object { $ids -contains $_ }
        $hasDownload = @('VBA-DOWNLOAD', 'VBA-STREAM-WRITE') |
                        Where-Object { $ids -contains $_ }

        if ($hasDownload -and $hasExec) {
            $findings.Add((New-Finding -Tool 'VbaRules' -Category 'risky-code' `
                -Severity 'CRITICAL' -Confidence 'HIGH' -UnitType 'vba' `
                -File $Unit.RelativePath `
                -Issue 'Download-and-execute: this module both retrieves remote content and launches a process.' `
                -TestID 'VBA-DOWNLOAD-EXEC' `
                -Recommendation 'Classic dropper shape. Reject unless the source and destination are both known-good.'))
        }
        if ($hasAutoExec -and ($hasExec -or $hasDownload)) {
            $findings.Add((New-Finding -Tool 'VbaRules' -Category 'macro' `
                -Severity 'CRITICAL' -Confidence 'HIGH' -UnitType 'vba' `
                -File $Unit.RelativePath `
                -Issue 'Auto-executing entry point combined with process launch or network fetch — payload runs on open.' `
                -TestID 'VBA-AUTOEXEC-PAYLOAD' `
                -Recommendation 'No user interaction is required to trigger this. Treat as malicious until proven otherwise.'))
        }

        Write-Log -Level INFO -Message "VbaRules: $($findings.Count) finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
