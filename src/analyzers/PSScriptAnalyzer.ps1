#Requires -Version 7.4
<#
    PSScriptAnalyzer analyzer — static analysis of PowerShell scripts (PLAN §4 v0.5).

    Three layers on powershell units (.ps1/.psm1/.psd1) and PowerShell content
    detected via the classifier (v0.2 disguised scripts):

    1. PSScriptAnalyzer (PS module): structural/best-practice/security rules
       (PSAvoidUsingInvokeExpression, plaintext-password rules, etc.). Static AST
       analysis — never runs the script.
    2. Custom risky-pattern rules (always run, no module needed): the high-signal
       offensive-PowerShell indicators — IEX, DownloadString, -EncodedCommand,
       FromBase64String, hidden-window launch, AMSI/Defender tampering.
    3. Authenticode signature status (Get-AuthenticodeSignature) — a tampered
       signed file (HashMismatch) is HIGH; valid/unsigned are recorded as INFO.

    All analysis is STATIC — the script is parsed, never executed.
    Tier: core.
#>
@{
    Name           = 'PSScriptAnalyzer'
    Version        = '0.1.0'
    UnitTypes      = @('powershell')
    RequiredTools  = @(@{ Kind = 'psmodule'; Id = 'PSScriptAnalyzer'; MinVersion = '1.20.0' })
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $target = $Unit.Path
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { return @() }

        $findings = [System.Collections.Generic.List[object]]::new()

        # ── Layer 1: PSScriptAnalyzer ────────────────────────────────────────
        $tool = $Context.Tools['PSScriptAnalyzer']
        if ($tool -and $tool.Available) {
            try {
                Import-Module PSScriptAnalyzer -ErrorAction Stop
                $records = Invoke-ScriptAnalyzer -Path $target -Severity @('Error','Warning','Information') -ErrorAction Stop
                foreach ($r in @($records)) {
                    $sev = switch ([string]$r.Severity) {
                        'Error'       { 'HIGH' }
                        'Warning'     { 'MEDIUM' }
                        'Information' { 'LOW' }
                        default       { 'INFO' }
                    }
                    $findings.Add((New-Finding -Tool 'PSScriptAnalyzer' -Category 'risky-code' `
                        -Severity $sev -Confidence 'HIGH' -UnitType 'powershell' `
                        -File $Unit.RelativePath -Line ([int]$r.Line) `
                        -Issue "$($r.Message) [$($r.RuleName)]" -TestID $r.RuleName))
                }
                Write-Log -Level INFO -Message "PSScriptAnalyzer: $($findings.Count) finding(s) in $($Unit.RelativePath)."
            } catch {
                Write-Log -Level WARN -Message "PSScriptAnalyzer: invocation error for $($Unit.RelativePath): $_"
            }
        } else {
            $findings.Add((New-Finding -Tool 'PSScriptAnalyzer' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'powershell' -File $Unit.RelativePath `
                -Issue 'PSScriptAnalyzer module not available — structural analysis skipped (custom rules + signature still applied).' `
                -TestID 'MTS-PSSA-UNAVAIL'))
        }

        # ── Layer 2: Custom risky-pattern rules (always) ─────────────────────
        try {
            $text = [IO.File]::ReadAllText($target, [System.Text.Encoding]::UTF8)
            $rules = @(
                @{ Re = '(?i)\b(Invoke-Expression|IEX)\b'; Sev='HIGH'; TID='PS-IEX'
                   Msg='Invoke-Expression / IEX — executes a dynamically-built string' }
                @{ Re = '(?i)\.(DownloadString|DownloadFile|DownloadData)\s*\('; Sev='HIGH'; TID='PS-DOWNLOAD'
                   Msg='Net.WebClient download method — remote payload retrieval' }
                @{ Re = '(?i)-EncodedCommand\b|(?i)\s-enc\b'; Sev='HIGH'; TID='PS-ENCODED-COMMAND'
                   Msg='-EncodedCommand — base64-encoded command (common obfuscation)' }
                @{ Re = '(?i)FromBase64String\s*\('; Sev='MEDIUM'; TID='PS-BASE64-DECODE'
                   Msg='Convert.FromBase64String — decoding an embedded payload' }
                @{ Re = '(?i)-WindowStyle\s+Hidden\b'; Sev='MEDIUM'; TID='PS-HIDDEN-WINDOW'
                   Msg='-WindowStyle Hidden — launches with no visible window' }
                @{ Re = '(?i)(amsiInitFailed|AmsiUtils|AmsiScanBuffer)'; Sev='HIGH'; TID='PS-AMSI-TAMPER'
                   Msg='AMSI tampering reference — attempts to disable malware scanning' }
                @{ Re = '(?i)(Add-MpPreference|Set-MpPreference)\b'; Sev='HIGH'; TID='PS-DEFENDER-TAMPER'
                   Msg='Microsoft Defender preference modification (e.g. exclusion / disable real-time)' }
                @{ Re = '(?i)-ExecutionPolicy\s+Bypass\b'; Sev='LOW'; TID='PS-EXEC-BYPASS'
                   Msg='-ExecutionPolicy Bypass — circumvents script execution policy' }
            )
            foreach ($rule in $rules) {
                foreach ($m in [regex]::Matches($text, $rule.Re)) {
                    $lineNum = ($text.Substring(0, $m.Index) -split '\r?\n').Count
                    $findings.Add((New-Finding -Tool 'PowerShellRules' -Category 'risky-code' `
                        -Severity $rule.Sev -Confidence 'MEDIUM' -UnitType 'powershell' `
                        -File $Unit.RelativePath -Line $lineNum -Issue $rule.Msg -TestID $rule.TID))
                }
            }
        } catch {
            Write-Log -Level WARN -Message "PowerShellRules: scan error for $($Unit.RelativePath): $_"
        }

        # ── Layer 3: Authenticode signature status ───────────────────────────
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
            switch ([string]$sig.Status) {
                'HashMismatch' {
                    $findings.Add((New-Finding -Tool 'Authenticode' -Category 'risky-code' -Severity 'HIGH' `
                        -Confidence 'HIGH' -UnitType 'powershell' -File $Unit.RelativePath `
                        -Issue 'Authenticode signature is present but the file hash does not match — file was modified after signing.' `
                        -TestID 'PS-SIG-HASHMISMATCH' `
                        -Recommendation 'Reject — a broken signature indicates tampering.'))
                }
                'Valid' {
                    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'unknown' }
                    $findings.Add((New-Finding -Tool 'Authenticode' -Category 'parser' -Severity 'INFO' `
                        -Confidence 'HIGH' -UnitType 'powershell' -File $Unit.RelativePath `
                        -Issue "Authenticode signature: Valid (signer: $signer)." -TestID 'PS-SIG-VALID'))
                }
                default {
                    $findings.Add((New-Finding -Tool 'Authenticode' -Category 'parser' -Severity 'INFO' `
                        -Confidence 'HIGH' -UnitType 'powershell' -File $Unit.RelativePath `
                        -Issue "Authenticode signature: $($sig.Status) (script is not validly signed)." -TestID 'PS-SIG-UNSIGNED'))
                }
            }
        } catch {
            Write-Log -Level DEBUG -Message "Authenticode check skipped for $($Unit.RelativePath): $_"
        }

        return $findings.ToArray()
    }
}
