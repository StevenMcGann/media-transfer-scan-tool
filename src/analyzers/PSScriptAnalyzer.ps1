#Requires -Version 7.4
<#
    PSScriptAnalyzer analyzer — static analysis of PowerShell scripts.

    Three layers on powershell units (.ps1/.psm1/.psd1) and PowerShell content
    detected via the classifier (v0.2 disguised scripts):

    1. PSScriptAnalyzer (PS module): structural/best-practice/security rules
       (PSAvoidUsingInvokeExpression, plaintext-password rules, etc.). Static AST
       analysis — never runs the script.
    2. Custom token rules (always run, no module needed): high-signal execution,
       download, obfuscation, antimalware-tampering, and policy-bypass indicators.
       The preferred stdlib-only Python helper and the PowerShell fallback both
       compare SHA-256 token identities; neither stores or rebuilds indicator text.
    3. Authenticode signature status (Get-AuthenticodeSignature) — a tampered
       signed file (HashMismatch) is HIGH; valid/unsigned are recorded as INFO.

    All analysis is STATIC — the script is parsed, never executed.
    Tier: core.
#>
@{
    Name           = 'PSScriptAnalyzer'
    Version        = '0.2.0'
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
                # Import the EXACT resolved/pinned version. By name alone, a host
                # with a newer side-by-side copy would load that instead, silently
                # bypassing the F3 pin (Import-Module defaults to the highest version).
                if ($tool.PSObject.Properties['Version'] -and $tool.Version) {
                    Import-Module PSScriptAnalyzer -RequiredVersion $tool.Version -ErrorAction Stop
                } else {
                    Import-Module PSScriptAnalyzer -ErrorAction Stop
                }
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

        # ── Layer 2: token-hash risky rules (always) ─────────────────────────
        $ruleStart = $findings.Count
        $ruleScanComplete = $false
        $contextVenv = if ($Context.PSObject.Properties['Venv']) { $Context.Venv } else { $null }
        $pythonExe = if ($null -ne $contextVenv -and $contextVenv.PSObject.Properties['Python']) {
            $contextVenv.Python
        } else { Find-Python }
        $helperDir = if ($Context.PSObject.Properties['HelperDir']) { [string]$Context.HelperDir } else { '' }
        $helper = if ($helperDir) { Join-Path $helperDir 'scan_powershell.py' } else { '' }
        $timeoutSeconds = if ($Context.PSObject.Properties['TimeoutSeconds']) {
            [int]$Context.TimeoutSeconds
        } else { 300 }

        if ($pythonExe -and $helper -and (Test-Path -LiteralPath $helper -PathType Leaf)) {
            $tmpJson = Join-Path $env:TEMP "mts_psrules_$([IO.Path]::GetRandomFileName()).json"
            try {
                $result = Invoke-BoundedProcess -FilePath $pythonExe `
                    -Arguments @($helper, $target, $tmpJson) -TimeoutSeconds $timeoutSeconds
                if (-not $result.TimedOut -and $result.ExitCode -eq 0 -and
                    (Test-Path -LiteralPath $tmpJson -PathType Leaf)) {
                    $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                    if ([int]$raw.scanned -eq 1) {
                        foreach ($finding in @($raw.findings)) {
                            $findings.Add((New-Finding -Tool 'PowerShellRules' -Category $finding.category `
                                -Severity $finding.severity -Confidence $finding.confidence -UnitType 'powershell' `
                                -File $Unit.RelativePath -Line ([int]$finding.line) `
                                -Issue $finding.issue -TestID $finding.testId))
                        }
                        $ruleScanComplete = $true
                    }
                }
                if (-not $ruleScanComplete) {
                    $why = if ($result.TimedOut) { 'timed out' } else { "exited $($result.ExitCode)" }
                    Write-Log -Level WARN -Message "PowerShellRules helper $why for $($Unit.RelativePath); using safe token-hash fallback."
                }
            } catch {
                Write-Log -Level WARN -Message "PowerShellRules helper error for $($Unit.RelativePath): $_; using safe token-hash fallback."
            } finally {
                Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not $ruleScanComplete) {
            try {
                $text = [IO.File]::ReadAllText($target, [Text.Encoding]::UTF8)
                foreach ($match in @(Find-MtsPowerShellRiskIndicator -Text $text)) {
                    $rule = $match.Rule
                    $findings.Add((New-Finding -Tool 'PowerShellRules' -Category 'risky-code' `
                        -Severity $rule.Severity -Confidence 'MEDIUM' -UnitType 'powershell' `
                        -File $Unit.RelativePath -Line $match.Line -Issue $rule.Message -TestID $rule.TestID))
                }
                $ruleScanComplete = $true
            } catch {
                Write-Log -Level WARN -Message "PowerShellRules fallback error for $($Unit.RelativePath): $_"
            }
        }
        Write-Log -Level INFO -Message "PowerShellRules: $($findings.Count - $ruleStart) finding(s) in $($Unit.RelativePath)."

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
