#Requires -Version 7.4
<#
    PSScriptAnalyzer analyzer — static analysis of PowerShell scripts.

    Three layers on powershell units (.ps1/.psm1/.psd1) and PowerShell content
    detected via the classifier (v0.2 disguised scripts):

    1. PSScriptAnalyzer (PS module): structural/best-practice/security rules
       (PSAvoidUsingInvokeExpression, plaintext-password rules, etc.). Static AST
       analysis — never runs the script.
    2. Custom token rules (always attempted, no module needed): high-signal
       execution, download, obfuscation, antimalware-tampering, and policy-bypass
       indicators. The preferred stdlib-only Python helper and the PowerShell
       fallback both compare SHA-256 token identities; neither stores or rebuilds
       indicator text. Any resource or execution limit is an explicit HIGH gap.
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

        $addRuleGap = {
            param(
                [Parameter(Mandatory)][string]$TestID,
                [Parameter(Mandatory)][string]$Issue
            )
            $findings.Add((New-Finding -Tool 'PowerShellRules' -Category 'parser' `
                -Severity 'HIGH' -Confidence 'HIGH' -UnitType 'powershell' `
                -File $Unit.RelativePath -Issue $Issue -TestID $TestID `
                -Recommendation 'Treat the file as suspicious and inspect it in isolation; absence of static-rule findings is not proof that the file is clean.'))
        }

        try {
            $ruleInputLength = (Get-Item -LiteralPath $target -ErrorAction Stop).Length
        } catch {
            & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                -Issue "Static PowerShell rule scanning could not inspect the input size, so this unit was NOT fully analyzed: $_"
            $ruleScanComplete = $true
        }

        if (-not $ruleScanComplete -and $ruleInputLength -gt $script:MtsPowerShellRuleMaxBytes) {
            & $addRuleGap -TestID 'MTS-PSSRULES-LIMIT' `
                -Issue "Static PowerShell rule scanning skipped this $ruleInputLength-byte file because it exceeds the $script:MtsPowerShellRuleMaxBytes-byte analysis limit; this unit was NOT fully analyzed."
            $ruleScanComplete = $true
        }

        $helperAvailable = $pythonExe -and $helper -and (Test-Path -LiteralPath $helper -PathType Leaf)
        if (-not $ruleScanComplete -and $helperAvailable) {
            $tmpJson = Join-Path $env:TEMP "mts_psrules_$([IO.Path]::GetRandomFileName()).json"
            try {
                $result = Invoke-BoundedProcess -FilePath $pythonExe `
                    -Arguments @($helper, $target, $tmpJson) -TimeoutSeconds $timeoutSeconds

                if (-not $result.Started) {
                    $findings.Add((New-ToolBlockedFinding -Tool 'PowerShellRules' `
                        -UnitType 'powershell' -File $Unit.RelativePath -Reason $result.StartError))
                } elseif ($result.TimedOut) {
                    $findings.Add((New-TimeoutFinding -Tool 'PowerShellRules' `
                        -UnitType 'powershell' -File $Unit.RelativePath -TimeoutSeconds $timeoutSeconds))
                } elseif ($result.ExitCode -ne 0) {
                    & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                        -Issue "The bounded static PowerShell rule helper exited with code $($result.ExitCode), so this unit was NOT fully analyzed."
                } elseif (-not (Test-Path -LiteralPath $tmpJson -PathType Leaf)) {
                    & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                        -Issue 'The bounded static PowerShell rule helper produced no result, so this unit was NOT fully analyzed.'
                } else {
                    $raw = Get-Content -LiteralPath $tmpJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if (-not $raw.PSObject.Properties['scanned'] -or
                        -not $raw.PSObject.Properties['findings']) {
                        & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                            -Issue 'The bounded static PowerShell rule helper returned an invalid result, so this unit was NOT fully analyzed.'
                    } elseif ([int]$raw.scanned -ne 1) {
                        $helperError = if ($raw.PSObject.Properties['error'] -and $raw.error) {
                            ": $($raw.error)"
                        } else { '' }
                        $helperFailureId = if ($helperError -match 'size limit') {
                            'MTS-PSSRULES-LIMIT'
                        } else { 'MTS-PSSRULES-FAILED' }
                        & $addRuleGap -TestID $helperFailureId `
                            -Issue "The bounded static PowerShell rule helper declined the input$helperError; this unit was NOT fully analyzed."
                    } else {
                        foreach ($finding in @($raw.findings)) {
                            $findings.Add((New-Finding -Tool 'PowerShellRules' -Category $finding.category `
                                -Severity $finding.severity -Confidence $finding.confidence -UnitType 'powershell' `
                                -File $Unit.RelativePath -Line ([int]$finding.line) `
                                -Issue $finding.issue -TestID $finding.testId))
                        }
                    }
                }
            } catch {
                & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                    -Issue "The bounded static PowerShell rule helper returned an unreadable result, so this unit was NOT fully analyzed: $_"
            } finally {
                Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
            }
            # An attempted bounded helper is authoritative. Retrying the same
            # hostile input in-process would defeat its wall-clock boundary.
            $ruleScanComplete = $true
        }

        if (-not $ruleScanComplete) {
            $stream = $null
            try {
                $stream = [IO.FileStream]::new(
                    $target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                $buffer = [byte[]]::new($script:MtsPowerShellFallbackMaxBytes + 1)
                $bytesRead = 0
                while ($bytesRead -lt $buffer.Length) {
                    $read = $stream.Read($buffer, $bytesRead, $buffer.Length - $bytesRead)
                    if ($read -eq 0) { break }
                    $bytesRead += $read
                }
                if ($bytesRead -gt $script:MtsPowerShellFallbackMaxBytes) {
                    & $addRuleGap -TestID 'MTS-PSSRULES-LIMIT' `
                        -Issue "The in-process static PowerShell fallback stopped after its $script:MtsPowerShellFallbackMaxBytes-byte safety limit; this unit was NOT fully analyzed."
                } else {
                    $snapshot = [byte[]]::new($bytesRead)
                    if ($bytesRead -gt 0) { [Array]::Copy($buffer, $snapshot, $bytesRead) }
                    $text = (ConvertFrom-MtsContentBytes -Bytes $snapshot).Text
                    $limitReason = ''
                    foreach ($match in @(Find-MtsPowerShellRiskIndicator -Text $text `
                        -MaxTokens $script:MtsPowerShellFallbackMaxTokens `
                        -MaxResults $script:MtsPowerShellFallbackMaxFindings `
                        -MaxMilliseconds $script:MtsPowerShellFallbackMaxMilliseconds `
                        -LimitReason ([ref]$limitReason))) {
                        $rule = $match.Rule
                        $findings.Add((New-Finding -Tool 'PowerShellRules' -Category 'risky-code' `
                            -Severity $rule.Severity -Confidence 'MEDIUM' -UnitType 'powershell' `
                            -File $Unit.RelativePath -Line $match.Line -Issue $rule.Message -TestID $rule.TestID))
                    }
                    if ($limitReason) {
                        & $addRuleGap -TestID 'MTS-PSSRULES-LIMIT' `
                            -Issue "The in-process static PowerShell fallback reached its $limitReason and stopped; this unit was NOT fully analyzed."
                    }
                }
                $ruleScanComplete = $true
            } catch {
                & $addRuleGap -TestID 'MTS-PSSRULES-FAILED' `
                    -Issue "The in-process static PowerShell fallback failed, so this unit was NOT fully analyzed: $_"
                $ruleScanComplete = $true
            } finally {
                if ($stream) { $stream.Dispose() }
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
