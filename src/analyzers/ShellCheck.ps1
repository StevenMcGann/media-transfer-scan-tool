#Requires -Version 7.4
<#
    ShellCheck analyzer — static analysis of shell scripts (PLAN §4 v0.4).

    Two-layer analysis on shell units (.sh/.bash/.zsh/.ksh) and on shell
    content detected via the classifier (disguised scripts, v0.2):

    1. ShellCheck (via shellcheck-py pip package, which bundles the shellcheck
       binary): full structural static analysis — undefined variables, quoting
       bugs, command injection, dangerous constructs.

    2. Custom risky-pattern scan (pure PowerShell, always runs even if ShellCheck
       is unavailable): catches patterns ShellCheck intentionally does not flag as
       errors because they are "valid" shell but operationally dangerous in a
       media-transfer context:
         - curl/wget | bash|sh (remote-fetch-and-execute)
         - base64 -d | bash|sh (decode-and-execute)
         - eval with variable expansion
         - chmod 777 / chmod a+rwx (world-writable)
         - Hardcoded IPv4 addresses (C2 beacons)

    Tier: core (shell-script risky patterns are targeted and high-signal).
    All analysis is STATIC — the script is read, never executed.
#>
@{
    Name           = 'ShellCheck'
    Version        = '0.1.0'
    UnitTypes      = @('shell')
    RequiredTools  = @(@{ Kind = 'pip'; Id = 'shellcheck-py'; MinVersion = '0.9.0'; BundlePath = $null })
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $target = $Unit.Path
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { return @() }

        $findings = [System.Collections.Generic.List[object]]::new()

        # ── Layer 1: ShellCheck ──────────────────────────────────────────────
        $tool = $Context.Tools['shellcheck-py']
        if ($tool -and $tool.Available) {
            # shellcheck-py installs the binary as 'shellcheck' (no .exe suffix on PATH;
            # on Windows the Scripts dir has shellcheck.exe)
            $scExe = Join-Path $tool.ScriptsDir 'shellcheck.exe'
            if (-not (Test-Path -LiteralPath $scExe)) {
                $scExe = Join-Path $tool.ScriptsDir 'shellcheck'
            }

            if (Test-Path -LiteralPath $scExe) {
                $tmpJson = Join-Path $env:TEMP "mts_sc_$([IO.Path]::GetRandomFileName()).json"
                try {
                    # Write JSON to a file (not stdout) — matches pattern used by all
                    # other analyzers and avoids 2>&1 corrupting the JSON stream.
                    # Exit 0 = clean; exit 1 = findings; exit >1 = error.
                    & $scExe -f json1 $target 2>$null | Set-Content -LiteralPath $tmpJson -Encoding utf8
                    $exit = $LASTEXITCODE
                    if ($exit -gt 1) {
                        Write-Log -Level WARN -Message "ShellCheck: unexpected exit $exit for $($Unit.RelativePath)."
                    } elseif (Test-Path -LiteralPath $tmpJson) {
                        $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                        # shellcheck -f json1 wraps results in { "comments": [...] }
                        $entries = if ($raw.PSObject.Properties['comments']) { @($raw.comments) } else { @($raw) }
                        foreach ($entry in $entries) {
                            $sev = switch ($entry.level) {
                                'error'   { 'HIGH' }
                                'warning' { 'MEDIUM' }
                                'info'    { 'LOW' }
                                default   { 'INFO' }
                            }
                            $findings.Add((New-Finding -Tool 'ShellCheck' -Category 'risky-code' `
                                -Severity $sev -Confidence 'HIGH' -UnitType 'shell' `
                                -File $Unit.RelativePath -Line ([int]$entry.line) `
                                -Issue "$($entry.message) [SC$($entry.code)]" `
                                -TestID "SC$($entry.code)" `
                                -Recommendation "See https://www.shellcheck.net/wiki/SC$($entry.code)"))
                        }
                        Write-Log -Level INFO -Message "ShellCheck: $($findings.Count) finding(s) in $($Unit.RelativePath)."
                    }
                } catch {
                    Write-Log -Level WARN -Message "ShellCheck: invocation error for $($Unit.RelativePath): $_"
                    $findings.Add((New-Finding -Tool 'ShellCheck' -Category 'parser' -Severity 'LOW' `
                        -Confidence 'LOW' -UnitType 'shell' -File $Unit.RelativePath `
                        -Issue "ShellCheck error: $_" -TestID 'MTS-SC-ERR'))
                } finally {
                    Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
                }
            } else {
                Write-Log -Level WARN -Message "ShellCheck binary not found in $($tool.ScriptsDir) — skipping ShellCheck pass."
            }
        } else {
            $findings.Add((New-Finding -Tool 'ShellCheck' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'shell' -File $Unit.RelativePath `
                -Issue 'ShellCheck not available — install shellcheck-py for full shell static analysis.' `
                -TestID 'MTS-SC-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or vendor shellcheck-py in the offline bundle.'))
        }

        # ── Layer 2: Risky-pattern scan (always runs) ─────────────────────────
        try {
            $text = [IO.File]::ReadAllText($target, [System.Text.Encoding]::UTF8)
            $patterns = @(
                @{ Re = '(?i)(curl|wget)\s+\S+\s*\|\s*(bash|sh)\b'
                   Sev = 'HIGH'; Msg = 'Remote-fetch-and-execute: downloads and pipes script directly to shell'
                   TID = 'SHELL-REMOTE-EXEC' }
                @{ Re = '(?i)base64\s+(-d|--decode)\s*\|\s*(bash|sh)\b'
                   Sev = 'HIGH'; Msg = 'Decode-and-execute: base64-decoded payload piped to shell'
                   TID = 'SHELL-B64-EXEC' }
                @{ Re = '(?i)\beval\s+["\''`$]'
                   Sev = 'HIGH'; Msg = 'eval with variable/subshell expansion — command injection risk'
                   TID = 'SHELL-EVAL' }
                @{ Re = '(?i)chmod\s+(777|a\+rwx|ugo\+rwx)\b'
                   Sev = 'MEDIUM'; Msg = 'World-writable permission granted (chmod 777 / a+rwx)'
                   TID = 'SHELL-CHMOD-777' }
                @{ Re = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
                   Sev = 'LOW'; Msg = 'Hardcoded IPv4 address — possible C2 endpoint or credential exposure'
                   TID = 'SHELL-HARDCODED-IP' }
            )
            $lineMap = $text -split '\r?\n'
            foreach ($p in $patterns) {
                $matches = [regex]::Matches($text, $p.Re, [System.Text.RegularExpressions.RegexOptions]::Multiline)
                foreach ($m in $matches) {
                    # Calculate line number from match position.
                    $lineNum = ($text[0..$m.Index] -join '' -split '\n').Count
                    $findings.Add((New-Finding -Tool 'ShellCheck' -Category 'risky-code' `
                        -Severity $p.Sev -Confidence 'MEDIUM' -UnitType 'shell' `
                        -File $Unit.RelativePath -Line $lineNum `
                        -Issue $p.Msg `
                        -TestID $p.TID))
                }
            }
        } catch {
            Write-Log -Level WARN -Message "ShellCheck: risky-pattern scan error for $($Unit.RelativePath): $_"
        }

        return $findings.ToArray()
    }
}
