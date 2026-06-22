#Requires -Version 7.4
<#
    PythonRules analyzer — curated, high-signal static rules for Python source.

    The Python analogue of the PowerShell/shell risky-pattern layers: it reports
    ONLY attacker-grade indicators relevant to media-transfer ingress (dynamic
    code-exec, unsafe deserialization, command/process spawn, download-and-run,
    decode-then-exec, native/shellcode injection). It deliberately does NOT emit
    the broad code-quality findings the deep-tier Bandit analyzer produces — this
    is the "middle tier" between blind (no code scan) and noisy (full Bandit).

    Primary path: src/helpers/scan_python.py (stdlib `ast`, no pip package), run
    under the bundled venv or system Python — precise (real call sites, not
    substrings) and offline/air-gap friendly. If no Python interpreter is present
    it falls back to a compact pure-PowerShell regex pass so a scan is never fully
    blind (findings marked LOW/degraded). All analysis is STATIC — the target is
    parsed, never imported or executed.

    Tier: core (default-on).
#>
@{
    Name           = 'PythonRules'
    Version        = '0.1.0'
    UnitTypes      = @('python')
    RequiredTools  = @()           # stdlib-only helper; needs Python, no pip package
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        # Archive units scan their extracted dir; loose .py units scan the file.
        $isArchive = ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                      (Test-Path -LiteralPath $Unit.StagingPath -PathType Container))
        $target = if ($isArchive) { $Unit.StagingPath } else { $Unit.Path }
        if (-not $target -or -not (Test-Path -LiteralPath $target)) { return @() }

        $rec = 'Static indicator only — confirm intent in context; reject code that executes, downloads, or deserializes untrusted input on load.'
        $findings = [System.Collections.Generic.List[object]]::new()

        $pythonExe = if ($null -ne $Context.Venv) { $Context.Venv.Python } else { Find-Python }
        $helper    = if ($Context.HelperDir) { Join-Path $Context.HelperDir 'scan_python.py' } else { '' }

        if ($pythonExe -and $helper -and (Test-Path -LiteralPath $helper)) {
            # ── Primary: AST helper ──────────────────────────────────────────
            $tmpJson = Join-Path $env:TEMP "mts_pyrules_$([IO.Path]::GetRandomFileName()).json"
            try {
                $r = Invoke-BoundedProcess -FilePath $pythonExe -Arguments @($helper, $target, $tmpJson) -TimeoutSeconds $Context.TimeoutSeconds
                if ($r.TimedOut) {
                    Write-Log -Level WARN -Message "PythonRules: scan_python timed out ($($Context.TimeoutSeconds)s) for $($Unit.RelativePath)."
                    $findings.Add((New-TimeoutFinding -Tool 'PythonRules' -UnitType 'python' -File $Unit.RelativePath -TimeoutSeconds $Context.TimeoutSeconds))
                    return $findings.ToArray()
                }
                $exit = $r.ExitCode
                foreach ($line in (($r.StdOut + $r.StdErr) -split "`n")) { $s = ([string]$line).Trim(); if ($s) { Write-Log -Level DEBUG -Message "scan_python: $s" } }
                if ($exit -eq 0 -and (Test-Path -LiteralPath $tmpJson)) {
                    $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                    foreach ($f in @($raw.findings)) {
                        $rel = if ($isArchive) { "$($Unit.RelativePath)!" + ([string]$f.file).Replace('\','/') }
                               else { $Unit.RelativePath }
                        $ln = if ($f.PSObject.Properties['line'] -and $f.line) { [int]$f.line } else { $null }
                        $findings.Add((New-Finding -Tool 'PythonRules' -Category $f.category `
                            -Severity $f.severity -Confidence $f.confidence -UnitType 'python' `
                            -File $rel -Line $ln -Issue $f.issue -TestID $f.testId -Recommendation $rec))
                    }
                    Write-Log -Level INFO -Message "PythonRules: $($findings.Count) finding(s) in $($Unit.RelativePath)."
                    return $findings.ToArray()
                }
                Write-Log -Level WARN -Message "PythonRules: helper exit $exit for $($Unit.RelativePath) — falling back to regex."
            } catch {
                Write-Log -Level WARN -Message "PythonRules: helper error for $($Unit.RelativePath): $_ — falling back to regex."
            } finally {
                Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
            }
        }

        # ── Fallback: compact pure-PowerShell regex pass (degraded, no Python) ─
        $files = if ($isArchive) {
            @(Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Extension -eq '.py' } | Select-Object -First 200)
        } else { @(Get-Item -LiteralPath $target -ErrorAction SilentlyContinue) }
        if ($files.Count -eq 0) { return $findings.ToArray() }

        $rules = @(
            @{ Re = '(?<![\w.])eval\s*\(';                  Sev='HIGH';   TID='PY-EVAL';            Msg='eval() executes a dynamically-built expression.' }
            @{ Re = '(?<![\w.])exec\s*\(';                  Sev='HIGH';   TID='PY-EXEC';            Msg='exec() executes a dynamically-built code string.' }
            @{ Re = '\bos\.system\s*\(';                    Sev='HIGH';   TID='PY-OS-SYSTEM';       Msg='os.system() runs an OS shell command.' }
            @{ Re = '\bos\.popen\s*\(';                     Sev='HIGH';   TID='PY-OS-POPEN';        Msg='os.popen() runs an OS shell command.' }
            @{ Re = '(?s)subprocess\.\w+\([^)]*shell\s*=\s*True'; Sev='HIGH'; TID='PY-SUBPROCESS-SHELL'; Msg='subprocess called with shell=True — command-injection surface.' }
            @{ Re = '\b(c?pickle|_pickle)\.loads?\s*\(';    Sev='HIGH';   TID='PY-PICKLE-LOAD';     Msg='pickle load executes arbitrary code on deserialization.'; Cat='deserialization' }
            @{ Re = '\bmarshal\.loads?\s*\(';               Sev='HIGH';   TID='PY-MARSHAL-LOAD';    Msg='marshal load of code objects.'; Cat='deserialization' }
            @{ Re = '(?<![\w.])__import__\s*\(';            Sev='MEDIUM'; TID='PY-DYNAMIC-IMPORT';  Msg='__import__() dynamic import.' }
            @{ Re = '\bb(?:16|32|64|85)decode\s*\(';        Sev='LOW';    TID='PY-DECODE';          Msg='base64 decode (often used to unpack a payload).'; Cat='obfuscation' }
        )
        $degraded = $false
        foreach ($fi in $files) {
            try { $text = [IO.File]::ReadAllText($fi.FullName, [System.Text.Encoding]::UTF8) } catch { continue }
            $rel = if ($isArchive) { "$($Unit.RelativePath)!" + $fi.FullName.Substring($target.Length).TrimStart('\','/').Replace('\','/') }
                   else { $Unit.RelativePath }
            foreach ($r in $rules) {
                foreach ($m in [regex]::Matches($text, $r.Re)) {
                    $degraded = $true
                    $lineNum = ($text.Substring(0, $m.Index) -split '\r?\n').Count
                    $cat = if ($r.ContainsKey('Cat')) { $r.Cat } else { 'risky-code' }
                    $findings.Add((New-Finding -Tool 'PythonRules' -Category $cat -Severity $r.Sev `
                        -Confidence 'LOW' -UnitType 'python' -File $rel -Line $lineNum `
                        -Issue $r.Msg -TestID $r.TID -Recommendation $rec))
                }
            }
        }
        if ($degraded) {
            $findings.Add((New-Finding -Tool 'PythonRules' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue 'Python not available — used the degraded regex rule set (lower confidence, no combination rules). Provide a Python 3 interpreter for precise AST analysis.' `
                -TestID 'PY-RULES-DEGRADED'))
        }
        Write-Log -Level INFO -Message "PythonRules (regex fallback): $($findings.Count) finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
