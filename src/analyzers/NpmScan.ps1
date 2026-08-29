#Requires -Version 7.4
<#
    NpmScan analyzer — static analysis of npm packages and JavaScript.

    Pure PowerShell, NO Node.js required:
      1. package.json lifecycle scripts — preinstall/install/postinstall run
         arbitrary commands on `npm install` (the #1 npm supply-chain vector).
         Flagged HIGH; their command strings are inspected for risky tooling.
         prepare/prepublish = MEDIUM; a `bin` field is noted (PATH shims).
      2. JavaScript risky patterns — eval(), child_process / exec / spawn,
         Function() constructor, and obfuscation (hex-escape / long base64 blobs).

    Dependency CVE audit against OSV.dev now lives in OsvScan.ps1 (issue #32),
    which owns package-lock.json for all ecosystems and fetches full advisory
    detail (severity/references/fixed versions), not just IDs.

    Runs on loose `npm` units only — package.json, or a standalone *.js/.mjs/
    .cjs/.ts file (no package.json required; see issue #31 acceptance). A
    package.json or .js/.ts file found inside a GENERIC archive is classified
    as its own 'npm' unit by recursive archive-member dispatch (issue #31) and
    reaches this analyzer through the exact same loose-unit path below — this
    used to ALSO walk a whole npm tarball's StagingPath itself (UnitTypes
    included 'archive'); removed, since that would now duplicate every finding
    member dispatch already produces for the same files.
    All analysis is STATIC — nothing is installed or executed. Tier: core.
#>
@{
    Name           = 'NpmScan'
    Version        = '0.3.0'
    UnitTypes      = @('npm')
    RequiredTools  = @()
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        $findings = [System.Collections.Generic.List[object]]::new()
        $jsExts   = @('.js', '.mjs', '.cjs', '.ts')

        $pkgJsonFiles = [System.Collections.Generic.List[string]]::new()
        $jsFiles      = [System.Collections.Generic.List[string]]::new()

        $name = $Unit.Name.ToLowerInvariant()
        if ($name -eq 'package.json')                       { $pkgJsonFiles.Add($Unit.Path) }
        elseif ([IO.Path]::GetExtension($name) -in $jsExts)  { $jsFiles.Add($Unit.Path) }
        else { return @() }   # e.g. a loose package-lock.json — OsvScan owns that

        # ── Layer 1: package.json lifecycle + manifest ──────────────────────
        $autoExec = @('preinstall', 'install', 'postinstall')
        $semiExec = @('prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack')
        $riskyCmd = '(?i)(curl|wget|\|\s*(bash|sh)\b|node\s+-e|child_process|base64|powershell|certutil|bitsadmin|eval\()'

        foreach ($pj in $pkgJsonFiles) {
            $rel = $Unit.RelativePath
            try {
                $pkg = Get-Content -LiteralPath $pj -Raw | ConvertFrom-Json
            } catch {
                $findings.Add((New-Finding -Tool 'NpmScan' -Category 'parser' -Severity 'LOW' `
                    -Confidence 'LOW' -UnitType 'npm' -File $rel `
                    -Issue "Malformed package.json: $_" -TestID 'NPM-MALFORMED'))
                continue
            }
            if ($pkg.PSObject.Properties['scripts'] -and $pkg.scripts) {
                foreach ($sp in $pkg.scripts.PSObject.Properties) {
                    $hookName = $sp.Name; $cmd = [string]$sp.Value
                    $isAuto = $autoExec -contains $hookName
                    $isSemi = $semiExec -contains $hookName
                    if (-not ($isAuto -or $isSemi)) { continue }
                    $riskyHit = $cmd -match $riskyCmd
                    $sev = if ($isAuto) { 'HIGH' } elseif ($riskyHit) { 'HIGH' } else { 'MEDIUM' }
                    $note = if ($riskyHit) { ' (command uses risky tooling)' } else { '' }
                    $findings.Add((New-Finding -Tool 'NpmScan' -Category 'active-content' `
                        -Severity $sev -Confidence 'HIGH' -UnitType 'npm' -File $rel `
                        -Issue ("Lifecycle script '{0}' runs on install: {1}{2}" -f $hookName, $cmd, $note) `
                        -TestID 'NPM-LIFECYCLE-SCRIPT' `
                        -Recommendation 'Install scripts execute on `npm install` — review the command before admitting.'))
                }
            }
            if ($pkg.PSObject.Properties['bin'] -and $pkg.bin) {
                $findings.Add((New-Finding -Tool 'NpmScan' -Category 'active-content' -Severity 'LOW' `
                    -Confidence 'MEDIUM' -UnitType 'npm' -File $rel `
                    -Issue 'Package declares `bin` entries (installs executable shims onto PATH).' `
                    -TestID 'NPM-BIN-SHIM'))
            }
        }

        # ── Layer 2: JavaScript risky patterns ───────────────────────────────
        $jsRules = @(
            @{ Re = '(?i)\bchild_process\b|\brequire\(\s*[''"]child_process[''"]\s*\)|\.(exec|execSync|spawn|spawnSync)\s*\('
               Sev='HIGH'; TID='NPM-JS-CHILD-PROCESS'; Msg='Spawns child processes (child_process / exec / spawn)' }
            @{ Re = '(?<![\w.])eval\s*\('
               Sev='HIGH'; TID='NPM-JS-EVAL'; Msg='eval() — executes a dynamically-built string' }
            @{ Re = '(?i)new\s+Function\s*\('
               Sev='MEDIUM'; TID='NPM-JS-FUNCTION-CTOR'; Msg='Function() constructor — dynamic code execution' }
            @{ Re = '(\\x[0-9A-Fa-f]{2}){8,}'
               Sev='MEDIUM'; TID='NPM-JS-OBFUSCATION'; Msg='Long hex-escape sequence — possible obfuscated payload' }
        )
        foreach ($js in $jsFiles) {
            $rel = $Unit.RelativePath
            try { $text = [IO.File]::ReadAllText($js, [System.Text.Encoding]::UTF8) } catch { continue }
            foreach ($rule in $jsRules) {
                $m = [regex]::Match($text, $rule.Re)
                if ($m.Success) {
                    $lineNum = ($text.Substring(0, $m.Index) -split '\r?\n').Count
                    $findings.Add((New-Finding -Tool 'NpmScan' -Category 'risky-code' `
                        -Severity $rule.Sev -Confidence 'MEDIUM' -UnitType 'npm' -File $rel `
                        -Line $lineNum -Issue $rule.Msg -TestID $rule.TID))
                }
            }
        }

        Write-Log -Level INFO -Message "NpmScan: $($findings.Count) finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
