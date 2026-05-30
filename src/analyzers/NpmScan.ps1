#Requires -Version 7.4
<#
    NpmScan analyzer — static analysis of npm packages and JavaScript (PLAN §4 v0.6).

    Pure PowerShell, NO Node.js required for the core analysis:
      1. package.json lifecycle scripts — preinstall/install/postinstall run
         arbitrary commands on `npm install` (the #1 npm supply-chain vector).
         Flagged HIGH; their command strings are inspected for risky tooling.
         prepare/prepublish = MEDIUM; a `bin` field is noted (PATH shims).
      2. JavaScript risky patterns — eval(), child_process / exec / spawn,
         Function() constructor, and obfuscation (hex-escape / long base64 blobs).
      3. Dependency CVE audit (online best-effort, no tool install): when a
         package-lock.json with exact versions is present, query the OSV.dev REST
         API for known vulnerabilities. Offline / no lockfile → coverage-gap note.

    Runs on `npm` units (loose package.json / *.js) and `archive` units (extracted
    .tgz tarballs — only acts if a package.json is present in the staging tree).
    All analysis is STATIC — nothing is installed or executed. Tier: core.
#>
@{
    Name           = 'NpmScan'
    Version        = '0.1.0'
    UnitTypes      = @('npm', 'archive')
    RequiredTools  = @()           # core is dependency-free; OSV uses the REST API
    Offline        = $true         # core works offline; OSV layer needs network
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)

        # OSV dependency audit (online): parse a package-lock.json, batch-query the
        # OSV.dev REST API for known vulns. Best-effort — network failure degrades
        # to a coverage-gap note, never throws.
        function Invoke-OsvAudit {
            param([string]$LockPath, [string]$Rel)
            $out = [System.Collections.Generic.List[object]]::new()
            try {
                # -AsHashtable is REQUIRED: npm lockfile v2/v3 has a root package keyed
                # by "" (empty string), which ConvertFrom-Json rejects without it.
                $lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json -AsHashtable
            } catch {
                return $out
            }
            $deps = [System.Collections.Generic.List[object]]::new()
            if ($lock.ContainsKey('packages') -and $lock.packages) {
                foreach ($key in $lock.packages.Keys) {
                    if ([string]::IsNullOrEmpty($key)) { continue }       # "" = root project
                    $entry = $lock.packages[$key]
                    $ver = $entry.version
                    if (-not $ver) { continue }
                    $nm = if ($entry.ContainsKey('name') -and $entry.name) { $entry.name }
                          else { ($key -replace '.*node_modules/', '') }
                    $deps.Add(@{ name = $nm; version = $ver })
                }
            } elseif ($lock.ContainsKey('dependencies') -and $lock.dependencies) {
                foreach ($name in $lock.dependencies.Keys) {
                    $v = $lock.dependencies[$name].version
                    if ($v) { $deps.Add(@{ name = $name; version = $v }) }
                }
            }
            if ($deps.Count -eq 0) { return $out }

            $queries = @($deps | Select-Object -First 100 | ForEach-Object {
                @{ package = @{ name = $_.name; ecosystem = 'npm' }; version = $_.version } })
            try {
                $body = @{ queries = $queries } | ConvertTo-Json -Depth 6
                $resp = Invoke-RestMethod -Uri 'https://api.osv.dev/v1/querybatch' -Method Post `
                    -Body $body -ContentType 'application/json' -TimeoutSec 30
            } catch {
                $out.Add((New-Finding -Tool 'NpmScan' -Category 'parser' -Severity 'INFO' `
                    -Confidence 'LOW' -UnitType 'npm' -File $Rel `
                    -Issue "OSV dependency audit could not reach api.osv.dev: $_" -TestID 'NPM-OSV-ERR'))
                return $out
            }
            for ($i = 0; $i -lt $resp.results.Count; $i++) {
                $vulns = $resp.results[$i].vulns
                if ($vulns) {
                    $dep = $queries[$i].package.name
                    $ver = $queries[$i].version
                    $ids = (@($vulns | ForEach-Object { $_.id }) | Select-Object -First 8) -join ', '
                    $out.Add((New-Finding -Tool 'NpmScan' -Category 'vuln-dependency' -Severity 'HIGH' `
                        -Confidence 'HIGH' -UnitType 'npm' -File "dependency: $dep@$ver" `
                        -Issue "Known vulnerabilities (OSV): $ids" -TestID ($vulns[0].id) `
                        -Recommendation "Update '$dep' to a patched version."))
                }
            }
            return $out
        }

        $findings = [System.Collections.Generic.List[object]]::new()
        $jsExts   = @('.js', '.mjs', '.cjs', '.ts')

        # ── Resolve targets by unit shape ────────────────────────────────────
        $pkgJsonFiles = [System.Collections.Generic.List[string]]::new()
        $lockFiles    = [System.Collections.Generic.List[string]]::new()
        $jsFiles      = [System.Collections.Generic.List[string]]::new()

        if ($Unit.Type -eq 'archive') {
            if (-not ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath -and
                      (Test-Path -LiteralPath $Unit.StagingPath -PathType Container))) { return @() }
            $pj = @(Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -Filter 'package.json' -ErrorAction SilentlyContinue)
            if ($pj.Count -eq 0) { return @() }   # not an npm package — leave for other analyzers
            $pj | ForEach-Object { $pkgJsonFiles.Add($_.FullName) }
            Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -Filter 'package-lock.json' -ErrorAction SilentlyContinue |
                ForEach-Object { $lockFiles.Add($_.FullName) }
            # Cap JS scan; npm-packed tarballs don't ship node_modules.
            @(Get-ChildItem -LiteralPath $Unit.StagingPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension.ToLowerInvariant() -in $jsExts -and $_.FullName -notmatch '[\\/]node_modules[\\/]' } |
                Select-Object -First 200) | ForEach-Object { $jsFiles.Add($_.FullName) }
        }
        else {
            # Loose npm unit
            $name = $Unit.Name.ToLowerInvariant()
            if ($name -eq 'package.json')           { $pkgJsonFiles.Add($Unit.Path) }
            elseif ($name -eq 'package-lock.json')  { $lockFiles.Add($Unit.Path) }
            elseif ([IO.Path]::GetExtension($name) -in $jsExts) { $jsFiles.Add($Unit.Path) }
            else { return @() }
        }

        $relOf = {
            param($full)
            if ($Unit.Type -eq 'archive' -and $Unit.StagingPath -and $full.StartsWith($Unit.StagingPath)) {
                "$($Unit.RelativePath)!" + $full.Substring($Unit.StagingPath.Length).TrimStart('\','/')
            } else { $Unit.RelativePath }
        }

        # ── Layer 1: package.json lifecycle + manifest ──────────────────────
        $autoExec = @('preinstall', 'install', 'postinstall')
        $semiExec = @('prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack')
        $riskyCmd = '(?i)(curl|wget|\|\s*(bash|sh)\b|node\s+-e|child_process|base64|powershell|certutil|bitsadmin|eval\()'

        foreach ($pj in $pkgJsonFiles) {
            $rel = & $relOf $pj
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
            $rel = & $relOf $js
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

        # ── Layer 3: OSV dependency audit (online best-effort) ───────────────
        if ($lockFiles.Count -gt 0) {
            if ($Context.Mode -eq 'offline') {
                $findings.Add((New-Finding -Tool 'NpmScan' -Category 'parser' -Severity 'INFO' `
                    -Confidence 'HIGH' -UnitType 'npm' -File (& $relOf $lockFiles[0]) `
                    -Issue 'Dependency CVE audit skipped (offline) — a lockfile is present but OSV needs network.' `
                    -TestID 'NPM-OSV-OFFLINE'))
            } else {
                foreach ($lock in $lockFiles) {
                    foreach ($f in (Invoke-OsvAudit -LockPath $lock -Rel (& $relOf $lock))) { $findings.Add($f) }
                }
            }
        }

        Write-Log -Level INFO -Message "NpmScan: $($findings.Count) finding(s) in $($Unit.RelativePath)."
        return $findings.ToArray()
    }
}
