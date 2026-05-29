#Requires -Version 7.4
<#
    Provisioning.ps1 - the Resolve-Tool layer (PLAN §3.4).

    Handles four kinds of dependency:
      pip     - Python packages into the shared scanner venv
      psmodule - PowerShell modules (PSScriptAnalyzer, etc.)
      exe      - external binaries (ShellCheck, Node, etc.) from PATH or bundle
      python   - the Python runtime itself

    Key design decisions carried forward from scan-python-packages v1.6.1:
      - Always invoke pip as 'python -m pip' (not pip.exe) to avoid the
        Windows pip.exe wrapper replacement bug on venv bootstrap upgrades.
      - PEP 440 version comparison is delegated to Python's packaging.version
        (or pip's vendored copy) — never [System.Version] which mis-orders
        pre/post/dev releases.
      - Provisioning is a write operation protected against concurrent scanner
        runs (TODO: lock file in a later increment). Scans (read) are safe.
      - Online mode  : installs/upgrades missing tools via pip/PSGallery.
        Offline mode : binds to the bundle and emits a coverage-gap finding
                       rather than aborting.
      - EAP wrappers from scan-python-packages are NOT needed on PS 7.2+
        (native-command stderr no longer triggers $ErrorActionPreference).
#>

Set-StrictMode -Version Latest

# ─────────────────────────────────────────────────────────────────────────────
# Python runtime discovery
# ─────────────────────────────────────────────────────────────────────────────

function Find-Python {
    <#
        Locate a Python 3 executable. Tries the Windows py launcher first,
        then 'python', then 'python3'. Returns the command name/path, or $null.
    #>
    foreach ($candidate in @('py', 'python', 'python3')) {
        try {
            $null = Get-Command $candidate -ErrorAction Stop
            $ver = & $candidate --version 2>$null
            if ($ver -match 'Python 3\.') {
                Write-Log -Level INFO -Message "Found Python: $candidate  ($ver)"
                return $candidate
            }
        } catch { }
    }
    Write-Log -Level WARN -Message 'No Python 3 found on PATH.'
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
# Virtual environment
# ─────────────────────────────────────────────────────────────────────────────

function Get-VenvPaths {
    param([string]$VenvDir)
    [PSCustomObject]@{
        Root    = $VenvDir
        Python  = Join-Path $VenvDir 'Scripts\python.exe'
        Pip     = Join-Path $VenvDir 'Scripts\pip.exe'
        Scripts = Join-Path $VenvDir 'Scripts'
    }
}

function Initialize-ScannerVenv {
    <#
        Create (or reuse) the shared scanner venv. Lives beside the engine
        scripts, not inside the scan target, so tools install once and are
        reused across all scans. Returns a venv-paths object.
    #>
    param(
        [Parameter(Mandatory)][string]$PythonCmd,
        [Parameter(Mandatory)][string]$VenvDir
    )

    if (Test-Path $VenvDir) {
        Write-Log -Level INFO -Message "Reusing existing scanner venv: $VenvDir"
    } else {
        Write-Log -Level INFO -Message "Creating scanner venv at: $VenvDir"
        $out = & $PythonCmd -m venv $VenvDir 2>&1
        foreach ($line in $out) { Write-Log -Level DEBUG -Message ([string]$line) }
        if ($LASTEXITCODE -ne 0) { throw "Failed to create venv at $VenvDir (exit $LASTEXITCODE)" }
    }

    $paths = Get-VenvPaths -VenvDir $VenvDir
    if (-not (Test-Path $paths.Python)) {
        throw "Python not found inside venv at $($paths.Python). Venv may be corrupt — delete '$VenvDir' and retry."
    }
    return $paths
}

# ─────────────────────────────────────────────────────────────────────────────
# Package version checks
# ─────────────────────────────────────────────────────────────────────────────

function Get-InstalledPipVersion {
    <#
        Query the venv for the installed version of a pip package.
        Uses 'python -m pip show' (not pip.exe) to avoid the pip.exe wrapper
        replacement bug that surfaces after bootstrap upgrades in scan-python-packages.
        Returns the version string, or $null if not installed.
    #>
    param(
        [Parameter(Mandatory)][string]$PythonExe,
        [Parameter(Mandatory)][string]$PackageName
    )
    try {
        $output = & $PythonExe -m pip show $PackageName 2>$null
        $verLine = $output | Where-Object { $_ -match '^Version:' } | Select-Object -First 1
        if ($verLine) { return ($verLine -replace '^Version:\s*').Trim() }
    } catch { }
    return $null
}

function Compare-PipVersions {
    <#
        PEP 440-compliant version comparison: returns $true if Installed >= Minimum.
        Delegates to Python's packaging.version (or pip's vendored copy which is
        present in any venv). Fails closed: an unparseable version forces a
        reinstall rather than silently passing. Pattern ported from v1.6.1.
    #>
    param(
        [Parameter(Mandatory)][string]$PythonExe,
        [string]$Installed,
        [string]$Minimum
    )
    if (-not $Minimum)   { return $true  }
    if (-not $Installed) { return $false }

    $py = @'
import sys
try:
    from packaging.version import Version, InvalidVersion
except ImportError:
    from pip._vendor.packaging.version import Version, InvalidVersion
try:
    sys.exit(0 if Version(sys.argv[1]) >= Version(sys.argv[2]) else 1)
except InvalidVersion:
    sys.exit(2)
'@
    & $PythonExe -c $py $Installed $Minimum 2>$null
    switch ($LASTEXITCODE) {
        0 { return $true }
        1 { return $false }
        default {
            Write-Log -Level WARN -Message "PEP 440 compare: could not parse '$Installed' or '$Minimum' — treating as below minimum."
            return $false
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# pip bootstrap + package installation
# ─────────────────────────────────────────────────────────────────────────────

function Update-PipBootstrap {
    <#
        Upgrade pip/setuptools/wheel inside the venv. Must use 'python -m pip'
        because pip.exe cannot replace itself while it is running.
    #>
    param([Parameter(Mandatory)][string]$PythonExe)
    Write-Log -Level INFO -Message 'Upgrading pip/setuptools/wheel...'
    $out = & $PythonExe -m pip install --upgrade pip setuptools wheel 2>&1
    foreach ($line in $out) {
        $s = ([string]$line).Trim()
        if ($s) { Write-Log -Level DEBUG -Message $s }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Level WARN -Message "pip bootstrap upgrade exited $LASTEXITCODE — continuing."
    }
}

function Install-PipPackage {
    <#
        Install or upgrade a single pip package. Confirm success by re-querying
        the version (pip exit codes are not reliable for this).
        Returns the installed version string, or throws on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$PythonExe,
        [Parameter(Mandatory)][string]$Package,
        [string]$MinVersion = ''
    )
    Show-Status "Installing $Package..."
    Write-Log -Level INFO -Message "Installing/upgrading pip package: $Package"
    $out = & $PythonExe -m pip install --upgrade $Package 2>&1
    foreach ($line in $out) {
        $s = ([string]$line).Trim()
        if ($s) { Write-Log -Level DEBUG -Message $s }
    }

    $ver = Get-InstalledPipVersion -PythonExe $PythonExe -PackageName $Package
    if (-not $ver) { throw "pip install of '$Package' appeared to succeed but package not found afterwards." }
    if (-not (Compare-PipVersions -PythonExe $PythonExe -Installed $ver -Minimum $MinVersion)) {
        throw "Installed $Package $ver is still below minimum $MinVersion."
    }
    Write-Log -Level INFO -Message "$Package $ver installed."
    return $ver
}

# ─────────────────────────────────────────────────────────────────────────────
# Resolve-Tool — the unified provisioning contract (PLAN §3.4)
# ─────────────────────────────────────────────────────────────────────────────

function Resolve-PipTool {
    param(
        [PSCustomObject]$Descriptor,   # { Kind='pip'; Id; MinVersion; BundlePath }
        [PSCustomObject]$Venv,         # from Get-VenvPaths
        [string]$Mode,
        [switch]$AutoInstall
    )
    $pkg        = $Descriptor.Id
    $minVer     = $Descriptor.MinVersion ?? ''
    $installedVer = Get-InstalledPipVersion -PythonExe $Venv.Python -PackageName $pkg

    if ($installedVer -and (Compare-PipVersions -PythonExe $Venv.Python -Installed $installedVer -Minimum $minVer)) {
        Write-Log -Level INFO -Message "$pkg $installedVer — OK."
        return [PSCustomObject]@{ Name = $pkg; Version = $installedVer; Available = $true; ScriptsDir = $Venv.Scripts }
    }

    # Missing or below-minimum.
    # Offline mode: never install — bind to the bundle or report a coverage gap.
    if ($Mode -eq 'offline') {
        Write-Log -Level WARN -Message "OFFLINE: $pkg not available (installed: $($installedVer ?? 'none'), min: $($minVer ? $minVer : 'any')). Coverage reduced."
        return [PSCustomObject]@{ Name = $pkg; Version = $null; Available = $false; ScriptsDir = $Venv.Scripts }
    }

    # Online mode is the convenience mode: install on demand. We do NOT prompt —
    # the engine must run non-interactively under the bootstrapper (§3.9), where
    # Read-Host has no console. ($AutoInstall is implied online and kept only for
    # explicit callers / signature stability.)
    try {
        $ver = Install-PipPackage -PythonExe $Venv.Python -Package $pkg -MinVersion $minVer
        return [PSCustomObject]@{ Name = $pkg; Version = $ver; Available = $true; ScriptsDir = $Venv.Scripts }
    } catch {
        Write-Log -Level WARN -Message "Install of $pkg failed ($_). Coverage reduced."
        return [PSCustomObject]@{ Name = $pkg; Version = $null; Available = $false; ScriptsDir = $Venv.Scripts }
    }
}

function Resolve-ExeTool {
    param(
        [PSCustomObject]$Descriptor,   # { Kind='exe'; Id; MinVersion; BundlePath }
        [string]$BundleRoot
    )
    # Check bundle path first; fall back to system PATH.
    $candidates = @()
    if ($Descriptor.BundlePath) { $candidates += Join-Path $BundleRoot $Descriptor.BundlePath }
    $candidates += $Descriptor.Id

    foreach ($c in $candidates) {
        if (Get-Command $c -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Resolved exe '$($Descriptor.Id)' via: $c"
            return [PSCustomObject]@{ Name = $Descriptor.Id; Command = $c; Available = $true }
        }
    }
    Write-Log -Level WARN -Message "Exe '$($Descriptor.Id)' not found (bundle or PATH). Coverage reduced."
    return [PSCustomObject]@{ Name = $Descriptor.Id; Command = $null; Available = $false }
}

function Resolve-PsModuleTool {
    param([PSCustomObject]$Descriptor)   # { Kind='psmodule'; Id; MinVersion }
    $mod = Get-Module -ListAvailable $Descriptor.Id |
           Sort-Object Version -Descending | Select-Object -First 1
    if ($mod -and ((-not $Descriptor.MinVersion) -or ($mod.Version -ge [version]$Descriptor.MinVersion))) {
        Write-Log -Level INFO -Message "PS module '$($Descriptor.Id)' $($mod.Version) — OK."
        return [PSCustomObject]@{ Name = $Descriptor.Id; Version = $mod.Version.ToString(); Available = $true }
    }
    Write-Log -Level WARN -Message "PS module '$($Descriptor.Id)' not found or below minimum. Coverage reduced."
    return [PSCustomObject]@{ Name = $Descriptor.Id; Version = $null; Available = $false }
}

function Invoke-Provisioning {
    <#
        Top-level provisioning entry point. Locates Python, creates/reuses the
        scanner venv, bootstraps pip, and resolves every RequiredTool declared
        across all enabled analyzer descriptors.

        Returns a $Context.Tools hashtable keyed by tool Id, plus the venv paths
        on $Context.Venv. A tool that could not be provisioned has .Available=$false;
        the engine emits a coverage-gap finding for any analyzer that requires it.
    #>
    param(
        [Parameter(Mandatory)][object[]]$EnabledAnalyzers,
        [Parameter(Mandatory)][string]$VenvDir,
        [Parameter(Mandatory)][string]$Mode,
        [string]$BundleRoot = '',
        [switch]$AutoInstall
    )

    # ── Python + venv ────────────────────────────────────────────────────────
    $pythonCmd = Find-Python
    if (-not $pythonCmd) { throw 'Python 3 is required but not found on PATH.' }

    $venv = Initialize-ScannerVenv -PythonCmd $pythonCmd -VenvDir $VenvDir
    Update-PipBootstrap -PythonExe $venv.Python

    # ── Collect unique RequiredTools from all enabled analyzers ──────────────
    $allTools = $EnabledAnalyzers |
        ForEach-Object { $_.RequiredTools } |
        Where-Object { $_ } |
        Group-Object { "$($_.Kind):$($_.Id)" } |
        ForEach-Object { $_.Group[0] }   # deduplicate by Kind:Id

    $tools = @{}
    foreach ($t in $allTools) {
        $result = switch ($t.Kind) {
            'pip'      { Resolve-PipTool      -Descriptor $t -Venv $venv -Mode $Mode -AutoInstall:$AutoInstall }
            'exe'      { Resolve-ExeTool      -Descriptor $t -BundleRoot $BundleRoot }
            'psmodule' { Resolve-PsModuleTool -Descriptor $t }
            default    { Write-Log -Level WARN -Message "Unknown tool kind '$($t.Kind)' — skipped."; $null }
        }
        if ($result) { $tools[$t.Id] = $result }
    }

    return [PSCustomObject]@{
        Venv  = $venv
        Tools = $tools
    }
}
