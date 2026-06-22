#Requires -Version 7.4
<#
    Process.ps1 - run an external tool under an enforced wall-clock timeout
    (F2 / issue #9).

    The analyzers shell out to bandit / pip-audit / shellcheck / oletools and the
    Python helpers on UNTRUSTED submission content. A crafted file that makes one
    of those tools hang (or a catastrophic-backtracking input) would otherwise
    stall the whole batch scan indefinitely - a denial-of-service, and an evasion
    vector (hang the analyzer that would have flagged you).

    Invoke-BoundedProcess bounds each call: stdout/stderr are drained
    asynchronously (so a child filling a redirected pipe buffer cannot deadlock us
    while we wait), the process is given $TimeoutSeconds to finish, and on expiry
    the WHOLE process tree is killed. It returns a result object; it never throws
    for a tool failure or timeout - the caller decides how to surface it.
#>

Set-StrictMode -Version Latest

function Invoke-BoundedProcess {
    <#
        Run $FilePath with $Arguments under a wall-clock timeout. Returns
        [PSCustomObject]@{ TimedOut; ExitCode; StdOut; StdErr }.
        On timeout the process tree is killed, TimedOut=$true and ExitCode=$null.
        Arguments are passed as a real argv list (ArgumentList), so no shell is
        involved and an attacker-controlled path cannot inject a command.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 300,
        [string]$WorkingDirectory = ''
    )

    if ($TimeoutSeconds -le 0) { $TimeoutSeconds = 300 }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    foreach ($a in $Arguments) { $psi.ArgumentList.Add([string]$a) }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi

    $timedOut = $false
    $exitCode = $null
    $stdout   = ''
    $stderr   = ''
    try {
        [void]$proc.Start()
        # Begin draining both pipes immediately on the thread pool — prevents a
        # deadlock where the child blocks writing to a full pipe while we wait.
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()

        if ($proc.WaitForExit($TimeoutSeconds * 1000)) {
            $exitCode = $proc.ExitCode
            $stdout   = $outTask.GetAwaiter().GetResult()
            $stderr   = $errTask.GetAwaiter().GetResult()
        } else {
            $timedOut = $true
            try { $proc.Kill($true) } catch { }          # kill the whole tree
            try { [void]$proc.WaitForExit(5000) } catch { }
            if ($outTask.IsCompleted) { $stdout = $outTask.Result }   # best-effort partial
            if ($errTask.IsCompleted) { $stderr = $errTask.Result }
        }
    } finally {
        $proc.Dispose()
    }

    return [PSCustomObject]@{
        TimedOut = $timedOut
        ExitCode = $exitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

function New-TimeoutFinding {
    <#
        Standard finding emitted when an analyzer's external tool exceeds the
        per-scan timeout. HIGH severity: a tool that hangs on a single submission
        file is anomalous (resource exhaustion / deliberate evasion) AND the unit
        was not fully analyzed, so it must not pass silently.
    #>
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$UnitType,
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )
    New-Finding -Tool $Tool -Category 'parser' -Severity 'HIGH' -Confidence 'MEDIUM' `
        -UnitType $UnitType -File $File `
        -Issue "$Tool exceeded the ${TimeoutSeconds}s analysis timeout and was terminated - this unit was NOT fully analyzed (possible resource-exhaustion / evasion)." `
        -TestID 'MTS-ANALYZER-TIMEOUT' `
        -Recommendation 'Treat as suspicious: inspect this file in isolation. If it is known-large/benign, re-scan with a higher -TimeoutSeconds.'
}
