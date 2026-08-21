#Requires -Version 7.4
<#
    Shared test helpers. Not a *.Tests.ps1 file, so Pester does not discover it —
    dot-source it from the test files that need it.

    Why this exists: on a host enforcing Application Control / Smart App Control
    (Windows 11 workstations often do — check
    `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy`
    -Name VerifiedAndReputablePolicyState; 1 = enforcing), a freshly pip-installed
    console shim such as bandit.exe is unsigned and has no reputation, so Windows
    refuses to start it. The deep-tier analyzer then produces no findings and a
    test asserting "flags risky.py" fails — looking exactly like a code regression
    while the code is fine. Worse, the decision is a per-binary cloud reputation
    lookup, so it varies between runs and between tools in the same venv, which is
    what made this present as random flakiness.

    Test-ExternalToolRunnable turns that into an explicit, loud skip.
#>

function Test-ExternalToolRunnable {
    <#
        Can this tool binary actually be executed on this host?
        Returns @{ Runnable = [bool]; Reason = [string] }.
    #>
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [string[]]$Arguments = @('--version'),
        [int]$TimeoutSeconds = 60
    )

    if (-not (Test-Path -LiteralPath $ExePath)) {
        # Callers normally pass a full path into a venv's Scripts dir, but accept a
        # bare command name (e.g. 'py') by resolving it on PATH first.
        # Assign first, then test: under Set-StrictMode -Version Latest, reading
        # .Source off an empty pipeline result throws.
        $cmd = @(Get-Command $ExePath -CommandType Application -ErrorAction SilentlyContinue) |
                    Select-Object -First 1
        $resolved = if ($cmd) { $cmd.Source } else { $null }
        if (-not $resolved) {
            return [PSCustomObject]@{ Runnable = $false; Reason = "binary not found at '$ExePath'" }
        }
        $ExePath = $resolved
    }

    $r = Invoke-BoundedProcess -FilePath $ExePath -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
    if (-not $r.Started) {
        return [PSCustomObject]@{ Runnable = $false; Reason = $r.StartError }
    }
    if ($r.TimedOut) {
        return [PSCustomObject]@{ Runnable = $false; Reason = "timed out after ${TimeoutSeconds}s running $ExePath $Arguments" }
    }
    return [PSCustomObject]@{ Runnable = $true; Reason = '' }
}

function Assert-DeepToolOrSkip {
    <#
        Announce an un-runnable external tool and skip the current test rather
        than failing it — the code is not broken, the host cannot run the binary.
        The skip is deliberately loud: a silent skip is a green run that guarantees
        nothing. Set MTS_REQUIRE_DEEP_TOOLS=1 (CI, release validation) to make an
        un-runnable tool a hard failure instead.
    #>
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][AllowNull()][object]$Probe
    )
    if ($null -eq $Probe) {
        $reason = "$Tool was never provisioned"
    } elseif ($Probe.Runnable) {
        return
    } else {
        $reason = "$Tool cannot be executed on this host: $($Probe.Reason)"
    }

    if ($env:MTS_REQUIRE_DEEP_TOOLS -in @('1', 'true', 'yes')) {
        throw "MTS_REQUIRE_DEEP_TOOLS is set but $reason"
    }
    Write-Warning "SKIPPING deep-tier coverage — $reason. Set MTS_REQUIRE_DEEP_TOOLS=1 to make this a failure."
    Set-ItResult -Skipped -Because $reason
}
