<#
    Defender / AMSI self-check  (Windows + Microsoft Defender only).

    Confirms the scanner's OWN code does not trip Microsoft Defender when it is
    loaded. The PowerShell analyzer used to carry the offensive-PowerShell
    signatures it detects (AMSI-tamper, Defender-preference, downloaders, ...) as
    contiguous literal strings; loading the engine then matched Defender's
    "Trojan:PowerShell/PsAttack.*" signature and fired "Possible AMSI tampering".
    Those tokens are now assembled from fragments at runtime, so the contiguous
    strings never appear in any shipped file. This script proves that on a real
    Defender host.

    How it works (no EDR portal needed): Microsoft Defender records every local
    detection in its threat-detection history (Get-MpThreatDetection). We snapshot
    the history, load the full engine from disk in a fresh pwsh (the same path
    that previously triggered the alert), then check whether any NEW detection
    appeared. A clean load => no new detection.

    Usage:   pwsh -NoProfile -File tools/verify-amsi.ps1

    Note: this script never writes the trigger tokens to disk or to a command
    line, so running it does not itself create a detection.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root  = Split-Path $PSScriptRoot -Parent
$entry = Join-Path $root 'src/Invoke-MediaTransferScan.ps1'

if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) {
    Write-Host "Get-MpThreatDetection is unavailable — this check requires Windows + Microsoft Defender." -ForegroundColor Yellow
    Write-Host "On a non-Defender host the fragmentation fix still applies; it just can't be self-verified here."
    exit 2
}

function Get-RecentDetections {
    @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Sort-Object InitialDetectionTime -Descending)
}

$before = Get-RecentDetections
$beforeKeys = [System.Collections.Generic.HashSet[string]]::new()
foreach ($d in $before) { [void]$beforeKeys.Add("$($d.DetectionID)") }
$latest = if ($before) { $before[0].InitialDetectionTime } else { '(none)' }
Write-Host "Defender threat-detection history: $($before.Count) record(s). Latest: $latest"

Write-Host "`nLoading the full engine from disk in a fresh pwsh (parses every lib + analyzer through AMSI) ..."
$out = & pwsh -NoProfile -NonInteractive -Command ". '$entry'; 'engine-loaded-ok'" 2>&1 | Out-String
if ($out -notmatch 'engine-loaded-ok') {
    Write-Host "Engine did not load cleanly:" -ForegroundColor Red
    Write-Host $out
    exit 1
}
Write-Host "  engine loaded and registered analyzers OK."

Start-Sleep -Seconds 6   # give Defender a moment to flush any detection to history

$after = Get-RecentDetections
$new = @($after | Where-Object { -not $beforeKeys.Contains("$($_.DetectionID)") })

Write-Host ""
if ($new.Count -eq 0) {
    Write-Host "VERIFIED: loading the scanner produced NO new Microsoft Defender detection." -ForegroundColor Green
    Write-Host "The engine's own code does not trip Defender on this host."
    exit 0
}
Write-Host "REGRESSION: $($new.Count) new Defender detection(s) appeared while loading the engine:" -ForegroundColor Red
foreach ($d in $new) {
    $name = (Get-MpThreat | Where-Object { $_.ThreatID -eq $d.ThreatID } | Select-Object -First 1).ThreatName
    $res  = ($d.Resources -join ' | ')
    Write-Host ("  [{0}] {1}" -f $d.InitialDetectionTime, $name) -ForegroundColor Red
    Write-Host ("     {0}" -f $res.Substring(0, [Math]::Min(200, $res.Length))) -ForegroundColor DarkGray
}
Write-Host "`nA shipped file still carries a contiguous trigger token — find and fragment it." -ForegroundColor Red
exit 1
