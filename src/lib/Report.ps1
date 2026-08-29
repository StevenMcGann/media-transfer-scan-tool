#Requires -Version 7.4
<#
    Report.ps1 - three renderers over one finding model:
      JSON (canonical, machine), HTML (primary human), slim TXT (summary).
    HTML encodes ALL submission-derived values and sets a strict inline CSP.
#>

# Frozen at 1.0.0 — the JSON report is a stable public contract (see docs/contract.md).
# A backward-incompatible change requires a MAJOR bump.
$script:SchemaVersion = '1.0.0'

function ConvertTo-HtmlEncoded {
# Encode untrusted submission-derived text before it enters HTML
    # mandatory anti-injection rule). Never interpolate raw submission data.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-ReportModel {
    # Build the single in-memory model the renderers share.
    param([PSCustomObject]$ScanResult)

    $allFindings = @($ScanResult.Units | ForEach-Object { $_.Findings } | Where-Object { $_ })
    $counts = [ordered]@{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
    foreach ($f in $allFindings) { $counts[$f.Severity]++ }

    [PSCustomObject]@{
        SchemaVersion   = $script:SchemaVersion
        ScanRoot        = $ScanResult.ScanRoot
        GeneratedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        ElapsedSeconds  = [Math]::Round(($ScanResult.EndTime - $ScanResult.StartTime).TotalSeconds, 2)
        Profile         = $ScanResult.Profile
        Mode            = $ScanResult.Mode
        OverallRisk     = Get-RiskLevel -Findings $allFindings
        Counts          = $counts
        EnabledAnalyzers  = $ScanResult.EnabledAnalyzers
        DisabledAnalyzers = $ScanResult.DisabledAnalyzers
        Units           = $ScanResult.Units
        TotalFindings   = $allFindings.Count
    }
}

function Write-JsonReport {
    param([PSCustomObject]$Model, [string]$ReportPath)
    # -AsArray-free here because Units/findings already typed arrays; depth covers nesting.
    $Model | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding utf8
    return $ReportPath
}

function Write-TxtReport {
    param([PSCustomObject]$Model, [string]$ReportPath)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('media-transfer-scan-tool - summary')
    [void]$sb.AppendLine('=' * 52)
    [void]$sb.AppendLine("Scan root    : $($Model.ScanRoot)")
    [void]$sb.AppendLine("Generated    : $($Model.GeneratedUtc)")
    [void]$sb.AppendLine("Profile/Mode : $($Model.Profile) / $($Model.Mode)")
    [void]$sb.AppendLine("Overall risk : $($Model.OverallRisk)")
    [void]$sb.AppendLine(("Findings     : CRIT {0}  HIGH {1}  MED {2}  LOW {3}  INFO {4}" -f `
        $Model.Counts.CRITICAL, $Model.Counts.HIGH, $Model.Counts.MEDIUM, $Model.Counts.LOW, $Model.Counts.INFO))
    if ($Model.DisabledAnalyzers.Count -gt 0) {
        [void]$sb.AppendLine("NOT checked  : $($Model.DisabledAnalyzers -join ', ')  (disabled this run)")
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('CRITICAL / HIGH findings:')
    $hot = @($Model.Units | ForEach-Object { $_.Findings } | Where-Object { $_ -and $_.Severity -in @('CRITICAL', 'HIGH') })
    if ($hot.Count -eq 0) {
        [void]$sb.AppendLine('  (none)')
    } else {
        foreach ($f in $hot) {
            [void]$sb.AppendLine(("  [{0}] {1}: {2} ({3})" -f $f.Severity, $f.File, $f.Issue, $f.Tool))
        }
    }
    $sb.ToString() | Set-Content -LiteralPath $ReportPath -Encoding utf8
    return $ReportPath
}

function Write-HtmlReport {
    param([PSCustomObject]$Model, [string]$ReportPath)

    $riskColor = switch ($Model.OverallRisk) {
        'CRITICAL' { '#b00020' } 'HIGH' { '#d9480f' } 'MEDIUM' { '#b8860b' }
        'LOW' { '#2b6cb0' } default { '#2f855a' }
    }

    $rows = foreach ($u in $Model.Units) {
        foreach ($f in @($u.Findings)) {
            $sevClass = $f.Severity.ToLower()
            @"
<tr class="sev-$sevClass">
  <td><span class="badge $sevClass">$(ConvertTo-HtmlEncoded $f.Severity)</span></td>
  <td>$(ConvertTo-HtmlEncoded $f.UnitType)</td>
  <td>$(ConvertTo-HtmlEncoded $f.Category)</td>
  <td>$(ConvertTo-HtmlEncoded $f.File)</td>
  <td>$(ConvertTo-HtmlEncoded $f.Issue)</td>
  <td>$(ConvertTo-HtmlEncoded $f.Tool)</td>
</tr>
"@
        }
    }
    $rowsHtml = if ($rows) { $rows -join "`n" } else { '<tr><td colspan="6">No findings.</td></tr>' }

    $disabledNote = if ($Model.DisabledAnalyzers.Count -gt 0) {
        "<p class='warn'>Not checked this run (disabled): $(ConvertTo-HtmlEncoded ($Model.DisabledAnalyzers -join ', '))</p>"
    } else { '' }

    # Strict inline CSP; no external/inline scripts; self-contained.
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'">
<title>media-transfer scan report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 1.5rem; color: #1a202c; }
  h1 { font-size: 1.3rem; }
  .summary { border-left: 6px solid $riskColor; padding: .5rem 1rem; background: #f7fafc; }
  .risk { font-weight: 700; color: $riskColor; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: .9rem; }
  th, td { border: 1px solid #e2e8f0; padding: .4rem .6rem; text-align: left; vertical-align: top; }
  th { background: #edf2f7; }
  .badge { padding: .1rem .4rem; border-radius: .25rem; color: #fff; font-size: .75rem; }
  .badge.critical { background: #b00020; } .badge.high { background: #d9480f; }
  .badge.medium { background: #b8860b; } .badge.low { background: #2b6cb0; } .badge.info { background: #718096; }
  .warn { color: #b00020; font-weight: 600; }
  .meta { color: #4a5568; font-size: .85rem; }
</style>
</head>
<body>
<h1>media-transfer-scan-tool report</h1>
<div class="summary">
  <div>Overall risk: <span class="risk">$(ConvertTo-HtmlEncoded $Model.OverallRisk)</span></div>
  <div>CRIT $($Model.Counts.CRITICAL) &middot; HIGH $($Model.Counts.HIGH) &middot; MED $($Model.Counts.MEDIUM) &middot; LOW $($Model.Counts.LOW) &middot; INFO $($Model.Counts.INFO)</div>
</div>
<p class="meta">
  Scan root: $(ConvertTo-HtmlEncoded $Model.ScanRoot)<br>
  Generated (UTC): $(ConvertTo-HtmlEncoded $Model.GeneratedUtc) &middot; elapsed $($Model.ElapsedSeconds)s<br>
  Profile/Mode: $(ConvertTo-HtmlEncoded $Model.Profile) / $(ConvertTo-HtmlEncoded $Model.Mode) &middot; schema $(ConvertTo-HtmlEncoded $Model.SchemaVersion)
</p>
$disabledNote
<table>
  <thead><tr><th>Severity</th><th>Type</th><th>Category</th><th>File</th><th>Issue</th><th>Tool</th></tr></thead>
  <tbody>
$rowsHtml
  </tbody>
</table>
</body>
</html>
"@
    $html | Set-Content -LiteralPath $ReportPath -Encoding utf8
    return $ReportPath
}

function Write-Reports {
    param([PSCustomObject]$ScanResult, [string]$ReportsDir)
    if (-not (Test-Path -LiteralPath $ReportsDir)) { New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $model = Get-ReportModel -ScanResult $ScanResult
    [PSCustomObject]@{
        Model = $model
        Json  = Write-JsonReport -Model $model -ReportPath (Join-Path $ReportsDir "summary_$stamp.json")
        Html  = Write-HtmlReport -Model $model -ReportPath (Join-Path $ReportsDir "summary_$stamp.html")
        Txt   = Write-TxtReport  -Model $model -ReportPath (Join-Path $ReportsDir "summary_$stamp.txt")
    }
}
