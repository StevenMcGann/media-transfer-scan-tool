#Requires -Version 7.4
<#
    Logging.ps1 - console + file logging and operator status output.
    Part of the media-transfer-scan-tool engine. Dot-sourced by the entry script.
#>

$script:LogPath = $null
$script:Quiet   = $false

function Initialize-Log {
    param([string]$LogDir)
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogPath = Join-Path $LogDir "run_$stamp.log"
    return $script:LogPath
}

function Write-Log {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory)][string]$Message
    )
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogPath) {
        Add-Content -LiteralPath $script:LogPath -Value $entry -Encoding utf8
    }
    if (-not $script:Quiet) {
        # Human/log noise goes to the information/host streams, never stdout,
    # so -Quiet -OutputFormat json keeps stdout pure.
        $color = switch ($Level) { 'INFO' { 'Cyan' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'DEBUG' { 'DarkGray' } }
        Write-Host $entry -ForegroundColor $color
    }
}

function Show-Status {
    param([string]$Message)
    if (-not $script:Quiet) { Write-Host "  >> $Message" -ForegroundColor White }
}
