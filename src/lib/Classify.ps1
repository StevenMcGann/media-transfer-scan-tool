#Requires -Version 7.4
<#
    Classify.ps1 - the router (PLAN §3.7). Decides each file's effective Type by
    content (magic bytes / shebang) over extension, and emits a disguised-file
    finding when the declared extension disagrees with detected content.

    All sniffing is STATIC: it reads leading bytes only, never executes a file.
#>

# Declared type from extension (the weakest signal; the "intent of record").
$script:ExtTypeMap = @{
    '.py' = 'python'; '.pyw' = 'python'; '.ipynb' = 'python'
    # .whl and .egg are ZIP-based Python formats — type is python, not generic archive.
    # The ZIP magic bytes (PK) are expected and should NOT trigger a disguised-file finding.
    '.whl' = 'python'; '.egg' = 'python'
    '.ps1' = 'powershell'; '.psm1' = 'powershell'; '.psd1' = 'powershell'
    '.sh' = 'shell'; '.bash' = 'shell'; '.zsh' = 'shell'; '.ksh' = 'shell'
    '.pdf' = 'pdf'
    '.doc' = 'office'; '.docx' = 'office'; '.docm' = 'office'; '.xls' = 'office'
    '.xlsx' = 'office'; '.xlsm' = 'office'; '.ppt' = 'office'; '.pptx' = 'office'; '.rtf' = 'office'
    '.pkl' = 'model'; '.pickle' = 'model'; '.pt' = 'model'; '.pth' = 'model'
    '.joblib' = 'model'; '.safetensors' = 'model'; '.gguf' = 'model'
    '.zip' = 'archive'; '.tgz' = 'archive'; '.tar' = 'archive'; '.gz' = 'archive'
    '.js' = 'npm'; '.mjs' = 'npm'; '.cjs' = 'npm'
}

# ZIP-based formats whose magic bytes (PK) legitimately don't match their declared type.
# Suppress the disguised-file finding for these — the ZIP container is expected by design.
$script:KnownZipContainerTypes = @('python', 'office', 'npm')

function Get-DeclaredType {
    param([System.IO.FileInfo]$File)
    $name = $File.Name.ToLowerInvariant()
    if ($name.EndsWith('.tar.gz')) { return 'archive' }
    $ext = $File.Extension.ToLowerInvariant()
    return $script:ExtTypeMap[$ext]   # $null if unknown
}

function Get-MagicType {
    <#
        Inspect leading bytes. Returns a PSCustomObject { Type; Confidence } or $null.
        Static byte inspection only.
    #>
    param([string]$Path)

    # Read enough leading bytes to capture a full shebang line / signature
    # while staying cheap. (Whole-file hashing happens elsewhere.)
    $bytes = [byte[]]::new(0)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $buf = [byte[]]::new(512)
            $read = $fs.Read($buf, 0, 512)
            $bytes = $buf[0..([Math]::Max($read - 1, 0))]
        } finally { $fs.Dispose() }
    } catch { return $null }

    if ($bytes.Count -lt 2) { return $null }

    # Hex only needs the first few bytes for format signatures.
    $hex = (($bytes | Select-Object -First 8) | ForEach-Object { $_.ToString('X2') }) -join ''
    $ascii = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { "`n" } })

    # Strong binary-format signatures.
    if ($hex.StartsWith('25504446')) { return [PSCustomObject]@{ Type = 'pdf'; Confidence = 'HIGH' } }       # %PDF
    if ($hex.StartsWith('D0CF11E0')) { return [PSCustomObject]@{ Type = 'office'; Confidence = 'HIGH' } }     # OLE/CFB
    if ($hex.StartsWith('504B0304') -or $hex.StartsWith('504B0506')) { return [PSCustomObject]@{ Type = 'archive'; Confidence = 'MEDIUM' } } # PK (zip-family; needs entry disambiguation - TODO §3.7)
    if ($hex.StartsWith('1F8B')) { return [PSCustomObject]@{ Type = 'archive'; Confidence = 'HIGH' } }        # gzip
    if ($hex.StartsWith('4D5A')) { return [PSCustomObject]@{ Type = 'native-binary'; Confidence = 'HIGH' } }  # MZ (PE)
    if ($hex.StartsWith('7F454C46')) { return [PSCustomObject]@{ Type = 'native-binary'; Confidence = 'HIGH' } } # ELF
    if ($ascii.StartsWith('{\rtf')) { return [PSCustomObject]@{ Type = 'office'; Confidence = 'HIGH' } }      # RTF

    # Shebang -> script; parse interpreter from the first line only.
    if ($ascii.StartsWith('#!')) {
        $line = (($ascii -split "`n")[0]).ToLowerInvariant()
        if ($line -match 'python') { return [PSCustomObject]@{ Type = 'python'; Confidence = 'HIGH' } }
        if ($line -match 'pwsh|powershell') { return [PSCustomObject]@{ Type = 'powershell'; Confidence = 'HIGH' } }
        if ($line -match 'bash|/sh|zsh|ksh') { return [PSCustomObject]@{ Type = 'shell'; Confidence = 'HIGH' } }
        return [PSCustomObject]@{ Type = 'shell'; Confidence = 'LOW' }
    }

    return $null
}

function New-Unit {
    <#
        Classify one file into a Unit and (optionally) a disguised-file finding.
        Returns @{ Unit; Findings }.
    #>
    param([System.IO.FileInfo]$File, [string]$ScanRoot)

    $declared = Get-DeclaredType -File $File
    $magic    = Get-MagicType -Path $File.FullName

    # For known ZIP-container formats (.whl, .docx, .xlsx, etc.) the extension
    # provides the SEMANTIC type (python / office / npm); the PK magic bytes only
    # confirm "this is a ZIP archive", not which specific kind. Use the declared
    # type for routing when magic says archive AND declared is a ZIP-based format.
    $magicIsZip = $magic -and $magic.Type -eq 'archive'
    $isKnownContainer = $declared -and $script:KnownZipContainerTypes -contains $declared

    $detected   = if ($magicIsZip -and $isKnownContainer) {
                      $declared          # semantic ZIP format: .whl→python, .docx→office
                  } elseif ($magic) {
                      $magic.Type        # authoritative for all other magic signatures
                  } elseif ($declared) {
                      $declared          # extension-only fallback
                  } else {
                      'unsupported'
                  }
    $confidence = if ($magic) { $magic.Confidence } elseif ($declared) { 'LOW' } else { 'LOW' }

    $rel = $File.FullName.Substring($ScanRoot.TrimEnd('\').Length).TrimStart('\')

    $unit = [PSCustomObject]@{
        Type         = $detected
        DeclaredType = $declared ?? 'unknown'
        DetectedType = $detected
        Confidence   = $confidence
        Name         = $File.Name
        Path         = $File.FullName
        RelativePath = $rel
        StagingPath  = $null   # populated by archive extraction (v0.1.0 port)
    }

    $findings = @()
    # Mismatch: content says one thing, the extension claimed another.
    # Suppress for known ZIP-container formats (.whl, .docx, .xlsx, etc.) — the PK
    # magic bytes are expected and declaring them as disguised would be a false positive.
    $isKnownZipContainer = ($magic -and $magic.Type -eq 'archive' -and
                            $declared -and $script:KnownZipContainerTypes -contains $declared)

    if ($magic -and $declared -and $magic.Type -ne $declared -and
        -not ($declared -eq 'archive' -and $magic.Type -eq 'archive') -and
        -not $isKnownZipContainer) {
        # Severity scales with how innocent the disguise is.
        $innocent = @('.txt', '.log', '.dat', '', '.csv') -contains $File.Extension.ToLowerInvariant()
        $sev = if ($innocent) { 'HIGH' } else { 'MEDIUM' }
        $findings += New-Finding -Tool 'Classifier' -Category 'disguised-file' -Severity $sev `
            -Confidence $magic.Confidence -UnitType $detected -File $rel `
            -Issue ("Content detected as '{0}' but extension declares '{1}'." -f $magic.Type, $declared) `
            -TestID 'MTS-DISGUISE-001' `
            -Recommendation 'Treat as the detected type; investigate why the extension differs.'
    }
    # Also flag a script-like file wearing a non-script/innocent extension with no declared type.
    elseif ($magic -and -not $declared -and $magic.Type -in @('python', 'powershell', 'shell')) {
        $findings += New-Finding -Tool 'Classifier' -Category 'disguised-file' -Severity 'HIGH' `
            -Confidence $magic.Confidence -UnitType $detected -File $rel `
            -Issue ("Script content ('{0}') under a non-script extension '{1}'." -f $magic.Type, ($File.Extension ? $File.Extension : '<none>')) `
            -TestID 'MTS-DISGUISE-002' `
            -Recommendation 'Review: scripts hidden behind innocent extensions are a common evasion.'
    }

    return @{ Unit = $unit; Findings = $findings }
}
