#Requires -Version 7.4
<#
    Classify.ps1 - the router (PLAN §3.7). Decides each file's effective Type by
    CONTENT over extension, and emits a disguised-file finding when the declared
    extension disagrees with detected content.

    Signals, strongest first (PLAN §3.7):
      1. Magic bytes / format signature  (binary formats)
      2. Shebang (#! on line 1)          (scripts that declare their interpreter)
      3. Language content signatures      (scored heuristics — catches a script
                                           hidden in an innocent extension with NO
                                           shebang, e.g. a PowerShell downloader.txt)
      4. Extension                        (weakest — the declared intent)

    All sniffing is STATIC: it reads leading bytes only, never executes a file.
#>

# Declared type from extension (the weakest signal; the "intent of record").
$script:ExtTypeMap = @{
    '.py' = 'python'; '.pyw' = 'python'; '.ipynb' = 'python'
    # .whl and .egg are ZIP-based Python formats — type is python, not generic archive.
    '.whl' = 'python'; '.egg' = 'python'
    '.ps1' = 'powershell'; '.psm1' = 'powershell'; '.psd1' = 'powershell'
    '.sh' = 'shell'; '.bash' = 'shell'; '.zsh' = 'shell'; '.ksh' = 'shell'
    '.bat' = 'batch'; '.cmd' = 'batch'
    '.pdf' = 'pdf'
    '.doc' = 'office'; '.docx' = 'office'; '.docm' = 'office'; '.xls' = 'office'
    '.xlsx' = 'office'; '.xlsm' = 'office'; '.ppt' = 'office'; '.pptx' = 'office'; '.rtf' = 'office'
    '.pkl' = 'model'; '.pickle' = 'model'; '.pt' = 'model'; '.pth' = 'model'
    '.joblib' = 'model'; '.safetensors' = 'model'; '.gguf' = 'model'
    '.zip' = 'archive'; '.tgz' = 'archive'; '.tar' = 'archive'; '.gz' = 'archive'
    '.js' = 'npm'; '.mjs' = 'npm'; '.cjs' = 'npm'; '.ts' = 'npm'
}

# Specific filenames that determine type regardless of extension (.json is generic,
# but package.json / package-lock.json are npm manifests).
$script:FilenameTypeMap = @{
    'package.json'      = 'npm'
    'package-lock.json' = 'npm'
}

# ZIP-based formats whose magic bytes (PK) legitimately don't match their declared type.
# 'model' is here because PyTorch .pt/.pth are ZIP archives containing data.pkl.
$script:KnownZipContainerTypes = @('python', 'office', 'npm', 'model')

# Types that represent executable scripts — disguising one of these under an
# innocent extension is the high-value evasion this module exists to catch.
$script:ScriptTypes = @('python', 'powershell', 'shell', 'batch', 'npm')

# Content-signature patterns (signal #3). Distinct-match counts per language;
# the highest count >= 2 wins. Patterns are chosen to be specific enough that
# ordinary prose does not trigger them.
$script:ContentSignatures = [ordered]@{
    powershell = @(
        '\[CmdletBinding\(\)\]',
        '\bparam\s*\(',
        '\$PSVersionTable',
        '\bInvoke-Expression\b', '\bIEX\b',
        '\b(Get|Set|New|Remove|Invoke|Import|Export|Write|Start|Stop)-[A-Za-z]\w+',
        '-ErrorAction\b',
        '\.DownloadString\(', '\.DownloadFile\(',
        '\bWrite-(Host|Output|Error|Verbose)\b',
        '\[System\.\w'
    )
    python = @(
        '(?m)^\s*import\s+\w',
        '(?m)^\s*from\s+[\w\.]+\s+import\s',
        '(?m)^\s*def\s+\w+\s*\(',
        '(?m)^\s*class\s+\w+\s*[:\(]',
        '__name__\s*==\s*[''"]__main__[''"]',
        '\bprint\s*\(',
        '\bos\.system\s*\(', '\bsubprocess\.\w'
    )
    shell = @(
        '(?m)^\s*if\s+\[',
        '\bthen\b', '\bfi\b', '\besac\b', '\bdone\b',
        '(?m)^\s*export\s+\w+=',
        '\$\([^)]+\)',
        '(?m)^\s*(curl|wget|chmod|chown)\b',
        '\|\s*(bash|sh)\b'
    )
    batch = @(
        '(?im)^\s*@echo\s+off',
        '(?im)^\s*goto\s+\w',
        '(?im)^\s*setlocal\b',
        '(?im)^\s*set\s+\w+=',
        '(?im)^\s*call\s+\S',
        '(?im)^\s*if\s+exist\b',
        '%\w+%'
    )
}

function Get-DeclaredType {
    param([System.IO.FileInfo]$File)
    $name = $File.Name.ToLowerInvariant()
    if ($script:FilenameTypeMap.ContainsKey($name)) { return $script:FilenameTypeMap[$name] }
    if ($name.EndsWith('.tar.gz')) { return 'archive' }
    $ext = $File.Extension.ToLowerInvariant()
    return $script:ExtTypeMap[$ext]   # $null if unknown
}

function Get-MagicType {
    <#
        Signals 1 & 2: binary magic bytes + shebang. Returns
        { Type; Confidence; Source } or $null. Static byte inspection only.
    #>
    param([string]$Path)

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

    $hex   = (($bytes | Select-Object -First 8) | ForEach-Object { $_.ToString('X2') }) -join ''
    $ascii = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { "`n" } })

    if ($hex.StartsWith('25504446')) { return [PSCustomObject]@{ Type = 'pdf';           Confidence = 'HIGH';   Source = 'magic' } } # %PDF
    if ($hex.StartsWith('D0CF11E0')) { return [PSCustomObject]@{ Type = 'office';        Confidence = 'HIGH';   Source = 'magic' } } # OLE/CFB
    if ($hex.StartsWith('504B0304') -or $hex.StartsWith('504B0506')) { return [PSCustomObject]@{ Type = 'archive'; Confidence = 'MEDIUM'; Source = 'magic' } } # PK
    if ($hex.StartsWith('1F8B'))     { return [PSCustomObject]@{ Type = 'archive';       Confidence = 'HIGH';   Source = 'magic' } } # gzip
    if ($hex.StartsWith('4D5A'))     { return [PSCustomObject]@{ Type = 'native-binary'; Confidence = 'HIGH';   Source = 'magic' } } # MZ (PE)
    if ($hex.StartsWith('7F454C46')) { return [PSCustomObject]@{ Type = 'native-binary'; Confidence = 'HIGH';   Source = 'magic' } } # ELF
    if ($ascii.StartsWith('{\rtf'))  { return [PSCustomObject]@{ Type = 'office';        Confidence = 'HIGH';   Source = 'magic' } } # RTF

    if ($ascii.StartsWith('#!')) {
        $line = (($ascii -split "`n")[0]).ToLowerInvariant()
        if ($line -match 'python')          { return [PSCustomObject]@{ Type = 'python';     Confidence = 'HIGH'; Source = 'shebang' } }
        if ($line -match 'pwsh|powershell') { return [PSCustomObject]@{ Type = 'powershell'; Confidence = 'HIGH'; Source = 'shebang' } }
        if ($line -match 'bash|/sh|zsh|ksh'){ return [PSCustomObject]@{ Type = 'shell';      Confidence = 'HIGH'; Source = 'shebang' } }
        return [PSCustomObject]@{ Type = 'shell'; Confidence = 'LOW'; Source = 'shebang' }
    }

    return $null
}

function Get-ContentSignature {
    <#
        Signal 3: score the leading text against language signatures. Returns
        { Type; Confidence; Source='signature'; Score } or $null. Only runs on
        text-like content (so binaries already handled by magic are skipped).
    #>
    param([string]$Path)

    $bytes = [byte[]]::new(0)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $buf = [byte[]]::new(8192)
            $read = $fs.Read($buf, 0, 8192)
            if ($read -le 0) { return $null }
            $bytes = $buf[0..($read - 1)]
        } finally { $fs.Dispose() }
    } catch { return $null }

    # Text-likeness gate: mostly printable/whitespace, no NUL bytes.
    $printable = 0
    foreach ($b in $bytes) {
        if ($b -eq 0) { return $null }                                  # NUL → binary
        if ($b -ge 32 -and $b -le 126) { $printable++ }
        elseif ($b -in 9, 10, 13) { $printable++ }                      # tab/CR/LF
    }
    if (($printable / $bytes.Count) -lt 0.90) { return $null }

    $text = [System.Text.Encoding]::UTF8.GetString($bytes)

    $best = $null
    foreach ($lang in $script:ContentSignatures.Keys) {
        $hits = 0
        foreach ($pat in $script:ContentSignatures[$lang]) {
            if ($text -match $pat) { $hits++ }
        }
        if ($hits -ge 2 -and ($null -eq $best -or $hits -gt $best.Score)) {
            $best = [PSCustomObject]@{ Type = $lang; Score = $hits }
        }
    }
    if (-not $best) { return $null }

    $conf = if ($best.Score -ge 3) { 'HIGH' } else { 'MEDIUM' }
    return [PSCustomObject]@{ Type = $best.Type; Confidence = $conf; Source = 'signature'; Score = $best.Score }
}

function New-Unit {
    <#
        Classify one file into a Unit and (optionally) a disguised-file finding.
        Returns @{ Unit; Findings }.
    #>
    param([System.IO.FileInfo]$File, [string]$ScanRoot)

    $declared = Get-DeclaredType -File $File
    $det      = Get-MagicType -Path $File.FullName
    if (-not $det) { $det = Get-ContentSignature -Path $File.FullName }   # signal #3

    # Known ZIP-container formats (.whl, .docx, npm) — extension carries the
    # semantic type; PK magic only confirms "this is a ZIP". Route by extension.
    $isKnownContainer = $declared -and $script:KnownZipContainerTypes -contains $declared
    $isZipContainer   = $det -and $det.Type -eq 'archive' -and $isKnownContainer

    $detected = if ($isZipContainer) { $declared }
                elseif ($det)        { $det.Type }
                elseif ($declared)   { $declared }
                else                 { 'unsupported' }

    $confidence = if ($det) { $det.Confidence } else { 'LOW' }

    $rel = $File.FullName.Substring($ScanRoot.TrimEnd('\').Length).TrimStart('\')
    $ext = $File.Extension.ToLowerInvariant()

    $unit = [PSCustomObject]@{
        Type         = $detected
        DeclaredType = $declared ?? 'unknown'
        DetectedType = $detected
        Confidence   = $confidence
        Name         = $File.Name
        Path         = $File.FullName
        RelativePath = $rel
        StagingPath  = $null
    }

    $findings = @()

    # Disguise detection — content (magic/shebang/signature) disagrees with the
    # declared extension. Skip the known-ZIP-container case (expected, not a disguise).
    $contentDetected = $det -and ($det.Source -in @('magic', 'shebang', 'signature')) -and -not $isZipContainer
    $innocentExt     = @('.txt', '.log', '.dat', '.csv', '.bin', '') -contains $ext

    if ($contentDetected -and $det.Type -ne $declared) {
        if (-not $declared) {
            # Unknown/innocent extension hiding real content.
            if ($det.Type -in $script:ScriptTypes) {
                $sev = if ($innocentExt) { 'HIGH' } else { 'MEDIUM' }
                $findings += New-Finding -Tool 'Classifier' -Category 'disguised-file' -Severity $sev `
                    -Confidence $det.Confidence -UnitType $detected -File $rel `
                    -Issue ("Script content ('{0}', via {1}) under a non-script extension '{2}'." -f $det.Type, $det.Source, ($ext ? $ext : '<none>')) `
                    -TestID 'MTS-DISGUISE-002' `
                    -Recommendation 'Review: scripts hidden behind innocent extensions are a common evasion.'
            }
        }
        else {
            # Extension claims one type; content says another.
            $sev = if ($det.Type -in $script:ScriptTypes -and $innocentExt) { 'HIGH' } else { 'MEDIUM' }
            $findings += New-Finding -Tool 'Classifier' -Category 'disguised-file' -Severity $sev `
                -Confidence $det.Confidence -UnitType $detected -File $rel `
                -Issue ("Content detected as '{0}' (via {1}) but extension declares '{2}'." -f $det.Type, $det.Source, $declared) `
                -TestID 'MTS-DISGUISE-001' `
                -Recommendation 'Treat as the detected type; investigate why the extension differs.'
        }
    }

    return @{ Unit = $unit; Findings = $findings }
}
