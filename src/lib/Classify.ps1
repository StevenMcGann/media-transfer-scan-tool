#Requires -Version 7.4
<#
    Classify.ps1 - the router. Decides each file's effective Type by
    CONTENT over extension, and emits a disguised-file finding when the declared
    extension disagrees with detected content.

    Signals, strongest first:
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
    # Model-adjacent formats PickleOpcodeScan has always scanned (a malicious
    # pickle stored under any of these extensions is exactly as executable —
    # scan_pickle.py's own suffix list already includes '.bin'). Recognizing
    # them here (rather than only inside PickleOpcodeScan's own archive walk,
    # which issue #31's recursive archive-member dispatch removed) means a
    # loose top-level file OR an archive member gets the same 'model' routing
    # either way — one classification decision, not two different code paths
    # that can silently drift apart.
    '.bin' = 'model'; '.h5' = 'model'; '.hdf5' = 'model'; '.pb' = 'model'
    '.onnx' = 'model'; '.npy' = 'model'; '.npz' = 'model'
    '.zip' = 'archive'; '.tgz' = 'archive'; '.tar' = 'archive'; '.gz' = 'archive'
    '.js' = 'npm'; '.mjs' = 'npm'; '.cjs' = 'npm'; '.ts' = 'npm'
    # NuGet package archive (issue #32 — OSV lookup). ZIP-based; id/version live in
    # the embedded .nuspec.
    '.nupkg' = 'nuget'
    # VB family (issue #25). Exported VBA modules (.bas/.cls/.frm/.vba) are inert
    # until imported; VBScript (.vbs/.vbe) and its wrappers (.wsf/.hta) execute on
    # double-click. Same language, same rule set — one unit type covers both.
    # NOTE: .cls and .frm are not exclusively VB (LaTeX class files also use .cls).
    # A misfiled one classifies as 'vba' and simply produces no findings.
    '.bas' = 'vba'; '.cls' = 'vba'; '.frm' = 'vba'; '.vba' = 'vba'
    '.vbs' = 'vba'; '.vbe' = 'vba'; '.wsf' = 'vba'; '.hta' = 'vba'
}

# Specific filenames that determine type regardless of extension (.json is generic,
# but package.json / package-lock.json are npm manifests).
$script:FilenameTypeMap = @{
    'package.json'      = 'npm'
    'package-lock.json' = 'npm'
    'npm-shrinkwrap.json' = 'npm'
    # PyPI dependency manifest (issue #32 — OSV lookup). Its own unit type, NOT
    # 'python': it's a list of `name==version` lines, not Python source, and
    # 'python' is claimed by PythonRules/Bandit/DetectSecrets, which would try
    # (and fail/misfire) to parse it as source. Only OsvScan claims this type.
    'requirements.txt'  = 'python-requirements'
    'pipfile.lock'      = 'python-requirements'
    'pyproject.toml'    = 'python-requirements'
    'poetry.lock'       = 'python-requirements'
    'uv.lock'           = 'python-requirements'
}

# ZIP-based formats whose magic bytes (PK) legitimately don't match their declared type.
# 'model' is here because PyTorch .pt/.pth are ZIP archives containing data.pkl.
$script:KnownZipContainerTypes = @('python', 'office', 'npm', 'model', 'nuget')

# Types that represent executable scripts — disguising one of these under an
# innocent extension is the high-value evasion this module exists to catch.
$script:ScriptTypes = @('python', 'powershell', 'shell', 'batch', 'npm', 'vba')

# Content-signature patterns (signal #3). Distinct-match counts per language;
# the highest count >= 2 wins. Patterns are chosen to be specific enough that
# ordinary prose does not trigger them.
#
# The offensive-PowerShell tokens are ASSEMBLED FROM FRAGMENTS so this engine
# file does not itself carry the contiguous strings that on-disk file AV / AMSI
# heuristics flag (same rationale as analyzers/PSScriptAnalyzer.ps1).
$psIex = 'Invoke-' + 'Expression'
$psDlS = 'Download' + 'String'
$psDlF = 'Download' + 'File'
$script:ContentSignatures = [ordered]@{
    powershell = @(
        '\[CmdletBinding\(\)\]',
        '\bparam\s*\(',
        '\$PSVersionTable',
        "\b($psIex)\b", '\bIEX\b',
        '\b(Get|Set|New|Remove|Invoke|Import|Export|Write|Start|Stop)-[A-Za-z]\w+',
        '-ErrorAction\b',
        "\.($psDlS)\(", "\.($psDlF)\(",
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
    # VB family — VBA modules and VBScript (issue #25). Patterns are deliberately
    # VB-exclusive to avoid stealing units from the other languages:
    #   - 'Sub' (never 'Function') as the procedure opener: 'function foo(' would
    #     otherwise match JavaScript, which has no signature block of its own and
    #     would then be reclassified and flagged as disguised.
    #   - 'Set x = New|CreateObject|obj.' requires the VB spacing; batch's
    #     'set VAR=value' (no spaces, no RHS keyword) must not match.
    vba = @(
        '(?im)^\s*Attribute\s+VB_Name\s*=',
        '(?im)^\s*Option\s+Explicit\s*$',
        '(?im)^\s*End\s+(Sub|Function|Property|With|Type)\s*$',
        '(?im)^\s*(Public\s+|Private\s+|Friend\s+)?Sub\s+\w+\s*\(',
        '(?im)^\s*Dim\s+\w+\s+As\s+\w',
        '(?im)^\s*Set\s+\w+\s*=\s*(New\s|CreateObject\s*\(|\w+\.)',
        '(?i)\bCreateObject\s*\(\s*["'']',
        '(?i)\bWScript\.(Shell|Echo|Sleep|Quit|Arguments|CreateObject)\b',
        '(?i)\b(vbCrLf|vbNormalFocus|vbHide|vbModal|vbNewLine)\b',
        '(?im)^\s*(Public\s+|Private\s+)?Declare\s+(PtrSafe\s+)?(Sub|Function)\s+\w+\s+Lib\b',
        '(?i)<script\s+language\s*=\s*["'']?vbscript'
    )
}

function Get-DeclaredType {
    param([System.IO.FileInfo]$File)
    $name = $File.Name.ToLowerInvariant()
    if ($script:FilenameTypeMap.ContainsKey($name)) { return $script:FilenameTypeMap[$name] }
    if ($name -match '^requirements[^\\/]*\.txt$') { return 'python-requirements' }
    if ($name.EndsWith('.nuspec')) { return 'nuget' }
    if ($name -eq 'metadata' -and $File.Directory -and $File.Directory.Name.ToLowerInvariant().EndsWith('.dist-info')) {
        return 'python-requirements'
    }
    if ($name -eq 'pkg-info' -and $File.Directory -and $File.Directory.Name.ToLowerInvariant().EndsWith('.egg-info')) {
        return 'python-requirements'
    }
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
    # A loose .nuspec is NuGet metadata, not a NuGet ZIP container: only .nupkg
    # is allowed to use the nuget semantic-container exception. Otherwise a ZIP
    # renamed to .nuspec could bypass generic archive-member dispatch.
    $isKnownContainer = $declared -and $script:KnownZipContainerTypes -contains $declared -and
                        ($declared -ne 'nuget' -or $File.Extension.Equals('.nupkg', [StringComparison]::OrdinalIgnoreCase))
    $isZipContainer   = $det -and $det.Type -eq 'archive' -and $isKnownContainer

    $detected = if ($isZipContainer) { $declared }
                elseif ($det)        { $det.Type }
                elseif ($declared)   { $declared }
                else                 { 'unsupported' }

    $confidence = if ($det) { $det.Confidence } else { 'LOW' }

    # GetRelativePath, not string arithmetic: tolerant of trailing separators and
    # of UNC roots (\\server\share\...), where length-based Substring is fragile.
    $rel = [System.IO.Path]::GetRelativePath($ScanRoot, $File.FullName)
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
