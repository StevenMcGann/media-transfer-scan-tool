#Requires -Version 7.4
<#
    Shared, token-based PowerShell risk indicators.

    The scanner must recognize high-risk command and member names without
    carrying those names in its own PowerShell source.  Each candidate token is
    normalized and compared by SHA-256 digest.  No rule reconstructs indicator
    text, so loading the engine does not resemble script de-obfuscation.

    The Python helper uses the same digests as the preferred execution path.
    These functions preserve static coverage when Python is unavailable and
    supply token-aware signals to the disguised-file classifier.
#>

$script:MtsPowerShellTokenPattern = [regex]::new(
    '(?<![A-Za-z0-9_])(?:-[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9_-]*)(?![A-Za-z0-9_])',
    [Text.RegularExpressions.RegexOptions]::Compiled -bor
    [Text.RegularExpressions.RegexOptions]::CultureInvariant)

$script:MtsPowerShellRuleMaxBytes = 5000000
$script:MtsPowerShellFallbackMaxBytes = 262144
$script:MtsPowerShellFallbackMaxTokens = 100000
$script:MtsPowerShellFallbackMaxFindings = 1000
$script:MtsPowerShellFallbackMaxMilliseconds = 5000

# Digest -> rule.  Pair rules name the digest of the immediately following
# token; tail tokens are not independently reportable.
$script:MtsPowerShellIndicatorRules = [ordered]@{
    '9902663A76D7A84D5A9BBE338FA9817CDE901A67DD64314E22945801D183A09D' = @{
        Severity='HIGH'; TestID='PS-IEX'; Context='Any'; Classifier=$true
        Message='Dynamic expression execution primitive.'
    }
    '7BDC79A32A635567A95C3BCC72754B623A417A21FA78154FE21E8CB8A963E47E' = @{
        Severity='HIGH'; TestID='PS-IEX'; Context='Any'; Classifier=$true
        Message='Dynamic expression execution primitive.'
    }
    'BB68081F43AE625A17063283B37A727EB79FA9F346CAEFBF729DFC0977403AA5' = @{
        Severity='HIGH'; TestID='PS-DOWNLOAD'; Context='MemberCall'; Classifier=$true
        Message='Network-client download method used for remote payload retrieval.'
    }
    '8D6F40E97020332EC4A9C077949B03190C586F074D928C6923A9DEAF87B98346' = @{
        Severity='HIGH'; TestID='PS-DOWNLOAD'; Context='MemberCall'; Classifier=$true
        Message='Network-client download method used for remote payload retrieval.'
    }
    '64523F7FB90D30E3203C13AB70DB6BD00F46C5804681E888E6F660C643CE5E25' = @{
        Severity='HIGH'; TestID='PS-DOWNLOAD'; Context='MemberCall'; Classifier=$true
        Message='Network-client download method used for remote payload retrieval.'
    }
    'D6B832EC499CBAB5CD8344D8107DCEC54FBE5049CCA7249113E4BCB37EBD3043' = @{
        Severity='HIGH'; TestID='PS-ENCODED-COMMAND'; Context='Any'; Classifier=$false
        Message='Encoded command-line content (common obfuscation).'
    }
    '8DE76D1DF3B6088F24383D86D51A8F4C60CC25BD8A8DCCF4753B743335D12F06' = @{
        Severity='HIGH'; TestID='PS-ENCODED-COMMAND'; Context='Any'; Classifier=$false
        Message='Encoded command-line content (common obfuscation).'
    }
    'CB9050410D3B62CB67F5811C5F8242A67DA1BA49422AA0358D1AE0B6DF98D5CF' = @{
        Severity='MEDIUM'; TestID='PS-BASE64-DECODE'; Context='Call'; Classifier=$false
        Message='Base64 decoding of embedded data.'
    }
    'B3AF578FDDE04CC108AB5A71AC2417388BB5599124EA52F498BA9154BEDAA3B7' = @{
        Severity='MEDIUM'; TestID='PS-HIDDEN-WINDOW'; Context='Pair'; Classifier=$false
        PairDigest='E564B4081D7A9EA4B00DADA53BDAE70C99B87B6FCE869F0C3DD4D2BFA1E53E1C'
        Message='Hidden-window process launch.'
    }
    'F4C5F28A8DFEC938CC0CE22256D33705EDF19F1ABF2F4A3A4035A84744908F80' = @{
        Severity='HIGH'; TestID='PS-AMSI-TAMPER'; Context='Any'; Classifier=$false
        Message='Antimalware interface tampering reference.'
    }
    '0669320B5058F4CFE827E208D721D8EBF76BC2E1BBF453766B054007C3AACD36' = @{
        Severity='HIGH'; TestID='PS-AMSI-TAMPER'; Context='Any'; Classifier=$false
        Message='Antimalware interface tampering reference.'
    }
    '2352DBCF9022952AD733DB2D079043E851230601A7833BB88A913A8361F737A5' = @{
        Severity='HIGH'; TestID='PS-AMSI-TAMPER'; Context='Any'; Classifier=$false
        Message='Antimalware interface tampering reference.'
    }
    '832735B8ABDDF1BEEF8D167B0F30B73DB49828A45BFF6AD4CD58A944B37B3633' = @{
        Severity='HIGH'; TestID='PS-DEFENDER-TAMPER'; Context='Any'; Classifier=$false
        Message='Endpoint-protection preference modification.'
    }
    '2F99DD1021CFC36E99910F971A36E02B11CBF110E35F82276EFBBBE4DC09AA34' = @{
        Severity='HIGH'; TestID='PS-DEFENDER-TAMPER'; Context='Any'; Classifier=$false
        Message='Endpoint-protection preference modification.'
    }
    '38413B5546EBB90054237B770EC2700448B9EE419F76770FEC82856CF45D6154' = @{
        Severity='LOW'; TestID='PS-EXEC-BYPASS'; Context='Pair'; Classifier=$false
        PairDigest='F271A122BF4230C7C217B4CB8A66F8B4325B9C1821627DCA16924FFF32D6AA71'
        Message='Execution-policy bypass.'
    }
}

$script:MtsPowerShellRiskTokenDigests = [Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        $script:MtsPowerShellIndicatorRules.Keys
        $script:MtsPowerShellIndicatorRules.Values |
            Where-Object { $_.ContainsKey('PairDigest') } |
            ForEach-Object { $_.PairDigest }
    ),
    [StringComparer]::OrdinalIgnoreCase)

function Get-MtsTokenDigest {
    param([Parameter(Mandatory)][string]$Token)

    $bytes = [Text.Encoding]::UTF8.GetBytes($Token.ToLowerInvariant())
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Get-MtsNextNonWhitespaceCharacter {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][int]$Start)

    for ($i = $Start; $i -lt $Text.Length; $i++) {
        if (-not [char]::IsWhiteSpace($Text[$i])) { return [string]$Text[$i] }
    }
    return ''
}

function Get-MtsPreviousNonWhitespaceCharacter {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][int]$Start)

    for ($i = $Start; $i -ge 0; $i--) {
        if (-not [char]::IsWhiteSpace($Text[$i])) { return [string]$Text[$i] }
    }
    return ''
}

function Test-MtsPowerShellPairSeparator {
    <#
        Accept command-argument separators, not assignment or collection syntax.
        $Start/$End bound the separator; $TailEnd is where the tail token ends.
        An opening quote must be closed right AFTER the tail token -- reading
        $Text[$End] instead sees the tail's first character, which never equals
        the quote, silently dropping quoted pairs such as -Opt 'Value'.
    #>
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][int]$Start,
        [Parameter(Mandatory)][int]$End,
        [Parameter(Mandatory)][int]$TailEnd
    )

    if ($End -lt $Start) { return $false }
    $separator = $Text.Substring($Start, $End - $Start)
    $separatorMatch = [regex]::Match(
        $separator,
        '\A(?:(?:[^\S\r\n]+|`(?:\r\n|\r|\n)[^\S\r\n]*)+|:(?:(?:[^\S\r\n]+|`(?:\r\n|\r|\n)[^\S\r\n]*))*)(?<Quote>[''"]?)\z')
    if (-not $separatorMatch.Success) { return $false }
    $quote = $separatorMatch.Groups['Quote'].Value
    return -not $quote -or ($TailEnd -lt $Text.Length -and [string]$Text[$TailEnd] -eq $quote)
}

function Find-MtsPowerShellRiskIndicator {
    <# Return token-aware matches without returning the source token itself. #>
    param(
        [AllowEmptyString()][string]$Text,
        [int]$MaxTokens = 0,
        [int]$MaxResults = 0,
        [int]$MaxMilliseconds = 0,
        [ref]$LimitReason
    )

    if ($null -ne $LimitReason) { $LimitReason.Value = '' }

    if ([string]::IsNullOrEmpty($Text)) { return @() }

    $results = [Collections.Generic.List[object]]::new()
    $token = $script:MtsPowerShellTokenPattern.Match($Text)
    $tokenCount = 0
    $line = 1
    $lineCursor = 0
    $timer = if ($MaxMilliseconds -gt 0) { [Diagnostics.Stopwatch]::StartNew() } else { $null }

    while ($token.Success) {
        $nextToken = $token.NextMatch()
        $tokenCount++
        if ($MaxTokens -gt 0 -and $tokenCount -gt $MaxTokens) {
            if ($null -ne $LimitReason) { $LimitReason.Value = "candidate-token limit ($MaxTokens)" }
            break
        }
        if ($timer -and ($tokenCount % 1024) -eq 0 -and $timer.ElapsedMilliseconds -ge $MaxMilliseconds) {
            if ($null -ne $LimitReason) { $LimitReason.Value = "time limit (${MaxMilliseconds}ms)" }
            break
        }

        $digest = Get-MtsTokenDigest -Token $token.Value
        if ($script:MtsPowerShellIndicatorRules.Contains($digest)) {
            $rule = $script:MtsPowerShellIndicatorRules[$digest]
            $contextMatches = switch ($rule.Context) {
                'MemberCall' {
                    (Get-MtsPreviousNonWhitespaceCharacter -Text $Text -Start ($token.Index - 1)) -eq '.' -and
                    (Get-MtsNextNonWhitespaceCharacter -Text $Text -Start ($token.Index + $token.Length)) -eq '('
                }
                'Call' {
                    (Get-MtsNextNonWhitespaceCharacter -Text $Text -Start ($token.Index + $token.Length)) -eq '('
                }
                'Pair' {
                    $nextToken.Success -and
                    (Get-MtsTokenDigest -Token $nextToken.Value) -eq $rule.PairDigest -and
                    (Test-MtsPowerShellPairSeparator -Text $Text `
                        -Start ($token.Index + $token.Length) -End $nextToken.Index `
                        -TailEnd ($nextToken.Index + $nextToken.Length))
                }
                default { $true }
            }

            if ($contextMatches) {
                while ($lineCursor -lt $token.Index) {
                    if ($Text[$lineCursor] -eq "`n") { $line++ }
                    $lineCursor++
                }
                $results.Add([PSCustomObject]@{
                    Index  = $token.Index
                    Line   = $line
                    Digest = $digest
                    Rule   = $rule
                })
                if ($MaxResults -gt 0 -and $results.Count -ge $MaxResults -and $nextToken.Success) {
                    if ($null -ne $LimitReason) { $LimitReason.Value = "finding limit ($MaxResults)" }
                    break
                }
            }
        }
        $token = $nextToken
    }
    if ($timer) { $timer.Stop() }
    return $results.ToArray()
}
