#Requires -Version 7.4
<#
    DetectSecrets analyzer — finds hardcoded credentials, tokens, API keys, and
    other secrets in source files via Yelp's detect-secrets.

    Ported from scan-python-packages v1.6.1 Invoke-DetectSecretsScan.
    Scans the extracted StagingPath for archive units, or the file itself for
    loose .py units. Uses Push-Location so reported paths are clean and relative.

    Carry-forward note: detect-secrets writes JSON to stdout but also writes to
    stderr; the stderr must be discarded (2>$null) or it corrupts the JSON. This
    is the one v1.6.1 stderr-redirection that survives on PS 7 (it's about output
    cleanliness, not EAP).

    Tier: deep (opt-in, default-off) — entropy-based matching is false-positive
    heavy on routine ingress. Enable with -Profile full or -EnableAnalyzers DetectSecrets.
#>
@{
    Name           = 'DetectSecrets'
    Version        = '0.1.0'
    UnitTypes      = @('python')
    RequiredTools  = @(@{ Kind = 'pip'; Id = 'detect-secrets'; MinVersion = '1.4.0'; BundlePath = $null })
    Offline        = $true
    Tier           = 'deep'
    DefaultEnabled = $false
    Invoke         = {
        param($Unit, $Context)

        $target = if ($Unit.PSObject.Properties['StagingPath'] -and $Unit.StagingPath) {
            $Unit.StagingPath
        } else {
            $Unit.Path
        }
        if (-not $target -or -not (Test-Path -LiteralPath $target)) { return @() }

        $tool = $Context.Tools['detect-secrets']
        if (-not $tool -or -not $tool.Available) {
            return @(New-Finding -Tool 'DetectSecrets' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue 'detect-secrets not available — secret scan skipped.' `
                -TestID 'MTS-SECRETS-UNAVAIL' `
                -Recommendation 'Run with -AutoInstall (online) or vendor detect-secrets in the offline bundle.')
        }
        $dsExe = Join-Path $tool.ScriptsDir 'detect-secrets.exe'
        $pythonExe = $Context.Venv?.Python
        if ((-not $pythonExe -or -not (Test-Path -LiteralPath $pythonExe)) -and
            -not (Test-Path -LiteralPath $dsExe)) {
            return @(New-Finding -Tool 'DetectSecrets' -Category 'parser' -Severity 'INFO' `
                -Confidence 'HIGH' -UnitType 'python' -File $Unit.RelativePath `
                -Issue 'detect-secrets module/launcher is unavailable.' -TestID 'MTS-SECRETS-MISSING')
        }
        $dsCommand = if ($pythonExe -and (Test-Path -LiteralPath $pythonExe)) { $pythonExe } else { $dsExe }
        $dsPrefix = if ($dsCommand -eq $pythonExe) {
            @('-c', 'from detect_secrets.main import main; main()')
        } else { @() }

        # Resolve scan dir + arg so detect-secrets emits clean relative paths.
        if (Test-Path -LiteralPath $target -PathType Leaf) {
            $pushDir = [IO.Path]::GetDirectoryName($target)
            $scanArg = [IO.Path]::GetFileName($target)
        } else {
            $pushDir = $target
            $scanArg = '.'
        }

        $tmpJson  = Join-Path $env:TEMP "mts_ds_$([IO.Path]::GetRandomFileName()).json"
        $findings = [System.Collections.Generic.List[object]]::new()
        try {
            # WorkingDirectory replaces Push-Location; the helper keeps stdout (the
            # JSON) and stderr separate, so detect-secrets' stderr progress noise
            # never pollutes the JSON we persist.
            $r = Invoke-BoundedProcess -FilePath $dsCommand -Arguments @($dsPrefix + @('scan', '--all-files', '--no-verify', $scanArg)) `
                -TimeoutSeconds $Context.TimeoutSeconds -WorkingDirectory $pushDir
            if (-not $r.Started) {
                return @(New-ToolBlockedFinding -Tool 'DetectSecrets' -UnitType $Unit.Type -File $Unit.RelativePath -Reason $r.StartError)
            }
            if ($r.TimedOut) {
                Write-Log -Level WARN -Message "DetectSecrets: timed out ($($Context.TimeoutSeconds)s) for $($Unit.RelativePath)."
                return @(New-TimeoutFinding -Tool 'DetectSecrets' -UnitType $Unit.Type -File $Unit.RelativePath -TimeoutSeconds $Context.TimeoutSeconds)
            }
            Set-Content -LiteralPath $tmpJson -Value $r.StdOut -Encoding utf8

            if (Test-Path -LiteralPath $tmpJson) {
                $raw = Get-Content -LiteralPath $tmpJson -Raw | ConvertFrom-Json
                if ($raw.PSObject.Properties['results'] -and $raw.results) {
                    $resultPaths = @($raw.results.PSObject.Properties | ForEach-Object { $_.Name })
                    foreach ($filePath in $resultPaths) {
                        # Report path relative to the unit for archives.
                        $relFile = if ($Unit.StagingPath) { "$($Unit.RelativePath)!$($filePath.TrimStart('.','/','\'))" } else { $Unit.RelativePath }
                        foreach ($secret in $raw.results.$filePath) {
                            $findings.Add((New-Finding `
                                -Tool       'DetectSecrets' `
                                -Category   'secrets' `
                                -Severity   'HIGH' `
                                -Confidence 'MEDIUM' `
                                -UnitType   'python' `
                                -File       $relFile `
                                -Line       ([int]$secret.line_number) `
                                -Issue      "Potential secret detected: $($secret.type)" `
                                -TestID     $secret.type `
                                -Recommendation 'Verify and rotate the credential if real; never admit hardcoded secrets.'))
                        }
                    }
                }
                Write-Log -Level INFO -Message "DetectSecrets: $($findings.Count) potential secret(s) in $($Unit.RelativePath)."
            }
        } catch {
            Write-Log -Level WARN -Message "DetectSecrets: scan error for $($Unit.RelativePath): $_"
            $findings.Add((New-Finding -Tool 'DetectSecrets' -Category 'parser' -Severity 'LOW' `
                -Confidence 'LOW' -UnitType 'python' -File $Unit.RelativePath `
                -Issue "detect-secrets scan error: $_" -TestID 'MTS-SECRETS-ERR'))
        } finally {
            Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
        }
        return $findings.ToArray()
    }
}
