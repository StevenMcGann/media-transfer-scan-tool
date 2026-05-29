#Requires -Version 7.4
<#
    FileHash analyzer - real, working. Records a SHA-256 for every file as an
    INFO finding, seeding the audit manifest (PLAN §4 cross-cutting). Demonstrates
    the descriptor contract end-to-end with genuine output.
#>
@{
    Name           = 'FileHash'
    Version        = '0.1.0'
    UnitTypes      = @('any')
    RequiredTools  = @()
    Offline        = $true
    Tier           = 'core'
    DefaultEnabled = $true
    Invoke         = {
        param($Unit, $Context)
        try {
            $hash = (Get-FileHash -LiteralPath $Unit.Path -Algorithm SHA256).Hash
            New-Finding -Tool 'FileHash' -Category 'parser' -Severity 'INFO' -Confidence 'HIGH' `
                -UnitType $Unit.Type -File $Unit.RelativePath `
                -Issue "SHA-256: $hash" -TestID 'MTS-HASH-001'
        } catch {
            New-Finding -Tool 'FileHash' -Category 'parser' -Severity 'LOW' -Confidence 'LOW' `
                -UnitType $Unit.Type -File $Unit.RelativePath `
                -Issue "Could not hash file: $_" -TestID 'MTS-HASH-ERR'
        }
    }
}
