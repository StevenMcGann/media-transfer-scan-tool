#Requires -Version 7.4
<#
    Bandit analyzer - STUB (v0.1 scaffold). The real port (running Bandit from the
    scanner venv over Python source) lands during v0.1.0 implementation.

    Lives in the opt-in `deep` tier: noisy on routine ingress, so default-off.
    Run with -Profile full (or -EnableAnalyzers Bandit) to include it. Emitting a
    single INFO placeholder lets us SEE that enablement/selection works.
#>
@{
    Name           = 'Bandit'
    Version        = '0.1.0-stub'
    UnitTypes      = @('python')
    RequiredTools  = @(@{ Kind = 'pip'; Id = 'bandit'; MinVersion = '1.7.0'; BundlePath = $null })
    Offline        = $true
    Tier           = 'deep'
    DefaultEnabled = $false
    Invoke         = {
        param($Unit, $Context)
        New-Finding -Tool 'Bandit' -Category 'parser' -Severity 'INFO' -Confidence 'LOW' `
            -UnitType $Unit.Type -File $Unit.RelativePath `
            -Issue 'Bandit analyzer is a v0.1 scaffold stub (no real scan yet).' `
            -TestID 'MTS-BANDIT-STUB'
    }
}
