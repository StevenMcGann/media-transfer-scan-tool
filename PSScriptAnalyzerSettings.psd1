@{
    # PSScriptAnalyzer settings for media-transfer-scan-tool's OWN source.
    # The engine targets PowerShell 7.4+ and is operator-facing console tooling,
    # so a few default rules don't apply and are excluded to keep findings signal.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # PS 7 writes UTF-8 *without* BOM by design (PLAN §6 — leaving 5.1 behind).
        'PSUseBOMForUnicodeEncodedFile',
        # Operator-facing console output is intentional (banners, status lines).
        'PSAvoidUsingWriteHost',
        # Internal helper naming; not public cmdlets bound to a noun convention.
        'PSUseSingularNouns',
        # Internal helpers are not user-invoked state-changing cmdlets needing -WhatIf.
        'PSUseShouldProcessForStateChangingFunctions',
        # `-Profile` is a deliberate parameter name (core|full); scoped, not the $PROFILE var.
        'PSAvoidAssignmentToAutomaticVariable',
        # Analyzer Invoke blocks must accept the ($Unit, $Context) contract signature
        # even when one is unused — not a real defect.
        'PSReviewUnusedParameter',
        # Write-Log is our intentional internal logging helper (no core built-in by that name).
        'PSAvoidOverwritingBuiltInCmdlets'
    )
}
