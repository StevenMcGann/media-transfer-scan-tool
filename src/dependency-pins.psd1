# Pinned scanner dependency versions (F3 / issue #10).
#
# SINGLE SOURCE OF TRUTH for provisioning (src/lib/Provisioning.ps1) AND the
# offline bundle builder (bundle/build-bundle.ps1). Online provisioning installs
# exactly these versions (pkg==version) instead of "latest", which closes the
# "silently pull a newer / compromised release" supply-chain risk. The analyzer
# RequiredTools MinVersion remains the compatibility floor; these pins are the
# exact version actually installed (must be >= that floor).
#
# Lives under src/ so it ships in the bundle and is covered by the F1 SHA-256
# integrity seal. Bump versions deliberately, then re-run the test suite.
# Verified current/stable on 2026-06-22.
@{
    pip = @{
        'bandit'         = '1.9.4'
        'pip-audit'      = '2.10.1'
        'detect-secrets' = '1.5.0'
        'pefile'         = '2024.8.26'
        'pyelftools'     = '0.33'
        'shellcheck-py'  = '0.11.0.1'
        'oletools'       = '0.60.2'
    }
    psmodule = @{
        'PSScriptAnalyzer' = '1.25.0'
    }
}
