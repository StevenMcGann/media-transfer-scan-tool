# Offline bundle

`build-bundle.ps1` assembles a self-contained bundle that runs the scanner on an
air-gapped operator host with nothing pre-installed (PLAN §3.5/§3.6).

## Build (on a connected dev host)

```powershell
# Full, operator-ready bundle (downloads pwsh 7.4 LTS, builds the scanner venv):
pwsh ./bundle/build-bundle.ps1 -Version 0.1.0 -Zip

# Using a pre-downloaded portable pwsh zip instead of fetching it:
pwsh ./bundle/build-bundle.ps1 -PwshZip C:\downloads\PowerShell-7.4.6-win-x64.zip -Zip

# Skeleton (layout only — NOT operator-ready; for testing the build itself):
pwsh ./bundle/build-bundle.ps1 -SkipPwsh -SkipVenv
```

## Output layout

```
media-transfer-scan-tool-<version>/
  Scan.cmd              operator entry point
  bootstrap.ps1         5.1-safe launcher (resolves PS 7.4+, runs the engine)
  src/                  engine + lib + analyzers + helpers
  tools/pwsh/           vendored portable PowerShell 7.4 (Windows x64)
  tools/venv/           vendored scanner venv (bandit, pip-audit, detect-secrets, pefile, pyelftools)
  manifest.json         bundle + tool versions, build date, completeness flag
```

`manifest.json` has `complete: true` only when both the runtime and venv are
vendored. The bootstrapper prefers `tools/pwsh` (authoritative) and, seeing
`tools/venv`, runs the engine in **offline** mode against the vendored venv.

## Delivery + use

Deliver the bundle to the isolated operator host via the controlled read-only
channel (see [../docs/test-environment.md](../docs/test-environment.md)). The
operator runs:

```
Scan.cmd -Path "D:\incoming\submission"
```

## TODO (later)

- Vendored CVE/OSV advisory cache so pip-audit runs fully offline (currently the
  advisory lookup needs connectivity; `manifest.advisoryDb.date` will record the
  cache snapshot once added).
- Bundle integrity hash / signature.
