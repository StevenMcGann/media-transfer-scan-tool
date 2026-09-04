# Offline bundle

`build-bundle.ps1` assembles a self-contained bundle that runs the scanner on an
air-gapped operator host with nothing pre-installed. See the runtime and release
requirements in [../PLAN.md](../PLAN.md).

## Build (on a connected dev host)

```powershell
# Full v0.14.0 operator bundle (downloads the pinned pwsh 7.4 LTS patch and builds the scanner venv):
pwsh ./bundle/build-bundle.ps1 -Version 0.14.0 -PwshVersion 7.4.19 -Zip

# Using a pre-downloaded portable pwsh zip instead of fetching it:
pwsh ./bundle/build-bundle.ps1 -Version 0.14.0 -PwshVersion 7.4.19 -PwshZip C:\downloads\PowerShell-7.4.19-win-x64.zip -Zip

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
  tools/python/         vendored Python embeddable runtime (Windows x64)
  tools/venv/           vendored scanner packages (bandit, pip-audit, detect-secrets, pefile, pyelftools)
  manifest.json         bundle/tool versions, build date, completeness flag, sealed-file hashes
```

`manifest.json` has `complete: true` only when the PowerShell runtime, Python
runtime, and scanner packages are vendored. The bootstrapper verifies its sealed-file SHA-256 values and prefers
`tools/pwsh` (authoritative). When `tools/venv` exists, the engine uses those
vendored tools but keeps the requested mode: online by default, or offline only
when the operator passes `-Mode offline`.

GitHub's automatically generated source archives are not operator bundles. A
release is operator-ready only when its assets include the ZIP produced here.

## Delivery + use

Deliver the bundle to the isolated operator host via the controlled read-only
channel (see [../docs/test-environment.md](../docs/test-environment.md)). The
operator runs:

```
Scan.cmd -Path "D:\incoming\submission"
```

## Remaining bundle work

- Vendored CVE/OSV advisory cache so pip-audit runs fully offline (currently the
  advisory lookup needs connectivity; `manifest.advisoryDb.date` will record the
  cache snapshot once added).
- Cryptographic signing of the manifest or bundle. Per-file SHA-256 integrity
  verification is already implemented, but hashes stored in the same unsigned
  bundle do not establish publisher authenticity.
