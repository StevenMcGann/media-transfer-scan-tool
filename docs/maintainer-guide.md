# Maintainer guide

For building, testing, and shipping the tool. The engine targets **PowerShell
7.4+** and is operator-delivered as an **offline bundle**.

## Dev setup
- PowerShell 7.4+ (`pwsh`), Python 3.x, git.
- Pester 5.7.1 (`Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser`).

## Run from source (dev / online host)
```powershell
pwsh ./src/Invoke-MediaTransferScan.ps1 -Path .\some-folder
```
Online, analyzers self-provision into a venv beside the engine (`src/.scan-venv`).

## Tests
```powershell
python ./tests/fixtures/build_fixtures.py   # (re)generate synthetic fixtures
pwsh ./tests/Run-Tests.ps1                  # full Pester suite
```
- Fixtures under `tests/fixtures/corpus/` are **generated** (gitignored); CI
  regenerates them. Committed wheels with real metadata are the exception.
- `-Tag Online` tests provision real tools / hit live feeds (OSV); they're skipped
  if Python is absent.

## CI (GitHub Actions)
- **test.yml** — Pester suite + an end-to-end smoke (`Scan.cmd` operator chain) on `windows-latest` / pwsh 7.
- **security.yml** — PSScriptAnalyzer (fails on Error; tuned by `PSScriptAnalyzerSettings.psd1`), gitleaks, CodeQL (Python).
- **dependabot.yml** — keeps GitHub Actions current.

## Defender / AMSI self-check
The PowerShell analyzer detects offensive-PowerShell signatures (AMSI-tamper,
Defender-preference, downloaders, ...). Those tokens must **never** appear as
contiguous literals in shipped source — if they do, simply loading the engine
trips Defender's `Trojan:PowerShell/PsAttack.*` signature ("Possible AMSI
tampering"). They are assembled from fragments at runtime to avoid this.

On a Windows + Microsoft Defender host, verify the engine loads without tripping
Defender:
```powershell
pwsh ./tools/verify-amsi.ps1   # exit 0 = no new detection; 1 = a token leaked into a shipped file
```
It snapshots `Get-MpThreatDetection`, loads the full engine in a fresh `pwsh`, and
fails if any new detection appears. Run it after touching analyzer signatures.
**Never** add a literal trigger token (even in a comment) to a `src/` file.

## Build the offline bundle
On a **connected** host:
```powershell
pwsh ./bundle/build-bundle.ps1 -Version 0.13.0 -PwshVersion 7.4.19 -Zip
```
Produces `bundle/out/media-transfer-scan-tool-0.13.0/` (+ `.zip`) containing the
engine, a vendored portable **PowerShell 7.4 LTS**, the scanner **venv**, and
`manifest.json`. Flags: `-PwshZip <path>` to use a pre-downloaded pwsh,
`-SkipPwsh`/`-SkipVenv` for layout-only test builds.

Use the current project version and current PowerShell 7.4 LTS patch for each
release. The version values above describe v0.13.0; the release checklist below
requires updating them for later releases. GitHub's automatically generated
source archives are not operator-ready bundles.

Deliver the bundle to the operator host via the controlled read-only channel
(see [test-environment.md](test-environment.md)).

## Python helper scripts
Stdlib-only helpers under `src/helpers/` give precise, dependency-free analysis
that runs offline from the bundled venv or system Python (never importing the
target): `scan_pickle.py` (pickle opcode triage) and `scan_python.py` (the
AST-based curated rules behind the `PythonRules` analyzer). When adding a rule to
`scan_python.py`, also add a fixture in `build_fixtures.py` (`python_rules/`) and
assert it in `PythonRules.Tests.ps1` — including a precision case proving trigger
words inside strings/comments are **not** flagged.

## Adding an analyzer
1. Drop a descriptor in `src/analyzers/<Name>.ps1` returning a hashtable with
   `Name, Version, UnitTypes, RequiredTools, Offline, Tier, DefaultEnabled, Invoke`
   (see the current architecture in [PLAN.md](../PLAN.md)). The engine
   auto-registers it.
2. `Invoke { param($Unit,$Context) }` must **return `Finding[]`** (never throw),
   be **static** (never execute submitted content), and use `New-Finding`.
3. Add fixtures to `build_fixtures.py` and a `*.Tests.ps1` suite.

## Releasing
1. Bump `$script:ToolVersion` (entry script `.NOTES` + the constant), the
   `[x.y.z]` heading in `CHANGELOG.md`, the README status, and the bundle build
   version examples/default.
2. Check the current PowerShell 7.4 LTS patch, update `build-bundle.ps1` and the
   bundle examples together, and rebuild the operator ZIP.
3. If the JSON/CLI contract changed incompatibly, bump `SchemaVersion` in
   `Report.ps1` and update [contract.md](contract.md) — that's a **major** bump.
4. Run the fixture generator, full Pester suite, operator-entry-point smoke test,
   relative-link check, and documentation consistency checks.
5. Commit, ensure CI is green, create the annotated tag and GitHub release, and
   attach the operator-ready `media-transfer-scan-tool-X.Y.Z.zip` asset.

## Versioning
The contract has been frozen since package v0.9.0 even though the package remains
on the 0.x line pending isolated-host validation. See [contract.md](contract.md).
Incompatible changes to the JSON schema, CLI flags, or exit codes require a
major package-version and schema-version bump.
