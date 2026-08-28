# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). The `0.x` series predates the
frozen public contract; **1.0.0 marks the full-coverage milestone** (see [PLAN.md](PLAN.md) §5).

## [Unreleased]

## [0.12.0] - 2026-08-28

### Security
- **NuGet identity spoofing via a nested decoy `<metadata>` block** — a
  `.nupkg` with exactly one root `.nuspec` (so it passes the existing
  multi-root-`.nuspec` ambiguity check) could still hide its real identity: the
  previous document-wide `//` XPath search matched the *first* `<metadata>`
  found anywhere in the file, in document order, so a decoy nested inside an
  unrelated wrapper element ahead of the real `<package><metadata>` was
  resolved instead — the package's real, possibly-vulnerable identity was
  never queried against OSV. `Get-NuGetDep` (`src/analyzers/OsvScan.ps1`) now
  reads only `<package>`'s direct-child `<metadata>`, and rejects (rather than
  guesses at) an unexpected shape — more than one `<metadata>`, or more than
  one `<id>`/`<version>` within it — the same fail-closed posture already
  applied to the multi-nuspec-file case. PoC verified before the fix, and a
  regression fixture (`nuget/nested_decoy`) added.
- **Unbounded per-advisory detail-fetch loop** — `Get-OsvDependencyFindings`
  (`src/lib/Osv.ps1`) bounds retries on the `POST /v1/querybatch` chunk loop
  after repeated consecutive failures, but the separate sequential
  `GET /v1/vulns/{id}` detail fetch (one call per distinct advisory) had no
  such bound. A manifest resolving to many distinct advisories during a
  detail-endpoint outage could hold an online scan for
  `uniqueIds.Count * TimeoutSec`. Now bounded by the same
  `-MaxConsecutiveFailures` parameter; a vulnerability already confirmed by
  querybatch still produces a finding via the existing "detail unavailable"
  fallback when the fetch stops early — none are silently dropped — and the
  skipped advisories are reported as an explicit coverage-gap finding, grouped
  by manifest. The stopped-early message also now reads "were skipped without
  an attempt (not just failed)" rather than the more ambiguous "were not
  fetched", to distinguish never-attempted advisories from attempted-and-failed
  ones (only the former count toward the reported number).

Both findings were caught by independent review of #33/#32 after it shipped
in 0.11.0; neither had a live exploit reported. Regression coverage added:
`nuget/nested_decoy` (plus direct fixtures for the new fail-closed shape
checks — two root `<metadata>` elements, a duplicate `<id>`, a missing
`<version>`) and a mocked failure→success→failure detail-fetch test.

## [0.11.0] - 2026-08-27

### Added
- **OSV.dev dependency-vulnerability audit — PyPI, npm, NuGet** ([#32](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/32)).
  New **`OsvScan`** analyzer (core, default-on — this tool always has network
  access to the connected/staging host, so the audit runs by default rather
  than opt-in): batch-queries `POST /v1/querybatch` and resolves every
  distinct advisory to full detail via `GET /v1/vulns/{id}` (severity,
  summary, fixed versions), scored with a real CVSS v3.1 base-score
  calculator plus a `database_specific.severity`/keyword fallback — not a
  flat severity for every hit.
  - **New `python-requirements` unit type** for a loose `requirements.txt`
    (its own type, not `python` — the Python-source analyzers must never
    parse it as source). Exact `==` pins are PEP 503-normalized and queried;
    a range, bare name, compound specifier, or VCS/URL requirement is
    reported as an explicit `OSV-PYPI-UNPINNED` finding rather than silently
    skipped.
  - **New `nuget` unit type** for `.nupkg` (routed through the existing
    hardened ZIP extraction path — zip-slip/bomb guards apply); the package's
    own id/version is read from its embedded `.nuspec` (namespace-agnostic —
    the schema URI varies by NuGet client version) and checked against OSV,
    since the artifact itself *is* the pinned dependency.
  - **npm** (`package-lock.json`, schema v1/v2/v3) moves from `NpmScan`'s old
    id-list-only layer into `OsvScan`, gaining the same full-detail scoring.
  - Shared query/scoring/PEP-503 logic lives in `src/lib/Osv.ps1` so every
    ecosystem — and any future one — reports the same way.
  - Adding two `UnitType` values is non-breaking under
    [docs/contract.md](docs/contract.md) §1.

### Fixed
- **`Finding.File` now carries the audited unit's path everywhere, not a
  `"dependency: name version"` descriptor.** `docs/contract.md` §1 defines
  `File` as a relative path; `PipAudit`'s CVE findings put a dependency label
  there instead. The dependency identity moved into `Issue`
  (`"Dependency 'name version': CVE-...: ..."`), matching the convention
  `OsvScan` uses. This also restores traceability when `Requires-Dist` is read
  from more than one wheel in a single scan.

## [0.10.0] - 2026-08-21

### Added
- **VB-family support — standalone VBA and VBScript** ([#25](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/25)).
  Embedded Office macros were already covered by `OleVbaScan`, but a VB module or
  script sitting loose in a submission classified as `unsupported` and was never
  analyzed: a `.bas` containing `Auto_Open` + `URLDownloadToFile` + `Shell` produced
  a SHA-256 line and nothing else. The same was true of `.vbs`/`.hta`, which matter
  more — a `.vbs` executes on double-click, an exported module does not.
  - **New `vba` unit type** covering `.bas .cls .frm .vba` and `.vbs .vbe .wsf .hta`.
    Adding a `UnitType` value is explicitly non-breaking under
    [docs/contract.md](docs/contract.md) §1.
  - **New `VbaRules` analyzer** (core, default-on): auto-exec entry points, shell and
    process launch, download primitives, native `Declare … Lib` imports, shellcode
    APIs (`VirtualAlloc`/`RtlMoveMemory`, CRITICAL), registry persistence, hidden or
    encoded PowerShell, and obfuscation (`Chr()` chains, `StrReverse`, `CallByName`).
    Combinations that only make sense in a dropper — download+execute, auto-exec+payload
    — escalate to CRITICAL, following the `PythonRules` precedent.
  - **Pure PowerShell**: no Python helper and no pip package, so unlike the Office path
    (which degrades to `OFFICE-OLEVBA-UNAVAIL` without oletools) this works air-gapped
    with zero provisioning.
  - **Disguise detection extended to VB**: a VBA module saved as `notes.txt` is now
    detected by content signature and raises `MTS-DISGUISE-002`, then gets the full
    rule pass. The signatures are deliberately VB-exclusive (`Sub`, never `Function`)
    so they cannot steal units from the JavaScript, batch, or PowerShell paths.
  - `.vbe` (Script Encoder output) reports `VBA-ENCODED-SOURCE` rather than a clean
    result — it is obfuscated by design and cannot be read statically.
  - Embedded Office macros are unchanged and stay with `OleVbaScan`. Running these
    rules over module source extracted from a container is a follow-up.

### Changed
- **A blocked external tool is now reported, not silent: `MTS-TOOL-BLOCKED` (HIGH).**
  On a host enforcing Application Control / Smart App Control, Windows refuses to
  start the unsigned pip console shims the scanner provisions (`bandit.exe`,
  `detect-secrets.exe`, `shellcheck.exe`, …). Previously `Invoke-BoundedProcess`
  threw, each analyzer caught it into a **LOW** `MTS-*-ERR`, and the practical
  result was a report that read as "this tool found nothing" when the tool never
  ran. `Invoke-BoundedProcess` now returns `Started`/`StartError` instead of
  throwing, and analyzers emit a HIGH finding saying the unit was **NOT** analyzed
  — the same treatment `MTS-ANALYZER-TIMEOUT` already got, for the same reason.
  `PythonRules` is unchanged: it already degrades to its regex fallback.
  See [docs/test-environment.md](docs/test-environment.md) for how to detect and
  clear the policy.
- **No silent coverage gaps: `MTS-NO-ANALYZER` (INFO).** A unit that no enabled
  analyzer claims — `unsupported` files, and `batch` units, which have never had an
  analyzer — now carries an explicit INFO finding saying it was hashed and listed but
  not inspected. Previously such a file produced only a hash line, which reads in a
  report as "reviewed, clean" when it means "never looked at."
  **Consumer impact:** `TotalFindings` rises on submissions containing ordinary
  unanalyzed files. Severity is INFO, so overall risk and exit codes are unaffected.
  **Known limitation:** this answers "did any analyzer claim this *unit*", not "was
  the content *inside* an archive inspected". A generic archive's contents are only
  inspected for npm and model content, and that gap is not yet reported — inferring
  it from analyzer descriptors was attempted and reverted, because descriptors cannot
  distinguish an analyzer that declined from one that inspected, which produced false
  warnings on every clean wheel and notebook. Tracked separately.
- `docs/contract.md` now documents `batch` in the `Type` enum. It was always
  producible from `.bat`/`.cmd`; the omission was a documentation bug, not a change.

### Fixed
- **`.hta`/`.wsf` were wrongly assumed to be VB**, caught in review of #28 and fixed
  before release. They are language-neutral wrappers that host JScript as readily as
  VBScript, so routing them to `VbaRules` by extension meant a JScript dropper
  (`new ActiveXObject("WScript.Shell").Run(...)`) matched no VB rule, reported clean,
  *and* suppressed `MTS-NO-ANALYZER` because a VB analyzer had claimed the unit —
  silent and falsely reassuring. Such a wrapper now reports `VBA-NON-VB-SCRIPT`
  (MEDIUM) saying the embedded script was not inspected. Genuine VBScript wrappers
  are unaffected.
- **Flaky deep-tier tests.** `BanditSecrets` and `Notebook` tests failed
  intermittently — a different one each run, each passing in isolation. The cause
  was not a race or PyPI: Smart App Control was blocking `bandit.exe` per-binary by
  reputation, so the analyzer produced no findings and the assertion failed with no
  diagnostic. `tests/TestTools.ps1` now probes whether each deep-tier binary can
  actually be executed and skips loudly with the reason when it cannot, so a host
  policy is never mistaken for a code regression. `MTS_REQUIRE_DEEP_TOOLS=1` makes
  an un-runnable tool a hard failure for CI and release validation.
- **UNC scan roots no longer crash the scan** ([#27](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/27)).
  `Resolve-Path ... .Path` returns a provider-qualified string for a network path
  (`Microsoft.PowerShell.Core\FileSystem::\\server\share\...`). That string is longer
  than the plain `FullName` of the files under it, so the length-based `Substring`
  that derived each unit's relative path threw
  `startIndex cannot be larger than length of string` and the scan aborted with exit
  code 2. Both resolution sites (`Invoke-MediaTransferScan.ps1`, `Invoke-Scan` in
  `lib/Engine.ps1`) now use `.ProviderPath`, and `New-Unit` computes the relative path
  with `[System.IO.Path]::GetRelativePath` instead of string-length arithmetic.
  `bundle/build-bundle.ps1` had the same `.Path` hazard for a UNC output dir and was
  fixed alongside. Covered by `tests/PathResolution.Tests.ps1`: UNC cases run against
  the local admin share and announce themselves loudly when it is unreachable
  (`MTS_REQUIRE_UNC_TESTS=1` turns that skip into a failure), plus an
  environment-independent source guard that fails if `Resolve-Path ... .Path` is
  reintroduced anywhere under `src/` or `bundle/`.

## [0.9.0] - 2026-06-06

### Added
- **PythonRules — curated, high-signal Python analysis (core, default-on).** The
  Python analogue of the PowerShell/shell risky-pattern layers: it reports ONLY
  attacker-grade indicators relevant to ingress — `eval`/`exec`/`compile`,
  dynamic import, `os.system`/`os.popen`, `subprocess(shell=True)`, `pickle`/
  `marshal`/unsafe-`yaml` loads, network fetch (`urllib`/`requests`/`socket`),
  base64/zlib decode, `ctypes` native loads — plus file-level **combination**
  escalations (download-and-run, decode-then-exec, reverse-shell, ctypes
  shellcode). It deliberately omits the broad code-quality findings of the
  deep-tier Bandit analyzer: the "middle tier" between blind and noisy.
  - Backed by `src/helpers/scan_python.py` (stdlib `ast`, no pip package): real
    call sites, not substrings — no false hits on trigger words in comments or
    strings, verified by fixtures. Runs under the bundled venv or system Python,
    so it works **offline / air-gapped**.
  - Pure-PowerShell regex fallback when no Python interpreter is present (marked
    LOW/`PY-RULES-DEGRADED`) so a scan is never fully blind.
- **Frozen the public contract** ahead of the 1.0.0 release: JSON report
  `schemaVersion` set to `1.0.0`; [docs/contract.md](docs/contract.md) documents the
  stable JSON schema, CLI surface, and exit codes, and what a breaking change is.
- **Operator guide** ([docs/operator-guide.md](docs/operator-guide.md)) — running the
  bundle (`Scan.cmd`), reading the report, severities, exit codes.
- **Maintainer guide** ([docs/maintainer-guide.md](docs/maintainer-guide.md)) — dev
  setup, tests, CI, bundle build, adding analyzers, release steps.
- **Defender/AMSI self-check** (`tools/verify-amsi.ps1`): on a Windows + Defender
  host, snapshots the threat-detection history, loads the full engine in a fresh
  `pwsh`, and fails if any new detection appears — guards against an offensive
  token leaking back into shipped source. Documented in the maintainer guide.
- *(Remaining for the 1.0.0 tag: operator validation on real untrusted transfers
  on the isolated host.)*

### Fixed
- **AMSI/EDR false positive on the scanner's own code.** The PowerShell analyzer's
  detection signatures (AMSI-tamper, Defender-preference, downloader,
  encoded-command) and the classifier's PowerShell content-signatures previously
  sat as contiguous literal strings in the engine source. Microsoft Defender's
  AMSI inspection scanned that source as `pwsh` loaded it and fired **“Possible
  AMSI tampering” (DefenseEvasion, High)** — a false positive triggered by our own
  patterns, which would also let on-disk file AV quarantine the analyzer. These
  tokens are now **assembled from fragments at runtime**, so the contiguous
  strings never appear in any shipped file (detection behavior is unchanged;
  verified by the full suite). See `docs/test-environment.md` → *AV / EDR on the
  review host* for the operator-side AV guidance this surfaced.

### Changed
- Bootstrapper: when a vendored venv is present it now passes `-VenvDir` but no
  longer force-sets `-Mode offline`. An online host running the bundle reuses the
  vendored tools *and* keeps live CVE coverage (pip-audit / OSV); air-gapped use
  selects `-Mode offline` explicitly.

### Security / CI
- Added a `security` workflow: PSScriptAnalyzer over `src/` (fails on Error
  severity; tuned via `PSScriptAnalyzerSettings.psd1`), gitleaks secret scanning,
  and CodeQL static analysis of the Python helpers. Weekly schedule + on push/PR.
- Added Dependabot for the `github-actions` ecosystem (keeps action versions
  current — removes the Node-runtime-deprecation treadmill).
- Cleaned the engine to a clean PSScriptAnalyzer run (removed dead variables,
  made best-effort `catch` blocks explicit).

## [0.8.0] - 2026-05-30

### Added
- **Archive hardening (v0.8):** ZIP-family archives are inspected BEFORE extraction
  and hard-blocked (never written to disk) on a hazard:
  - **Zip-slip / path traversal** (`..`, absolute, drive-rooted) → HARD block.
  - **Decompression bomb** → HARD block: per-entry ratio (>100× over a 10 MB floor),
    512 MB aggregate-uncompressed cap, and a 50k entry-count cap.
  - **Symlink entries** (unix `S_IFLNK` in external attributes) → flagged (MEDIUM).
  - **Nested archives** → flagged (LOW; scanned at top level only).
  - tar (`.tgz`/`.tar.gz`): a `tar -tzf` listing is checked for traversal before
    extraction; the Python tarfile fallback uses the secure PEP 706 `data` filter.

### Changed
- Path-traversal handling moved from advisory to a true pre-extraction block.

## [0.7.0] - 2026-05-30

### Added
- **Model / pickle analysis (v0.7):** `PickleOpcodeScan` (core) + `helpers/scan_pickle.py`
  on `model` units (`.pkl .pickle .pt .pth .bin .joblib .h5 .pb .onnx .safetensors
  .gguf .npy .npz`) and model files inside extracted archives.
  - **Pickle opcode triage** via `pickletools.genops` — walks the opcode stream
    and is NEVER unpickled (unpickling executes code). Flags `REDUCE` (the
    code-exec primitive, CRITICAL), `GLOBAL`/`STACK_GLOBAL` arbitrary imports, and
    dangerous modules (`os`/`nt`/`subprocess`/`builtins`/...) as CRITICAL.
  - **Safe-format recognition:** safetensors and GGUF cleared as safe-by-design.
  - **Embedded pickles:** PyTorch `.pt`/`.pth` ZIP containers are opened and their
    `data.pkl` scanned; `.pt` is routed to `model` (not generic archive).
- Classifier: `model` added to the ZIP-container types (PyTorch `.pt` is a ZIP).

## [0.6.0] - 2026-05-30

### Added
- **npm analysis (v0.6):** `NpmScan` (core, dependency-free core) on `npm` units
  (loose `package.json` / `.js` / `.ts`) and extracted `.tgz` tarballs:
  1. **package.json lifecycle scripts** — `preinstall`/`install`/`postinstall`
     (run on `npm install`, the #1 npm supply-chain vector) flagged HIGH; their
     command strings inspected for risky tooling; `prepare`/`prepublish` MEDIUM;
     `bin` shims noted.
  2. **JavaScript risky patterns** — `child_process`/`exec`/`spawn`, `eval()`,
     `Function()` constructor, long hex-escape obfuscation.
  3. **OSV dependency audit** (online, no tool install — OSV.dev REST API): when a
     `package-lock.json` with exact versions is present, batch-queries OSV for
     known vulnerabilities. Offline / no lockfile → coverage-gap note.
- Classifier: `package.json` / `package-lock.json` routed to `npm` by filename;
  `.ts` added to npm extensions.

## [0.5.0] - 2026-05-30

### Added
- **PowerShell analysis (v0.5):** three-layer static analysis on `.ps1`/`.psm1`/`.psd1`
  units and PowerShell content detected via the classifier:
  1. **PSScriptAnalyzer** (PS module, installed on demand online / vendored offline):
     structural + security rules.
  2. **Custom risky-pattern rules** (always run): `IEX`/`Invoke-Expression`,
     `DownloadString`/`DownloadFile`, `-EncodedCommand`, `FromBase64String`,
     `-WindowStyle Hidden`, AMSI tampering, Defender preference tampering,
     `-ExecutionPolicy Bypass`.
  3. **Authenticode signature status** — `HashMismatch` (tampered signed file) is
     HIGH; valid/unsigned recorded as INFO.
- Provisioning: PS-module install-on-demand (online) via `Resolve-PsModuleTool`;
  the Python venv is now created **only when a pip-based analyzer is enabled**, so
  PowerShell-only scans no longer require Python.

### Changed
- Release titles are now the bare version (no descriptive suffix).

## [0.4.0] - 2026-05-29

Shell script analysis — ShellCheck + risky-pattern rules.

### Added
- **Shell script analysis (v0.4):** two-layer analysis on `.sh`/`.bash`/`.zsh`/`.ksh`
  units and shell content detected via the classifier (v0.2 disguised scripts):
  1. **ShellCheck** (via `shellcheck-py` pip package, which bundles the binary):
     full structural static analysis — quoting bugs, undefined variables, command
     injection, deprecated constructs (SC-coded findings).
  2. **Custom risky-pattern rules** (pure PowerShell, always runs): catches
     `curl|bash`, `base64 -d|bash`, `eval` with expansion, `chmod 777`, and
     hardcoded IPv4 addresses. These are intentionally not ShellCheck errors
     (syntactically valid shell) but operationally dangerous in a media-transfer
     context.

## [0.3.0] - 2026-05-29

Document analysis — Office + PDF triage.

### Added
- **Document analysis (v0.3) — Office + PDF:**
  - **PdfTriage** (core, pure PowerShell, no dependency): static keyword triage of
    PDFs — `/JS` `/JavaScript`, `/OpenAction` `/AA` `/Launch`, `/EmbeddedFile`,
    `/URI`, `/RichMedia`, and `/Encrypt` — with PDF name hex-escape de-obfuscation
    (`/#4A...`). Reading bytes only; never renders the PDF or runs JavaScript.
    Deliberately dependency-free to avoid a heavy PDF-parser attack surface.
  - **OleVbaScan** (core) + `helpers/scan_office.py`: Office triage via stdlib zip
    inspection (VBA `vbaProject.bin` presence, DDE/DDEAUTO fields, remote-template
    injection) plus deep VBA analysis (auto-exec / suspicious keywords) through
    `oletools` when available. Documents are parsed structurally — never opened in
    Office, never executed.
  - New finding categories `macro` / `active-content`; new analyzer test corpus
    (PDF + OOXML fixtures, generated by `build_fixtures.py`).

## [0.2.0] - 2026-05-29

Disguised-script detection — the first new file-type capability beyond Python parity.

### Added
- **Disguised-script detection (v0.2):** content-signature classification (PLAN §3.7
  signal #3) scores a file's text against PowerShell / Python / shell / batch
  signatures, catching a script hidden in an innocent extension (e.g. `.txt`,
  `.log`, `.dat`) with **no shebang** — the classic media-transfer evasion. The
  router uses the detected type (content over extension), emits a `disguised-file`
  finding (`MTS-DISGUISE-001/002`, severity scaled by how innocent the extension
  is), and dispatches the unit to the matching analyzer as those analyzers land.
  Includes a text-likeness gate (binaries skipped) and a ≥2-distinct-signature
  threshold so ordinary prose is not flagged. `.bat`/`.cmd` recognized as `batch`.

## [0.1.0] - 2026-05-29

First tagged release. Engine + full **Python** analyzer set + offline deployment.
Parity with `scan-python-packages` v1.6.1 on the new file-type-agnostic engine.

### Added
- Initial repository scaffold: engine pipeline (discover → classify → extract/project →
  dispatch → render), analyzer registry contract, normalized finding schema, and
  three-renderer report (canonical JSON + HTML with CSP + slim TXT).
- Provisioning layer: Python discovery, shared scanner venv, PEP 440 version checks,
  and a `Resolve-Tool` contract (pip / exe / PowerShell module) with offline fallback.
- Archive extraction (.whl/.egg/.zip/.tar.gz/.tgz) with path-traversal and corrupt-archive
  guards and ZIP-family disambiguation.
- Python analyzer set (parity with scan-python-packages v1.6.1, on the new engine):
  - **FileHash** — SHA-256 audit manifest (core)
  - **PipAudit** — CVE dependency audit from `Requires-Dist` + CycloneDX SBOM (core)
  - **BinaryInspection** — PE/ELF native triage via pefile/pyelftools (core)
  - **Bandit** — risky Python code patterns (deep tier, opt-in)
  - **DetectSecrets** — hardcoded credential detection (deep tier, opt-in)
  - **Jupyter notebook projection** — code cells projected to static .py; saved
    outputs/attachments/malformed surfaced as findings (notebook is never executed)
- Analyzer tiers (`core` default-on / `deep` opt-in) with `-Profile core|full` and
  `-EnableAnalyzers`/`-DisableAnalyzers`; disabled analyzers surfaced in every report.
- **Deployment:** 5.1-safe `bootstrap.ps1` + `Scan.cmd` operator entry point that
  resolves PowerShell 7.4+ (bundled-authoritative → PATH → fail) and re-launches the
  engine; `-VenvDir` engine override; `bundle/build-bundle.ps1` offline-bundle builder
  (portable pwsh 7.4 LTS + scanner venv + manifest).
- Documented exit codes (0 clean / 10 findings / 2 error / 3 bad input / 4 no runtime).
- Test-environment runbook for isolated real-untrusted scanning ([docs/test-environment.md](docs/test-environment.md)).
- Project plan and feature roadmap ([PLAN.md](PLAN.md)).
- Pester suite (53 tests) + GitHub Actions CI on PowerShell 7.
