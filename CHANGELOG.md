# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). The `0.x` series predates the
frozen public contract; **1.0.0 marks the full-coverage milestone** (see [PLAN.md](PLAN.md) §5).

## [Unreleased]

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
