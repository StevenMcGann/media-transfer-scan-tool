# media-transfer-scan-tool — Plan & Feature List

**Status:** planning (pre-v0.1.0). **Versioning:** ships as **0.x** while coverage and the JSON/CLI contract are still expanding; **1.0.0 is reserved for the full-coverage milestone** — all planned ingress types working, contract frozen, and validated on real untrusted transfers (see §5).
**Lineage:** clean-room successor to [`scan-python-packages`](https://github.com/StevenMcGann/scan-python-packages) v1.6.1
**Runtime:** PowerShell 7.4+ (7-only), Python 3.x helpers, external analyzer binaries/modules
**Host:** Windows operator host; PS 7 self-hosted from the offline bundle (no system install required)
**Core invariant:** *all analysis is static — no submitted code is ever executed, imported, unpickled, or installed.*

---

## 1. Purpose

A single operator-driven tool for **media-transfer review**: a reviewer points it at a submission folder of untrusted artifacts and gets a durable, per-submission report before anything is admitted to a trusted environment.

`scan-python-packages` proved the workflow for Python. This project generalizes that same workflow — *operator points at a folder, gets a report* — into a **superset that fully scans Python AND adds npm packages, PowerShell, bash/shell, disguised scripts, and ML/model files.** **Python is not dropped or delegated to the old tool** — the new engine **ports every Python analyzer** (Bandit, detect-secrets, pip-audit + SBOM, PE/ELF binary triage, notebook projection); Python is the v0.1.0 foundation (see §5). It also reuses the hard-won lifecycle, fixture/test, and reporting infrastructure.

This is a **fresh codebase (v0.1.0 onward)**, not a rename-in-place. We carry forward proven patterns and rebuild the discovery/routing/reporting layer to be file-type-agnostic from day one.

**Relationship to `scan-python-packages`:** it **remains its own active, independently-maintained tool — not archived or deprecated.** The two **overlap on Python by design** — `media-transfer-scan-tool` is the broad multi-type scanner, `scan-python-packages` stays as the focused Python-only tool. The repos cross-link.

### Decisions locked in
- **First new analyzer after Python parity:** disguised-script detection (content sniffing). It is the highest-value detection *and* its classifier becomes the routing backbone every other analyzer depends on.
- **Operator host:** mixed/both. The engine must run **fully offline** from a pre-built bundle, with an **online convenience mode** (`-AutoInstall` + live advisory feeds) for connected dev/operator hosts.
- **Runtime: PowerShell 7.4+ (7-only).** The clean rewrite is the moment to leave Windows PowerShell 5.1 behind. PS 7 *removes* most of the robustness tax that dominates the 5.1 codebase rather than carrying it forward (see §6), gives correct JSON serialization for the report/SBOM deliverables, and unlocks native parallelism for the slow per-unit scans. The deployment cost — PS 7 isn't in-box on Windows — is neutralized by the bundle: we ship a **portable `pwsh`** in `tools\` and a thin 5.1-safe bootstrapper re-launches the engine under it, so the operator never installs anything (see §3.6). We do **not** support 5.1 and 7 simultaneously; dual-targeting would forfeit every PS 7 benefit while doubling compat testing. *Only revisit if a real operator pattern requires running the bare script on a locked-down host where a portable `pwsh` cannot be dropped.*

---

## 2. What this is / is not

**Is:**
- A static-analysis orchestrator that classifies every file in a submission and dispatches it to the right analyzer set.
- An operator-host tool (run it, keep the report with the submission) and a developer-host project (regenerate fixtures, run Pester, smoke, CI before a release).

**Is not:**
- A sandbox, detonation chamber, runtime monitor, or AV engine.
- It does not execute, import, install, or deserialize submitted content. Pickles are **opcode-scanned, never loaded**. Scripts are read, never run. Dependencies are audited from declared metadata, never installed.

---

## 3. Architecture

### 3.1 The shift from v1.x
`scan-python-packages` hardcoded discovery (`Get-PackageUnits` → `archive|pyfile|notebook`) and dispatch (a fixed sequence of `Invoke-*Scan` calls in the main loop). The new engine replaces both with a **classifier + analyzer registry**.

```
                       ┌─────────────────────────────────────────────┐
  submission folder ──▶│ 1. Discover  (walk tree, collect candidates) │
                       └─────────────────────────────────────────────┘
                                          │
                       ┌──────────────────▼──────────────────────────┐
                       │ 2. Classify  (extension + magic-byte + content│
                       │    sniff → UnitType; flag extension/content   │
                       │    mismatches → "disguised" finding)          │
                       └──────────────────┬──────────────────────────┘
                                          │  one Unit per artifact
                       ┌──────────────────▼──────────────────────────┐
                       │ 3. Dispatch  (registry maps UnitType → set of │
                       │    analyzers; extract archives to staging)    │
                       └──────────────────┬──────────────────────────┘
                                          │  Finding[] (normalized schema)
                       ┌──────────────────▼──────────────────────────┐
                       │ 4. Aggregate + Render  (HTML human report +   │
                       │    canonical JSON + slim TXT + SBOM + manifest)│
                       └─────────────────────────────────────────────┘
```

### 3.2 Analyzer registry (the central new abstraction)
Every analyzer is a self-describing module so the engine never hardcodes "run Bandit then detect-secrets." Each file in `src/analyzers/` returns one **descriptor** (a hashtable); the engine imports them all at startup into an ordered registry. Adding a file type = register classifier signatures + drop in analyzer descriptors. The main loop never changes.

**Descriptor contract** — what an analyzer declares:

| Field | Type | Purpose |
|---|---|---|
| `Name` | string (unique) | e.g. `Bandit`, `PSScriptAnalyzer`, `PickleOpcodeScan`. Recorded on every finding's `Tool`. |
| `Version` | string | Analyzer-module version, surfaced in report provenance (separate from the underlying tool version). |
| `UnitTypes` | string[] | Types it handles: `python`,`npm`,`powershell`,`shell`,`batch`,`vba`,`office`,`pdf`,`model`,`disguised`,`archive`, or `any`. |
| `RequiredTools` | descriptor[] | Each: `@{ Kind = 'pwsh'\|'pip'\|'psmodule'\|'exe'; Id; MinVersion; BundlePath }`. Resolved by `Resolve-Tool` (§3.4) before `Invoke`. |
| `Offline` | bool | Whether it runs air-gapped. Advisory-DB analyzers (pip-audit/npm audit) set `$false` unless a vendored DB is present. |
| `Tier` | string | `core` (high-signal, on by default) or `deep` (broader, opt-in — currently **Bandit** and **detect-secrets**). See enablement below. |
| `DefaultEnabled` | bool | Whether it runs without being explicitly requested. `core` → `$true`; `deep` → `$false`. |
| `Invoke` | scriptblock | `param($Unit, $Context)` → returns `Finding[]` (possibly empty). The only behavioral entry point. |

**`$Context`** — what the engine *guarantees* each analyzer (so analyzers never re-resolve environment):

| Field | Purpose |
|---|---|
| `Tools` | Resolved handles: venv `python`/`Scripts` dir, `ShellCheck.exe`, `node`/`npm`, PSScriptAnalyzer module — already provisioned, paths absolute. |
| `Mode` | `offline` \| `online`. |
| `WorkDir` | Per-unit scratch dir under staging (writable, auto-cleaned). |
| `ReportsDir` | Where side artifacts (SBOMs) go, with engine-supplied naming helpers. |
| `Log` | The shared `Write-Log` sink. |
| `TimeoutSeconds` | Per-analyzer budget; the engine cancels overruns and records an `analyzer-error` finding. |
| `AdvisoryDbDate` | Snapshot date of vendored CVE/OSV data (for provenance in findings). |

**`$Unit`** — the classified artifact: `Type`, `Name`, `Path`, `StagingPath` (extraction root if an archive, else null), and `Files` (enumerated members for extracted units).

**Invoke rules (the analyzer's obligations):**
1. **Static only.** Never execute, import, install, or deserialize submitted content. A shared `Assert-StaticOnly` guard wraps tool invocation; analyzers shell out to *scanners*, never to an interpreter pointed at the submission.
2. **Return, don't throw.** Emit `Finding[]` (empty is valid). Tool failures are caught internally and returned as a `parser`/`analyzer-error` Category finding — a broken analyzer degrades coverage, it never aborts the run.
3. **Stateless & idempotent.** No global mutation; safe to run concurrently. (Enables §6 parallelism.)
4. **Side artifacts go to `$Context.ReportsDir`** via the provided naming helper (keeps SBOM/etc. naming consistent and test-assertable).

**Engine selection & degradation (generic, type-agnostic):**
- For each unit, select every descriptor whose `UnitTypes` matches the unit's `Type` (or `any`) **and that is enabled for this run** (see enablement).
- Resolve each descriptor's `RequiredTools`. If a required tool is **unavailable** (e.g. offline + not bundled), the engine **skips that analyzer and emits an explicit coverage-gap finding** (`Category=parser`, `INFO`) — the report always shows *which* analysis was skipped and why; never a silent gap.
- Run the surviving analyzers (parallel, throttled — §6), aggregate their findings into the unit result.

**Analyzer enablement & profiles (tiers).** Not every analyzer should run on every ingress. The broad, false-positive-prone static checks are noise for routine media-transfer review, so they are **opt-in**, while the targeted, high-signal detections are on by default:
- **`core` (default-on):** pip-audit/npm-audit CVE checks, binary/PE-ELF inspection, pickle opcode scan, npm install-script inspection, disguised-file detection, archive-hazard guards, signature checks, notebook parser. These are precise and low-noise.
- **`deep` (opt-in, default-off):** **Bandit** (broad risky-code patterns) and **detect-secrets** (entropy-based credential matches). Useful for deeper review, but historically *just noise* on routine ingress.
- **Selection controls (CLI):** `-Profile core|full` (full = core + deep), plus fine-grained `-EnableAnalyzers <names>` / `-DisableAnalyzers <names>` overrides. Default profile is **`core`**.
- **Surfaced, never silent.** Because a `deep` analyzer being off means "secrets/risky-code were *not* checked," the report header lists which analyzers ran vs. were disabled — so a reviewer is never misled into thinking a submission was secret-scanned when it wasn't (consistent with the no-silent-gap principle above).

This is the seam every future file type plugs into: §4's matrix is just "which descriptors declare which `UnitTypes`," and which `Tier` they sit in.

### 3.3 Normalized finding schema
Generalize the v1.x finding (`Tool, Severity, Confidence, File, Line, Issue, TestID`) by adding type/grouping/guidance fields:

```
Finding {
  Tool          # analyzer name
  Category       # secrets | risky-code | vuln-dependency | native-binary |
                 #   deserialization | macro | active-content | disguised-file |
                 #   archive-hazard | parser
  Severity       # CRITICAL | HIGH | MEDIUM | LOW | INFO
  Confidence     # HIGH | MEDIUM | LOW
  UnitType       # python | npm | powershell | shell | office | pdf | model | disguised | archive
  File           # path relative to submission root (or unit-internal path)
  Line           # nullable
  Issue          # human-readable description
  TestID         # stable rule id for dedupe/triage
  Recommendation # NEW: what the reviewer should do about it
}
```
`Category` + `UnitType` let the report group findings meaningfully across mixed submissions and let tests assert on stable dimensions.

### 3.4 Tool provisioning layer (generalized from the venv bootstrap)
v1.x only had to install pip packages into one venv. Now provisioning spans four kinds of tools:
- **The PowerShell 7 runtime itself** (portable `pwsh`) → vendored in the bundle's `tools\pwsh\`; see §3.6.
- **pip packages** (bandit, pip-audit, detect-secrets, pefile, pyelftools, **oletools, pdfid/pdf-parser**, + JS/pickle helpers) → scanner venv, as today.
- **PowerShell modules** (PSScriptAnalyzer) → user-scope module path.
- **External binaries** (ShellCheck, Node/npm) → resolved from PATH or from the offline bundle's `tools\` directory.

The layer exposes one `Resolve-Tool` contract that, in **online mode**, installs/upgrades on demand (`-AutoInstall`), and in **offline mode**, binds to the pre-built bundle and fails loudly (with a clear "this analyzer is unavailable offline; finding coverage reduced" log line) rather than silently skipping. This mirrors the existing "binary inspection helper not found → skip + log" graceful-degradation behavior, made first-class.

### 3.5 Offline-capable execution + online convenience mode
- **Offline bundle** (built on a connected dev host, shipped to operator): vendored scanner venv, PSScriptAnalyzer module, ShellCheck + Node binaries, and **cached advisory databases** (PyPI/OSV for pip-audit, npm advisory/OSV for npm) with a recorded snapshot date surfaced in the report.
- **Online mode:** keeps the current `-AutoInstall` + live `pip-audit`/`npm audit` behavior.
- The report header always states **mode** and **advisory-DB date** so a reviewer knows how fresh the CVE data was.

### 3.6 Runtime: PowerShell 7, self-hosted from the bundle
The engine targets **PowerShell 7.4+ only** and is written PS-7-idiomatic (no 5.1 compat subset). Because PS 7 is not in-box on Windows, the bundle makes it a non-event for the operator:
- A **portable `pwsh`** — the **Windows x64 self-contained** `.zip` build (bundles its own .NET runtime, no MSI/admin, no host .NET dependency) — is vendored at `tools\pwsh\`. It is version-stamped and refreshed alongside the advisory DBs (see cadence note below); it is a .NET app with its own CVE surface, so it is treated as a maintained dependency, not a one-time drop.
- **The bundled `pwsh` is authoritative — never a prerequisite.** Bundling the runtime is what guarantees the engine runs the way we tested and shipped it: the exact PS/.NET version our Pester/smoke suite passed on, immune to whatever (older, preview, modified, or PATH-hijacked) `pwsh` happens to be on a host that reviews untrusted material.
- A thin **5.1-safe bootstrapper** (`Invoke-MediaTransferScan.cmd` / stub `.ps1`) is the operator entry point. It resolves the runtime in this order, then re-launches the engine under it (with **`-NoProfile`**, so no host `$PROFILE`/module shadowing leaks into the run) and forwards all arguments:
  1. **Bundled present → always use `tools\pwsh\pwsh.exe`** (pinned, hash-verifiable), even if the host also has PS 7. *Determinism + integrity outrank saving the ~150 MB we already ship.*
  2. **No bundle (dev/online checkout) →** use host PATH `pwsh` ≥ 7.4 (PS 7.4+ is an expected developer dependency in a source tree; we never vendor `pwsh` into the repo).
  3. **Neither →** fail loudly with a clear message — never a silent downgrade to 5.1.
- The operator runs one thing and never reasons about which PowerShell is installed.
- **Scope note:** bundling pins the *runtime layer* (PowerShell + .NET). Full "runs as expected" determinism also depends on pinning the analyzers the engine shells out to — vendored scanner venv (Bandit/pip-audit/detect-secrets), ShellCheck, Node/npm, PSScriptAnalyzer — which the bundle already does (§3.4/§3.5). The PS 7 decision closes the runtime-layer gap; the bundle strategy closes the rest.
- **CI** runs the suite on PS 7 (Windows and, where analyzers allow, Linux runners), removing the 5.1 test matrix entirely.

**Refresh cadence (pwsh patch lifecycle).** Pin to the **PowerShell 7.4 LTS** line. The bundled `pwsh` is refreshed to the latest 7.4 patch **whenever the bundle's CVE/advisory database is rebuilt** (the runtime rides the same refresh pass as the data), **plus an out-of-band rebuild on any PowerShell/.NET security advisory**. The bundled `pwsh` version + build date are stamped into the report header so a reviewer can see how fresh the runtime is.

### 3.7 Classification & content sniffing (the router) — elaborates §3.1 step 2
The classifier (`src/helpers/classify.ps1`) is an **engine component, not an analyzer** — it runs before dispatch and decides each unit's effective `Type`. It is the backbone the v0.2 disguised-script detection is built on, so it is specified concretely here. **Core principle: the file extension is the *declared* intent and is never trusted for routing; content decides.** All sniffing is static — it reads bytes only, never executes a file to learn what it is.

**For every file, read the leading bytes (cap ~64 KB; hash the whole file separately) and evaluate four signals, strongest first:**

| # | Signal | Authoritative for | Examples |
|---|---|---|---|
| 1 | **Magic bytes / format signature** | binary *formats* (a file that *is* a ZIP is a ZIP regardless of name) | `PK\x03\x04`→zip-family (whl/egg/jar/zip **/ OOXML docx-xlsx-pptx**), `D0 CF 11 E0`→OLE/CFB (legacy doc/xls/ppt **+ vbaProject.bin**), `%PDF`→pdf, `{\rtf`→rtf, `1F 8B`→gzip (tgz/tar.gz), `MZ`→PE, `7F ELF`→ELF, `\x89HDF`→HDF5, `GGUF`→gguf, safetensors 8-byte header+JSON, pickle proto `\x80\x02..` |
| 2 | **Shebang** (`#!` at byte 0 of text) | scripts; parse the interpreter | `#!/bin/bash`→shell, `#!/usr/bin/env python`→python, `#!.../pwsh`→powershell |
| 3 | **Language content signatures** (scored heuristics) | text without shebang | PS: `[CmdletBinding()]`, `param(`, `$PSVersionTable`, `Verb-Noun`/`Invoke-*`; Python: `def `,`import `,`__name__`; shell: `then/fi/esac/done`, `$(...)`, `export ` |
| 4 | **Extension** (weakest = the *declared* type) | fallback / intent of record | `.py .ps1 .sh .tgz .pkl …` |

**Precedence & conflict resolution:**
- Binary **magic bytes win** for format identity (signals 2–4 don't override a confirmed binary format).
- **ZIP-family disambiguation** (many formats share the `PK` signature): peek at archive entries — `[Content_Types].xml` + `word/`\|`xl/`\|`ppt/` → **Office OOXML**; `*.dist-info/`\|`*.egg-info` → **Python wheel/egg**; `package/package.json` → **npm**; else **generic archive**. Likewise an `OLE/CFB` container is checked for `vbaProject.bin` → macro-bearing Office.
- For text: **shebang > content signature > extension.**
- The classifier records both a **`DeclaredType`** (signal 4) and a **`DetectedType`** (best of signals 1–3) with a **confidence** score.
- **Routing uses `DetectedType` when confident** — a `.txt` that is really PowerShell is dispatched to the PowerShell analyzer *and* flagged. Extension routing is the fallback only when content is unrecognized.
- **`DeclaredType ≠ DetectedType` → emit a `disguised-file` finding.** Severity scales with suspiciousness: a script masquerading under an innocent/no extension (`.txt`, `.log`, none) is **HIGH**; a benign format/extension drift is **LOW/INFO**. These findings are **advisory** (never abort the run).

**Defense-in-depth rules (the disguised case is the whole point):**
- **Sniff every file**, not just unknown extensions — the threat is a script wearing a trusted name.
- **Ambiguous / polyglot files:** route to the *most dangerous* matching analyzer (if it could be PowerShell, scan it as PowerShell) and flag it — bias toward over-scanning, not under.
- **Low-confidence & unrecognized:** route by recognized extension if any, else mark `unsupported`. Either way the file is still **hashed and listed** so nothing submitted is silently ignored (the unsupported-file pass remains the safety net — §4 cross-cutting).
- **Nested:** archive members are re-classified recursively after extraction, subject to the depth cap (§4 archive hardening).
- Detect text **encoding (UTF-8/16, BOM)** before signal 3 so pattern matching isn't defeated by encoding.

**Classifier output per file:** a `Unit { Type=DetectedType, DeclaredType, DetectedType, Confidence, Path, Name, StagingPath?, Files? }` plus zero or more pre-dispatch `disguised-file` findings (same normalized schema as §3.3).

### 3.8 Report outputs — three renderers over one model
The aggregation step builds **one in-memory finding model** (the §3.3 schema, grouped by unit) and renders it three ways. There is exactly one source of truth; the human formats are *views*, not separately-computed data.

- **JSON — canonical, machine-readable (the contract).** Carries a top-level **`schemaVersion`** so downstream consumers (CI, automation, §3.9) can depend on a stable shape; changes to it are versioned deliberately. This — not HTML — is the machine format.
- **HTML — primary human report.** A **single self-contained `.html`** (inline CSS + minimal inline JS; **no external/CDN/network loads** so it works air-gapped and never phones home). Layout fixes the "noisy / hard to scan" problem: a summary dashboard up top (overall risk + counts by severity and category), collapsible per-unit sections, and a sortable/filterable findings table with color-coded severity badges. Report header shows runtime/mode/advisory-DB date (§3.5/§3.6).
  - **Security requirement (mandatory, designed in from day one):** the report is built from *untrusted* submission data (file names, code snippets, secret matches). **Every submission-derived value is HTML-encoded** before interpolation; the file sets a restrictive inline **`Content-Security-Policy`** meta; **no data-driven inline event handlers, no external resource loads.** This closes the XSS/HTML-injection vector where a malicious artifact plants `<script>` in a filename that executes when the analyst opens the report. A v0.1.0 exit criterion is an injection/CSP test that feeds hostile strings through every renderer field.
- **TXT — slim summary only.** Header + overall risk + CRITICAL/HIGH findings (not the full flat dump that made the old text reports noisy). Stays useful for terminals, CI logs, `grep`, and browser-less consoles. Plain text has no injection surface.
- **SBOM** (per archive, CycloneDX) and the **SHA-256 manifest** are emitted alongside, as today.

Testing: assert findings against **JSON** (the source of truth); HTML/TXT get smoke checks (renders, contains expected anchors/counts) plus the injection/CSP test above.

### 3.9 Automation / orchestration interface (e.g. n8n, CI, SOAR) — design considerations
*Not an early-release deliverable (post-1.0 backlog), but the choices below are cheap if designed for now and expensive to retrofit, so the engine is built to not preclude them.* The goal: let an external orchestrator (n8n's Execute Command / HTTP nodes, a CI step, a SOAR playbook) drive the scanner and consume results without a human.

**What a clean CLI contract needs (gets ~90% of integrations, including n8n's Execute Command node):**
- **Fully non-interactive guarantee.** Never block on a prompt under automation: `-Path` + `-AutoInstall` + a `-NonInteractive` mode where the bootstrapper preflight (§3.6) *fails fast with a clear message and exit code* instead of prompting.
- **Documented, meaningful exit codes.** The single most important automation feature — orchestrators branch on them. e.g. `0` = completed, no findings at/above gate; `10` = completed, findings at/above gate; `2` = execution/tooling error; `3` = bad input. Plus a **`-FailOn <severity>`** gate so a pipeline can say "fail if anything HIGH+."
- **Clean stdout/stderr separation.** A **`-Quiet -OutputFormat json`** mode that writes *only* the canonical JSON (§3.8) to stdout, with all human banner/status/log noise on stderr or the log file. (This is the detect-secrets stderr-pollution lesson, generalized.) Orchestrators capture stdout and parse it directly.
- **Stable `schemaVersion`** on the JSON (§3.8) so workflows don't break on output changes.
- **Deterministic outputs + concurrency safety.** Known output paths (or stdout); idempotent runs; first-time tool *provisioning* (write) guarded by a lock while concurrent *scans* (read) of the shared venv/bundle are safe — so parallel workflow executions don't corrupt each other.

**Considerations specific to a tool like n8n:**
- **Where it runs.** Self-hosted n8n is typically **Linux/Docker**, while our operator bundle is Windows x64. Two paths: (a) n8n invokes the scanner on a **Windows host remotely** (SSH/WinRM, or the HTTP wrapper below); or (b) we lean on **PS 7 being cross-platform** — Bandit, detect-secrets, pip-audit, ShellCheck, Node, pefile/pyelftools all run on Linux too, so a **Linux build of the engine** is genuinely within reach (the classifier/registry/analyzers are OS-agnostic; only the PE-centric bits and the bundled `pwsh` build are Windows-flavored). This is a latent payoff of the PS 7 choice — worth keeping the code path-/OS-clean even before we commit to a Linux build.
- **Long-running scans (~minutes/unit) break synchronous calls.** n8n's Execute Command and a sync HTTP request will time out on big submissions. The orchestration-friendly pattern is **async: submit → get a job ID → poll status / fetch report when done** (or a webhook callback). The CLI already supports the simplest version of this — n8n drops files in a watched folder, fires the scan, and reads the JSON/HTML from a deterministic results path when the process exits.
- **Optional HTTP wrapper (fuller integration, later).** A thin service: `POST` a file/folder → job ID → `GET` status/report. Because it then ingests untrusted input over the network, it inherits hard requirements — authentication, strict input validation, resource/timeout caps (the §4 zip-bomb/timeout guards become load-bearing), and never running privileged. This is a deliberate later component (post-1.0 backlog); the CLI contract above is the foundation it would wrap.

---

## 4. Analyzer coverage matrix

| Unit type | Inputs | Extract? | Risky-code | Secrets | Dependency/CVE | Binary/Deserialization | Type-specific high-value checks |
|---|---|---|---|---|---|---|---|
| **Python** *(port)* | `.whl .egg .zip .tar.gz .tgz .py .pyw .ipynb` | yes | **PythonRules** (core, curated high-signal: `eval`/`exec`, `os.system`, `subprocess(shell=True)`, `pickle`/`marshal` loads, download-and-run, decode-then-exec, ctypes — via AST helper `scan_python.py`); Bandit (deep †) | detect-secrets †| pip-audit (`Requires-Dist`) + CycloneDX SBOM | PE/ELF triage (`inspect_binary.py`) | notebook code-cell projection (no execution) |
| **Disguised** *(v0.2 ✅)* | any ext / no ext | n/a | reroute to matched analyzer | detect-secrets | — | — | shebang + magic-byte + **content-signature** sniff (PS/Python/shell/batch/VB, no-shebang); **extension/content mismatch** finding (`MTS-DISGUISE-001/002`) |
| **Documents** *(v0.3 ✅)* | Office `.doc .docx .docm .xls .xlsx .xlsm .ppt .pptx .rtf`; `.pdf` | scanned in place | — | — | — | — | **Office** (`OleVbaScan` + `scan_office.py`/oletools): VBA macro presence + auto-exec/suspicious keywords, DDE/DDEAUTO, remote-template injection. **PDF** (`PdfTriage`, pure PowerShell): `/JS` `/JavaScript`, `/OpenAction`/`/AA`/`/Launch`, `/EmbeddedFile`, `/URI`, `/RichMedia`, `/Encrypt`, with name hex-escape de-obfuscation. Never rendered/opened/executed. |
| **Shell** *(v0.4 ✅)* | `.sh .bash .zsh .ksh` | no | ShellCheck (`shellcheck-py`) + custom rules (`curl\|bash`, `base64 -d\|sh`, `eval`, `chmod 777`, hardcoded IPs) | detect-secrets | — | — | Two-layer: ShellCheck flags shell bugs (SC-coded); custom rules flag dangerous-but-valid patterns ShellCheck intentionally skips |
| **PowerShell** *(v0.5 ✅)* | `.ps1 .psm1 .psd1` | no | PSScriptAnalyzer + custom rules | detect-secrets | — | Authenticode signature check (HashMismatch=HIGH) | `IEX`, `DownloadString`/`DownloadFile`, `-EncodedCommand`, hidden-window, `FromBase64String`, AMSI/Defender tampering, exec-policy bypass |
| **npm** *(v0.6 ✅)* | `.tgz`, `package.json`, `.js .mjs .cjs .ts` | yes (tar) | JS risky patterns (child_process/eval/Function/obfuscation) | detect-secrets | **OSV** (api.osv.dev) vs `package-lock.json` exact versions (online) | — | **pre/post/install lifecycle scripts** (top signal, HIGH) + risky-command inspection, `bin` shims; pure-PowerShell core (no Node) |
| **Model / LLM** *(v0.7 ✅)* | `.pkl .pickle .pt .pth .bin .joblib .h5 .pb .onnx .safetensors .gguf .npy .npz` | `.pt` zip opened in-helper | — | detect-secrets on sidecar configs | — | **pickle opcode scan** (`pickletools.genops`, NEVER unpickles): `REDUCE`/`GLOBAL`/`STACK_GLOBAL` + dangerous modules (os/subprocess/...) = CRITICAL | safetensors/gguf cleared as safe; PyTorch `.pt` zip → `data.pkl` scanned |
| **VB family** *(v0.10 ✅)* | `.bas .cls .frm .vba` (exported VBA modules); `.vbs .vbe .wsf .hta` (VBScript + wrappers) | no | **VbaRules** (core, pure PowerShell — no helper, no pip package, works air-gapped with zero provisioning) | — | — | — | Auto-exec entry points (`Auto_Open`/`Document_Open`/`Workbook_Open`), `Shell`/`WScript.Shell`, download primitives (`URLDownloadToFile`, `MSXML2.XMLHTTP`, `WinHttp`), `Declare … Lib` + shellcode APIs (`VirtualAlloc`/`RtlMoveMemory`, CRITICAL), registry persistence, obfuscation (`Chr()` chains, `StrReverse`, `CallByName`), hidden/encoded PowerShell; **combination escalation** (download+exec, auto-exec+payload → CRITICAL). `.vbe` reported as an explicit coverage gap (Script Encoder output is unreadable statically). Embedded Office macros stay with `OleVbaScan`. |
| **Generic archive** *(v0.8 ✅)* | `.zip .whl .egg`, `.tgz .tar.gz` | yes (hardened) | — | — | — | — | Pre-extraction hazard inspection: **zip-slip / path-traversal HARD-BLOCK**, **decompression-bomb caps** (per-entry ratio + 512 MB aggregate + entry-count), **symlink** flag, **nested-archive** flag; tar gets a traversal pre-check + Python `data` filter |

**† `deep` tier — opt-in, off by default.** **Bandit** and **detect-secrets** generate noise on routine ingress, so they sit in the `deep` tier and run only under `-Profile full` or an explicit `-EnableAnalyzers` (§3.2). Every other column above is `core` (on by default). The type-specific linters (`ShellCheck`, `PSScriptAnalyzer`, npm `semgrep/njsscan`) **stay `core` (on by default)** — but, like any analyzer, can be turned off per-run by name via `-DisableAnalyzers ShellCheck,PSScriptAnalyzer` if they prove noisy for a given operator.

### Cross-cutting (all units, every release)
- **Report outputs** — three renderers over one finding model (see §3.8): canonical **JSON** (machine), rich **HTML** (primary human), slim **TXT** (summary). All submission-derived text is HTML-encoded and the HTML carries a strict inline CSP — see §3.8.
- **SHA-256 manifest** of every file in the submission → audit trail in report (NEW; cheap, high audit value).
- **Extension/content mismatch** surfaced prominently (driven by the v0.2 classifier).
- **Unsupported-file pass** (carried forward) — but now far fewer files are "unsupported" because the classifier sniffs content.
- **Static-only guarantee** enforced structurally: no analyzer is allowed to invoke an interpreter on submitted content.

---

## 5. Phased roadmap

Semver from day one. **0.x while coverage and the JSON/CLI contract are still expanding** — the contract may change between 0.x releases as real-world testing teaches us what the generic model needs. **1.0.0 is the full-coverage milestone**, not the first release. Each phase ships a tagged GitHub Release with notes, gated by passing Pester + smoke + CI.

| Version | Theme | Scope | Exit criteria |
|---|---|---|---|
| **v0.1.0** | **Engine + Python parity** | Classifier, analyzer registry, generic finding schema, provisioning layer (online + offline bundle), three-renderer report (canonical JSON + HTML + slim TXT + SBOM + SHA-256 manifest, §3.8). Port all Python analyzers (Bandit, detect-secrets, pip-audit, binary inspection, notebook projection) onto the new engine, with Bandit + detect-secrets in the opt-in `deep` tier (§3.2/§4). | New engine reproduces 100% of `scan-python-packages` v1.6.1 Python findings on the ported fixture corpus **when run under `-Profile full`**; default `core` profile excludes Bandit/detect-secrets; offline bundle runs air-gapped; HTML report passes injection/CSP checks. |
| **v0.2.0** | **Disguised scripts** | Content sniffing (shebang, magic bytes, script signatures); extension/content-mismatch findings; router uses sniff result to dispatch a `.txt` that is really a script to the right analyzer. | Disguised `.txt`/no-ext scripts are reclassified and flagged; fixtures cover PS/bash/python hidden behind innocent extensions. |
| **v0.3.0** | **Documents (Office + PDF)** | `oletools` + `pdfid`/`pdf-parser` provisioning (pip; offline-bundle vendored); `Invoke-OleVbaScan` (VBA/XLM macros, auto-exec, DDE, remote-template injection, embedded OLE) and `Invoke-PdfTriage` (`/JS`, `/OpenAction`/`/AA`/`/Launch`, `/EmbeddedFile`, `/URI`); OOXML unzip + embedded-file extraction → recursive re-classification; encrypted-doc coverage-gap finding; `core` tier with tuned severities; fixtures. | Macro/auto-exec, DDE, remote-template, and PDF JS/launch/embedded fixtures flagged; encrypted-doc fixture reported as uninspectable; static-only (no doc rendered, no macro/JS executed). |
| **v0.4.0** | **Shell / bash** | ShellCheck provisioning (PATH/bundle), `Invoke-ShellCheckScan`, custom risky-pattern rules, fixtures. | Shell fixtures produce expected findings online and offline. |
| **v0.5.0** | **PowerShell** | PSScriptAnalyzer module provisioning, custom rule set for the high-value patterns above, Authenticode signature check, fixtures. | PS fixtures produce expected findings; signature status reported. |
| **v0.6.0** | **npm packages** | Node/npm provisioning, tarball extraction, `package.json` lifecycle-script inspection, `npm audit`/OSV + npm SBOM, JS static analysis, fixtures. | npm fixtures (incl. malicious postinstall) flagged; offline audit uses vendored advisory DB. |
| **v0.7.0** | **Model / LLM files** | Pickle opcode scanner (never unpickle), safe-format recognition, sidecar-config URL/secret scan, fixtures. | Malicious-pickle fixture flagged via opcodes; safetensors fixture recognized as safe. |
| **v0.8.0** | **Archive hardening** | Generic archive routing, zip-slip/path-traversal guard, decompression-bomb caps, nested-depth limit, symlink detection. | Bomb/zip-slip fixtures are caught before extraction; nested archives handled to depth limit. |
| **v1.0.0** | **Full-coverage milestone** | All planned ingress types working end-to-end; **JSON `schemaVersion` + CLI contract frozen** (post-1.0 changes follow strict semver); docs/operator guide complete. **Validated on real untrusted file transfers**, not just fixtures (see §8 — run on an isolated/disposable host). | All file-type fixtures pass; contract declared stable; a real-transfer pilot completes with reviewer-usable reports and no engine crashes/false-clean on the pilot set. |
| **Backlog (post-1.0)** | Reporting & ops | Cross-submission aggregate dashboard, signed/tamper-evident reports, advisory-DB refresh tooling for the offline bundle, optional offline hash-reputation lookup, automation/orchestration interface (§3.9). | — |

---

## 6. Carry forward vs. rethink

The runtime decision (§3.6) reshapes this section: a large share of the 5.1 "robustness tax" exists *only because of Windows PowerShell 5.1* and is **retired**, not ported, on PS 7. What remains is the version-independent engineering value.

### Retired on PS 7 (do not port — these were 5.1 workarounds)
- ~~Save script with **UTF-8 BOM**~~ → PS 7 defaults to `utf8NoBOM` for all text output and reads BOM-less UTF-8 correctly. Em-dashes "just work"; reports/logs/JSON are clean UTF-8 by default.
- ~~**EAP save/restore** around every native-command call~~ → since **PS 7.2**, error records redirected from native commands (`2>&1`) are not written to `$Error` and `$ErrorActionPreference` no longer applies to them. The wrapper that threaded through the whole 5.1 script is unnecessary.
- ~~Iterate captured native output with **`foreach` statement, not the pipeline**~~ → same root cause as above; native-command `ErrorRecord`s no longer escalate to Stop, so normal pipeline iteration is safe.
- ~~**`@(...)` wrapping** before `.Count`~~ → PS 7 exposes a consistent `.Count`/`.Length` on scalars and `$null` (`$null.Count` → 0), so the defensive wrapping for counting is no longer required. *(Keep light `@()` only where a cmdlet genuinely returns scalar-or-array and you then iterate — hygiene, not a workaround.)*
- ~~ArrayList-everywhere to dodge single-element JSON collapse~~ → use **`ConvertTo-Json -AsArray`** (and `ConvertFrom-Json -NoEnumerate`); PS 7 also *warns* on depth overflow instead of silently truncating. The report/SBOM schema becomes correct without scaffolding.

### Carry forward (version-independent value — port)
- **`2>$null`** for tools that pollute stderr into stdout JSON (detect-secrets). On PS 7 this is about keeping captured output clean, not crash-avoidance — still wanted.
- **`PSObject.Properties.Name`** wrapped when enumerating member names under `Set-StrictMode` (StrictMode behavior is version-independent).
- **PEP 440 version comparison**, generalized into a comparator that also handles npm semver and PS module versions for the new `Resolve-Tool` layer.
- **Lifecycle & infra:** shared scanner venv, central timestamped logs, temp staging deleted in `finally` (now `clean {}` blocks, PS 7.3+), scan-root `.reports\`.
- **Graceful degradation:** missing optional tool → log + reduced coverage, never a crash (now extended to "analyzer unavailable offline" per §3.4).
- **Test/CI:** Pester structure, deterministic fixture generator + manifest contract, smoke harness with timestamped artifacts, GitHub Actions (test / smoke / security) with read-only token perms; Pester-safe dot-sourcing (main guarded so tests load functions without launching a scan).

### Rethink / build new
- **Runtime + entry point:** ship portable `pwsh` in the bundle and a 5.1-safe bootstrapper that re-launches under PS 7.4+ (§3.6); write the engine PS-7-idiomatic.
- **Discovery & routing:** `Get-PackageUnits` → `Invoke-Classification` (extension + magic-byte + content sniff, emits `UnitType` and mismatch findings).
- **Dispatch:** fixed `Invoke-*` sequence → **analyzer registry** lookup by `UnitType`.
- **Concurrency:** per-unit scans run under **`ForEach-Object -Parallel` / `Start-ThreadJob`** (PS 7) with a throttle cap, directly attacking the ~8 min/pkg wall-clock pain — impossible natively on 5.1.
- **Archive extraction:** drop the `Expand-Archive` `.zip`-only copy-to-temp dance; call **`[System.IO.Compression.ZipFile]`** directly for `.whl`/`.egg`/`.zip` (identical behavior, no temp copy), with the §4 archive-hazard guards layered on top.
- **Finding schema:** add `Category`, `UnitType`, `Recommendation`.
- **Provisioning:** single-venv installer → **multi-kind `Resolve-Tool`** (portable pwsh / pip / PS module / external binary) with offline-bundle binding.
- **Reporting:** Python-specific summary → type-grouped summary with runtime/mode/advisory-date header and SHA-256 manifest.
- **Fixtures:** Python-only corpus → multi-type corpus (disguised, shell, PS, npm, model, archive-hazard) with per-type manifest expectations.

---

## 7. Proposed repo layout

*(✅ = exists in the v0.1.0 scaffold and is verified running under pwsh 7.6 with the Pester suite green.)*

```
media-transfer-scan-tool/
  src/
    Invoke-MediaTransferScan.ps1     # ✅ entrypoint: param/guarded-main, dot-sources lib + analyzers
    lib/                              # engine internals (PowerShell)
      Logging.ps1                     # ✅ Write-Log / Show-Status (-Quiet aware)
      Findings.ps1                    # ✅ New-Finding factory + Get-RiskLevel (§3.3 schema)
      Classify.ps1                    # ✅ classifier: ext + magic-byte + shebang (§3.7)
      Registry.ps1                    # ✅ Import-AnalyzerRegistry + tier/profile selection (§3.2)
      Engine.ps1                      # ✅ Invoke-Scan pipeline (discover→classify→dispatch→aggregate)
      Report.ps1                      # ✅ JSON + HTML(encoded+CSP) + slim TXT renderers (§3.8)
    analyzers/                        # one file per analyzer module (registry descriptors)
      FileHash.ps1                    # ✅ SHA-256 manifest (core)
      PipAudit.ps1  BinaryInspection.ps1   # ✅ v0.1.0 (core)
      Bandit.ps1  DetectSecrets.ps1        # ✅ v0.1.0 (deep, opt-in)
      PythonRules.ps1                 # ✅ curated high-signal Python rules (core; AST helper scan_python.py)
      PdfTriage.ps1                   # ✅ v0.3 PDF keyword triage — pure PowerShell, no deps
      OleVbaScan.ps1                  # ✅ v0.3 Office triage (via scan_office.py)
      VbaRules.ps1                    # ✅ v0.10 standalone VBA/VBScript rules — pure PowerShell, no deps
      ShellCheck.ps1  PSScriptAnalyzer.ps1  NpmAudit.ps1  PickleOpcodeScan.ps1   # (v0.4–v0.7)
    helpers/                          # Python helper scripts
      inspect_binary.py               # ✅ PE/ELF triage (pefile/pyelftools)
      scan_office.py                  # ✅ oletools + stdlib zip checks — static, never opens in Office
      scan_pickle.py                  # (v0.6 — pickle opcode scanner, static, never loads)
      scan_python.py                  # ✅ curated high-signal Python rules (stdlib ast; never imports/executes)
      # note: no scan_pdf.py — PdfTriage is pure PowerShell (no third-party PDF parser)
  bundle/                             # offline-bundle build script + manifest (vendored tools/DBs) — later
  tests/
    MediaTransferScan.Tests.ps1       # ✅ Pester 5: classification, registry/tiers, reporting, HTML-injection
    Run-Tests.ps1                     # ✅ runner (cross-edition Pester discovery; -CI for GH Actions)
    fixtures/sample/                  # ✅ clean.py + notes.txt (python disguised as .txt)
    fixtures/build_fixtures.py        # deterministic multi-type corpus + manifest.json — later
    Run-Smoke.ps1                     # later
  docs/
    test-environment.md               # ✅ isolated-host runbook for real untrusted transfers
    release-notes/
  .github/workflows/
    test.yml                          # ✅ Pester on windows-latest (pwsh 7), read-only token
    smoke.yml  security.yml           # later
  README.md  CHANGELOG.md  LICENSE  .gitignore   # ✅
```

> **Scaffold note (v0.1.0 in progress).** The engine pipeline, registry, classifier, finding schema, and all three renderers exist and are **verified**: `pwsh ./tests/Run-Tests.ps1` → 7/7 green, and `pwsh ./src/Invoke-MediaTransferScan.ps1 -Path <folder>` produces JSON+HTML+TXT (exit 0 clean / 10 findings). Still to do for v0.1.0: port the real Python analyzers (Bandit/detect-secrets/pip-audit/binary inspection/notebook projection), the provisioning layer + offline bundle, and the bootstrapper. The dev host now has PowerShell 7.6.

---

## 8. Risks & open questions

- **Offline advisory freshness.** Vendored CVE/OSV DBs go stale. Need a documented refresh cadence and a build script that stamps the snapshot date into every report. *(decision: surface date in report header — done in design; cadence TBD.)*
- **External binary provisioning on locked-down hosts.** ShellCheck/Node may be blocked by policy. The offline bundle must be self-contained and runnable from a non-admin user profile.
- **Pickle scanner depth.** Opcode scanning catches the obvious `REDUCE`/`GLOBAL` patterns; sophisticated obfuscation may evade it. Document it as triage, not proof of safety (same framing as binary inspection).
- **Performance on large submissions.** Semgrep/Bandit rule fetches and per-package scans are slow (~8 min/pkg observed). Addressed by bundle rule caching + PS 7 `ForEach-Object -Parallel` (§6); needs a sane throttle cap so concurrent venv/tool invocations don't thrash the host.
- **Portable `pwsh` patch lifecycle.** *Resolved:* pin to PS 7.4 LTS; refresh the bundled `pwsh` on every CVE-database rebuild + on any PowerShell/.NET security advisory; stamp version + build date in the report header (§3.6).
- **Classifier false positives.** Content sniffing may misroute exotic files; mismatch findings must be advisory, and the unsupported-file pass remains the safety net.
- **⚠ Analyzer/parser attack surface when testing on *real* untrusted transfers.** The static-only guarantee stops the *submission's intended* payload from running, but it does **not** protect against an exploit in the *analyzer tooling itself* — oletools, pdfid/pdf-parser, pip's wheel/tar parsing, image/PE parsers, etc. have all had parser CVEs, and a crafted file can target them. Therefore: **real-untrusted-transfer testing (and ideally production scanning) must run on an isolated, disposable host** — no network (or egress-filtered), VM snapshots, least-privilege account, resource caps. This is a hard prerequisite for the v1.0.0 real-transfer pilot, and the tooling (incl. bundled `pwsh`/.NET and every analyzer) must be kept patched (ties to the §3.6 refresh cadence). Treat "static analysis" as *lower* risk than detonation, not *zero* risk.

### To confirm before v0.1.0 build starts
1. Do you want me to **scaffold the v0.1.0 repo now** (engine skeleton + registry + ported Python analyzers), or keep iterating on this plan first?
2. Repo strategy: *Settled* — **new GitHub repo `media-transfer-scan-tool`** (clean rewrite, not a rename-in-place). `scan-python-packages` **remains a separate, active tool — not archived or deprecated**; the two repos cross-link in their READMEs.
3. Offline-bundle target: operator host is **Windows x64** → vendor the Windows x64 self-contained portable `pwsh`. *Settled:* no application-allowlisting/execute-location policy blocks a dropped signed `pwsh.exe`, and bundle delivery is controlled — **PS 7-only is fully committed; no 5.1 fallback.** *(Revisit only if a future operator host introduces WDAC/AppLocker that can't allowlist the bundled binaries.)*
```
