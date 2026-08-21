# Public contract (v1.0.0)

As of **v1.0.0**, the interfaces below are a **stable contract**. Downstream
consumers (automation, CI, SOAR, dashboards) may depend on them. A
backward-incompatible change requires a **major version bump** (→ 2.0.0) and a
matching `schemaVersion` bump.

The **JSON report is the canonical machine-readable output.** The HTML and TXT
reports are human views and are *not* contractual — their layout may change at
any time.

---

## 1. JSON report schema (`schemaVersion: "1.0.0"`)

Written to `<scan-root>\.reports\summary_<timestamp>.json`. Top-level object:

| Field | Type | Notes |
|---|---|---|
| `SchemaVersion` | string | `"1.0.0"`. Consumers should check the major component. |
| `ScanRoot` | string | Absolute path scanned. |
| `GeneratedUtc` | string | ISO-8601 UTC timestamp. |
| `ElapsedSeconds` | number | Wall-clock scan duration. |
| `Profile` | string | `core` \| `full`. |
| `Mode` | string | `online` \| `offline`. |
| `OverallRisk` | string | `CLEAN` \| `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` (highest finding severity; `CLEAN` if none above INFO). |
| `Counts` | object | Keys `CRITICAL,HIGH,MEDIUM,LOW,INFO` → integer counts. |
| `EnabledAnalyzers` | string[] | Analyzers that ran this scan. |
| `DisabledAnalyzers` | string[] | Analyzers **not** run (so a clean report never hides "not checked"). |
| `TotalFindings` | number | Count across all units. |
| `Units` | object[] | One per discovered file (see below). |

**Unit object:**

| Field | Type | Notes |
|---|---|---|
| `Name` | string | File name. |
| `Type` | string | Classified type: `python,npm,powershell,shell,batch,vba,office,pdf,model,disguised,archive,native-binary,unsupported`. |
| `Path` | string | Path relative to the scan root. |
| `Findings` | object[] | See below. |

**Finding object** (the normalized schema — stable):

| Field | Type | Notes |
|---|---|---|
| `Tool` | string | Producing analyzer (e.g. `PipAudit`, `PdfTriage`). |
| `Category` | string | `secrets,risky-code,vuln-dependency,native-binary,deserialization,macro,active-content,disguised-file,archive-hazard,parser`. |
| `Severity` | string | `CRITICAL,HIGH,MEDIUM,LOW,INFO`. |
| `Confidence` | string | `HIGH,MEDIUM,LOW`. |
| `UnitType` | string | The unit's type. |
| `File` | string | File (relative; `archive!inner/path` for archive members). |
| `Line` | number\|null | Line number where applicable. |
| `Issue` | string | Human-readable description. |
| `TestID` | string | Stable rule id (e.g. `PDF-LAUNCH`, `PICKLE-REDUCE`, a CVE/GHSA id). |
| `Recommendation` | string | Reviewer guidance (may be empty). |

### What is contractual
- The **field names, types, and enum values** above.
- New enum values **may be added** within a major version (new analyzers add new
  `TestID`s, `Category` is fixed but new `Tool`/`UnitType` values can appear) —
  consumers must tolerate unknown `Tool`/`TestID`/`UnitType` values gracefully.
- Removing/renaming a field or removing a `Category`/`Severity` value is breaking.

---

## 2. CLI surface

Entry points: `Scan.cmd` (bundle) and `src\Invoke-MediaTransferScan.ps1` (engine).

| Parameter | Values | Meaning |
|---|---|---|
| `-Path <dir>` | folder | Submission folder to scan. |
| `-Profile` | `core` (default) \| `full` | `full` adds the opt-in `deep`-tier analyzers. |
| `-EnableAnalyzers <names>` | analyzer names | Force-enable specific analyzers. |
| `-DisableAnalyzers <names>` | analyzer names | Force-disable specific analyzers. |
| `-Mode` | `online` (default) \| `offline` | `offline` skips network (no installs / live advisory feeds). |
| `-AutoInstall` | switch | (online) install missing tools without interaction. |
| `-VenvDir <dir>` | path | Use a specific scanner venv (the bundle sets this). |
| `-Quiet` | switch | Suppress console/log noise. |
| `-OutputFormat` | `all` (default) \| `json` | `json` echoes the JSON report path to stdout. |

### Exit codes (stable)

| Code | Meaning |
|---|---|
| `0` | Completed; overall risk `CLEAN`. |
| `10` | Completed; findings present (risk above CLEAN). |
| `2` | Execution / tooling error. |
| `3` | Bad input (no/invalid `-Path`). |
| `4` | No usable PowerShell 7.4+ runtime (bootstrapper). |

---

## 3. Not contractual (may change without a major bump)
- HTML and slim-TXT report layout/wording.
- Log file format and DEBUG message text.
- The specific set of analyzers and `TestID`s (these grow over time).
- SBOM filenames and the staging/venv directory layout.
