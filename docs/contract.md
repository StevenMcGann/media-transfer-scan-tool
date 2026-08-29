# Public contract (`schemaVersion: "1.0.0"`)

The interfaces below have been the project's **stable contract since package
v0.9.0**. The report schema version is already `1.0.0`; it is independent of the
package version. Downstream consumers (automation, CI, SOAR, dashboards) may
depend on these interfaces. A backward-incompatible change requires a major
package-version bump and a matching `schemaVersion` bump.

Package v1.0.0 remains an operational milestone: validation against real
untrusted transfers on the isolated review host. It does not defer or re-freeze
the contract described here.

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
| `OverallRisk` | string | `CLEAN` \| `INFO` \| `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL`. Current behavior uses the highest non-INFO finding; an INFO-only report is `CLEAN`. `INFO` remains a reserved schema value and consumers must accept it. |
| `Counts` | object | Keys `CRITICAL,HIGH,MEDIUM,LOW,INFO` → integer counts. |
| `EnabledAnalyzers` | string[] | Analyzers that ran this scan. |
| `DisabledAnalyzers` | string[] | Analyzers **not** run (so a clean report never hides "not checked"). |
| `TotalFindings` | number | Count across all units. |
| `Units` | object[] | One per file discovered directly under the scan root. Extracted archive members do not become units; their findings are folded onto the parent archive (see below). |

**Unit object:**

| Field | Type | Notes |
|---|---|---|
| `Name` | string | File name. |
| `Type` | string | Classified type: `python,python-requirements,npm,nuget,powershell,shell,batch,vba,office,pdf,model,disguised,archive,native-binary,unsupported`. `disguised` is a reserved contract value; current disguise detection keeps the effective script type and adds a `disguised-file` finding. |
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
| `-AutoInstall` | switch | Compatibility switch. Online mode already installs missing pinned tools without interaction; offline mode never installs them. |
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
| `5` | Offline-bundle integrity verification failed. |

---

## 3. Not contractual (may change without a major bump)
- HTML and slim-TXT report layout/wording.
- Log file format and DEBUG message text.
- The specific set of analyzers and `TestID`s (these grow over time).
- SBOM filenames and the staging/venv directory layout.
