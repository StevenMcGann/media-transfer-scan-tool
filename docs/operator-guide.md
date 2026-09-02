# Operator guide

How to scan a submission and read the result. This guide assumes you received an
operator-ready **bundle** produced by `bundle/build-bundle.ps1`—not one of
GitHub's automatically generated source archives. Nothing needs to be installed
on the review host.

> **Safety first.** Run untrusted submissions on an **isolated, disposable host**
> (no network or egress-filtered, snapshot-reverted). Static analysis is lower
> risk than opening files, but the analyzer tooling itself has parser attack
> surface. See [test-environment.md](test-environment.md).
>
> **Expect AV/EDR alerts on real malware.** Microsoft Defender (or your EDR) will
> independently flag genuinely malicious *submissions* — that's normal on a
> malware-handling host. If AV quarantines a file before the scanner reads it, the
> report will under-count, so review the AV alerts alongside the scan. See
> [test-environment.md](test-environment.md#av--edr-on-the-review-host-microsoft-defender-etc)
> for how to run a complete scan (path exclusions / audit mode). The scanner does
> **not** trip AV on its *own* code — if it appears to, report it as a bug.

## 1. Set up (once)
1. Copy the bundle folder to the review host (via the controlled read-only channel).
2. That's it — the bundle carries its own PowerShell 7 and scanner tools. Nothing
   to install.

The bundle looks like:
```
media-transfer-scan-tool-<version>/
  Scan.cmd            <- run this
  bootstrap.ps1
  src/  tools/  manifest.json
```

## 2. Run a scan
From a command prompt in the bundle folder:
```
Scan.cmd -Path "D:\incoming\submission_2026-05-30"
```
- Point `-Path` at the **folder** of submitted files (it scans recursively).
- The report is written to `<that folder>\.reports\` — keep it with the submission.

### Common options
```
REM Add the deeper, noisier analyzers (Bandit risky-code + detect-secrets):
Scan.cmd -Path "D:\incoming\sub" -Profile full

REM Turn specific analyzers on/off by name:
Scan.cmd -Path "D:\incoming\sub" -EnableAnalyzers DetectSecrets
Scan.cmd -Path "D:\incoming\sub" -DisableAnalyzers ShellCheck

REM Air-gapped host: use vendored tools and skip live advisory lookups:
Scan.cmd -Path "D:\incoming\sub" -Mode offline
```
The bundle uses its vendored tools in either mode. It does not automatically
select offline mode. In v0.13.0 there is no vendored OSV advisory database, so
`-Mode offline` emits explicit INFO coverage-gap findings for dependency inputs
instead of treating them as vulnerability-free.

> By default (`-Profile core`) the high-signal analyzers run and the broad,
> false-positive-prone ones (Bandit, detect-secrets) are **off**. The report
> always lists what was *not* checked, so a clean report never hides a gap.
>
> **Python in core:** scripts are scanned by **PythonRules** — a curated set that
> reports only attacker-grade indicators (`eval`/`exec`, `os.system`,
> `subprocess(shell=True)`, `pickle`/`marshal` loads, download-and-run,
> decode-then-exec, etc.), *not* general code-quality noise. This is the middle
> tier: `-Profile full` / `-EnableAnalyzers Bandit` adds the deeper, noisier pass
> only when you want everything.

## 3. Read the report
Three files are written per scan (same timestamp):
- **`summary_<ts>.html`** — open in a browser. Start here: overall risk banner,
  severity counts, and a per-finding table.
- **`summary_<ts>.txt`** — quick terminal summary (CRITICAL/HIGH only).
- **`summary_<ts>.json`** — machine-readable (for automation).

**Overall risk** is the highest non-INFO finding severity:
`CLEAN < LOW < MEDIUM < HIGH < CRITICAL`. INFO findings stay visible but do not
raise overall risk; an INFO-only report is `CLEAN` and exits 0. Always review INFO
coverage statements before accepting a clean result.

**Severity guide:**
| Severity | Treat as |
|---|---|
| CRITICAL | Code-execution-on-load, a critical-scored confirmed vulnerability, or a tampered signature — **reject pending review**. |
| HIGH | Strong risk indicator (install scripts, IEX/downloaders, macros, zip-slip). |
| MEDIUM | Worth a look (obfuscation, DDE, base64 decode, symlinks). |
| LOW | Lower-confidence or contextual risk that still raises overall risk. |
| INFO | Inventory or coverage status. INFO can mean content was not inspected; it is not automatically benign. |

The **"NOT checked"** line lists disabled analyzers — if you need that coverage,
re-run with `-Profile full` or `-EnableAnalyzers <name>`.

**`MTS-NO-ANALYZER` (INFO)** marks a file that was hashed and listed but never
actually inspected, because no enabled analyzer covers its type — ordinary
documents and data files, mostly. It is there so the report never lets an
uninspected file read as a reviewed-and-clean one: **absence of findings on such
a file is absence of coverage, not evidence it is safe.** Judge those by what
they are, not by their empty finding list.

### Archive coverage findings

v0.13.0 recursively classifies and dispatches ordinary members of ZIP and tar
archives. The archive tree has run-wide limits of five nested archive levels,
5,000 staged entries, and 1 GB of expanded file content. Review these INFO
findings even when overall risk is CLEAN:

- **`MTS-ARCHIVE-MEMBER-UNINSPECTED`** — one or more extracted members had no
  enabled type-specific analyzer. The finding aggregates their names on the
  parent archive.
- **`MTS-ARCHIVE-DEPTH-CAP`** — a nested archive was not opened because the
  depth limit was reached.
- **`MTS-ARCHIVE-BUDGET-EXCEEDED`** — one or more members or semantic containers
  were not staged or analyzed because the shared entry/byte budget was reached.
- **`MTS-ARCHIVE-METADATA-PARTIAL`** — the v0.14 development path inspected
  recognized dependency metadata without extracting the blocked archive. This
  can identify a compressed wheel's own name/version and exact dependencies,
  but it does not mean the archive payload received full static analysis.
- **`MTS-ARCHIVE-METADATA-LIMIT` / `MTS-ARCHIVE-METADATA-ERROR`** — the bounded
  fallback itself reached a safety limit or could not safely read some metadata.

These findings describe incomplete coverage. Inspect the named content by a
separate controlled method or split the submission and rescan; do not interpret
the parent archive as fully reviewed.

## 4. Exit codes (for scripted use)
`0` no non-INFO findings · `10` non-INFO findings present · `2` error · `3` bad
input · `4` no PowerShell 7 runtime · `5` bundle integrity verification failed.

## 5. What it does and does not do
- **Static only** — it never executes, installs, imports, or unpickles submitted
  content. A clean report means "no static indicators found," not a guarantee.
- It is **not** a sandbox or AV engine. Use it as one gate in your review, on an
  isolated host, with the report kept as the audit record.
