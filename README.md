# Media Transfer Scan Tool

[![Tests](https://github.com/StevenMcGann/media-transfer-scan-tool/actions/workflows/test.yml/badge.svg)](https://github.com/StevenMcGann/media-transfer-scan-tool/actions/workflows/test.yml)

A Windows-focused static security scanner for reviewing untrusted files before they are transferred into a trusted environment.

Point the scanner at a submission folder and it will inventory, classify, hash, and route the files through the appropriate analyzers. Each scan produces a durable report in JSON, HTML, and text formats.

> **Current release: v0.11.0**
>
> The planned file-type coverage and public report contract are implemented. The project remains in the 0.x series until it has been validated against real untrusted transfers on the intended isolated review host. See [PLAN.md](PLAN.md) and [CHANGELOG.md](CHANGELOG.md).

## Purpose

Media-transfer reviews often involve mixed submissions: source code, scripts, documents, archives, packages, binaries, and machine-learning artifacts. A single antivirus result does not show whether every file was meaningfully inspected or whether a required analyzer failed to run.

This tool provides a repeatable static-analysis gate that:

- Recursively inventories and hashes submitted files
- Classifies content instead of trusting file extensions alone
- Detects scripts disguised as ordinary files
- Routes supported files to specialized analyzers
- Reports disabled, unavailable, blocked, or missing analysis coverage
- Produces a machine-readable audit record and a human-readable review report
- Supports a packaged Windows workflow for isolated and air-gapped review hosts

## Safety Model

The scanner performs **static analysis only**. It does not execute, import, install, open in the associated desktop application, or deserialize submitted content.

Static analysis still carries parser risk. Real untrusted submissions should be scanned on an isolated, disposable review host with appropriate containment and recovery controls. Microsoft Defender or another EDR may independently detect or quarantine malicious submitted files; review those alerts alongside the scanner report.

This tool is not a sandbox, detonation platform, or replacement for antivirus. A clean result means that the enabled analyzers found no reportable static indicators. It is not proof that the submission is safe.

See [docs/test-environment.md](docs/test-environment.md) for the recommended review-host design and AV/EDR considerations.

## Analysis Coverage

The current release includes coverage for:

- Python source, packages, wheels, notebooks, and pinned requirements
- PowerShell, shell, VBA, and VBScript
- Scripts disguised by an incorrect or innocuous file extension
- Microsoft Office documents, embedded VBA, DDE fields, and remote templates
- PDF active-content indicators
- npm packages, JavaScript/TypeScript, lifecycle scripts, and lock files
- NuGet packages
- PE and ELF binary inspection
- Pickle-based and common machine-learning model formats
- ZIP-family and tar archives, including path traversal and decompression-bomb controls, with every extracted member recursively classified and scanned by the full analyzer set (nested archives included, to a bounded depth/size budget)
- Known dependency vulnerabilities through OSV.dev for supported PyPI, npm, and NuGet inputs

The default **core** profile favors focused, higher-signal checks. The **full** profile adds Bandit and detect-secrets, which provide broader coverage but may generate more review noise.

Files for which no enabled analyzer claims meaningful coverage receive an explicit `MTS-NO-ANALYZER` finding (an uninspected archive member gets an aggregate `MTS-ARCHIVE-MEMBER-UNINSPECTED` note on its parent archive instead, so a large archive doesn't produce one warning per file). Tool failures and blocked external analyzers are also surfaced; they are not treated as clean results.

For the stable JSON schema, analyzer contract, CLI surface, and exit codes, see [docs/contract.md](docs/contract.md).

## Running the Packaged Tool

The operator bundle is the preferred way to run the scanner on Windows. It includes the supported PowerShell runtime and scanner dependencies, so the review host does not require a separate installation.

From a command prompt in the bundle directory:

```powershell
Scan.cmd -Path "D:\incoming\submission"
```

The path must identify a folder. Files beneath it are scanned recursively, and the results are written to:

```text
D:\incoming\submission\.reports\
```

### Common Options

Run the core profile, which is the default:

```powershell
Scan.cmd -Path "D:\incoming\submission" -Profile core
```

Add the broader Bandit and detect-secrets analyzers:

```powershell
Scan.cmd -Path "D:\incoming\submission" -Profile full
```

Enable or disable an individual analyzer:

```powershell
Scan.cmd -Path "D:\incoming\submission" -EnableAnalyzers DetectSecrets
Scan.cmd -Path "D:\incoming\submission" -DisableAnalyzers ShellCheck
```

Run without network access:

```powershell
Scan.cmd -Path "D:\incoming\submission" -Mode offline
```

Offline mode uses the analyzers available in the bundle. Live OSV.dev dependency lookups require network access; when that coverage is unavailable, the report identifies the resulting gap rather than silently treating the dependencies as clean.

For operating instructions and result interpretation, see [docs/operator-guide.md](docs/operator-guide.md).

## Reports

Each completed scan writes three timestamped reports from the same finding model:

| Report | Purpose |
| --- | --- |
| `summary_<timestamp>.html` | Primary analyst report with overall risk, counts, and findings |
| `summary_<timestamp>.json` | Canonical machine-readable report for automation and retention |
| `summary_<timestamp>.txt` | Concise terminal-friendly summary focused on high-severity results |

Overall risk reflects the highest reported severity:

```text
CLEAN < INFO < LOW < MEDIUM < HIGH < CRITICAL
```

The report also identifies analyzers that were disabled or unable to run. Review those coverage statements before interpreting a clean or low-risk result.

## Running from Source

Development checkouts require PowerShell 7.4 or later:

```powershell
pwsh ./src/Invoke-MediaTransferScan.ps1 -Path .\sample-folder
```

If a required analyzer dependency is not already available, connected development environments can allow provisioning with `-AutoInstall`. Do not use automatic installation on the untrusted review host.

## Tests

Run the full Pester test suite with:

```powershell
pwsh ./tests/Run-Tests.ps1
```

Maintainers should also review:

- [Maintainer guide](docs/maintainer-guide.md)
- [Test-environment guidance](docs/test-environment.md)
- [Public contract](docs/contract.md)
- [Offline bundle documentation](bundle/README.md)
- [Project plan](PLAN.md)
- [Changelog](CHANGELOG.md)

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed with no findings |
| 10 | Scan completed and findings were reported |
| 2 | Scanner or analyzer execution error |
| 3 | Invalid input |
| 4 | A suitable PowerShell 7 runtime was not available |
| 5 | Offline bundle integrity verification failed |

## Project Lineage

This project is a clean-room successor to [scan-python-packages](https://github.com/StevenMcGann/scan-python-packages). The earlier project remains a separate, active tool; Media Transfer Scan Tool expands the scope beyond Python while retaining Python scanning.

## License

Licensed under the [MIT License](LICENSE).
