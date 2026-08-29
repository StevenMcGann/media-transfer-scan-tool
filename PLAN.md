# Media Transfer Scan Tool — current plan

## Status

- **Current package release:** v0.13.0
- **Report schema:** `1.0.0`, frozen since package v0.9.0
- **Runtime:** PowerShell 7.4+ on Windows; the operator bundle vendors a pinned
  PowerShell 7.4 LTS patch and scanner environment
- **Remaining v1.0.0 gate:** successful validation against real untrusted
  transfers on an isolated, disposable review host

All originally planned ingress families are implemented. The project remains on
the 0.x package line because deterministic fixtures and CI do not substitute for
the real-transfer pilot described below.

## Purpose and boundaries

The scanner provides a repeatable static-analysis gate for mixed files arriving
through a media-transfer process. An operator points it at a writable submission
directory and receives JSON, HTML, and text reports under `<scan-root>\.reports\`.

The scanner:

- inventories, hashes, and classifies files by content rather than extension
  alone;
- routes supported types through specialized static analyzers;
- recursively dispatches ordinary ZIP/tar members through the same classifier
  and analyzers, subject to run-wide safety budgets;
- reports disabled, unavailable, blocked, skipped, and missing coverage; and
- never executes, imports, installs, opens in its associated application, or
  deserializes submitted content.

It is not a sandbox, detonation platform, antivirus replacement, or proof that a
clean submission is safe. Parser risk remains, so real untrusted work belongs on
the isolated host defined in [docs/test-environment.md](docs/test-environment.md).

## Current architecture

1. `Scan.cmd` starts the Windows PowerShell-compatible bootstrapper.
2. `bootstrap.ps1` verifies sealed bundle files, selects bundled PowerShell 7.4+
   before PATH PowerShell, binds the vendored scanner environment when present,
   and forwards the requested online/offline mode.
3. `src/Invoke-MediaTransferScan.ps1` discovers files and loads the analyzer
   registry.
4. `src/lib/Classify.ps1` classifies by filename, extension, magic bytes,
   shebang, and content signatures.
5. `src/lib/Engine.ps1` dispatches units and archive members through enabled
   analyzers and aggregates normalized findings.
6. `src/lib/Report.ps1` renders the same model as canonical JSON, HTML, and slim
   text reports.

The stable machine contract is documented in
[docs/contract.md](docs/contract.md). New tools, TestIDs, and unit types may be
added compatibly; removing or renaming contractual fields or values requires a
major package and schema version bump.

## Implemented release milestones

| Package release | Delivered capability |
| --- | --- |
| v0.1.0 | Generic engine, registry, normalized findings, Python parity, reporting, bootstrapper, and offline-bundle foundation |
| v0.2.0 | Content-based disguised-script detection and routing |
| v0.3.0 | Office and PDF static triage |
| v0.4.0 | Shell analysis |
| v0.5.0 | PowerShell analysis and signature status |
| v0.6.0 | npm package, JavaScript/TypeScript, lifecycle-script, and lock-file analysis |
| v0.7.0 | Pickle/model triage and safe-format recognition |
| v0.8.0 | Archive traversal, bomb, nesting, and symlink hardening |
| v0.9.0 | Curated core Python rules, frozen schema/CLI contract, operator and maintainer guides, and Defender/AMSI self-check |
| v0.10.0 | Standalone VBA/VBScript coverage, blocked-tool reporting, and analyzer timeouts |
| v0.11.0 | Default-on live OSV.dev audits for pinned PyPI, npm, and NuGet inputs |
| v0.12.0 | NuGet identity and OSV failure-bound hardening |
| v0.13.0 | Recursive archive-member classification/dispatch with run-wide depth, entry, byte, and staging controls |

Historical release detail belongs in [CHANGELOG.md](CHANGELOG.md); this file
tracks current architecture and remaining work.

## v1.0.0 acceptance plan

The package may move to v1.0.0 after all of the following are complete:

1. Build an operator-ready bundle with the current pinned PowerShell 7.4 LTS
   patch and scanner dependencies.
2. Verify the bundle manifest and sealed-file hashes before use.
3. On an isolated disposable host, copy a real transfer from read-only ingress
   media into a writable guest-local scan directory.
4. Run representative mixed submissions in offline mode and, during a separately
   controlled connected interval if authorized, online mode for live OSV checks.
5. Confirm that unsupported, disabled, blocked, timed-out, archive-budgeted, and
   otherwise uninspected content is visible rather than falsely clean.
6. Confirm that reports are usable for reviewer decisions and retained with the
   transfer record.
7. Review AV/EDR events alongside scanner reports and document any quarantine
   effects or scanner self-detections.
8. Revert the review host to its clean checkpoint after each sample set.
9. Record pilot outcomes, remaining false positives/negatives, crashes, and
   coverage gaps. Resolve release-blocking defects before tagging v1.0.0.

Fixture coverage, CI, and a successful bundle smoke test remain mandatory but do
not replace this pilot.

## Current backlog

These items are useful but are not part of the v1.0.0 acceptance gate unless the
pilot shows they are required:

- signed or otherwise publisher-authenticated bundles/manifests;
- a vendored, date-stamped advisory database for offline vulnerability lookup;
- documented advisory/runtime/analyzer refresh automation;
- optional offline hash-reputation lookup;
- cross-submission aggregate reporting; and
- an authenticated, resource-bounded automation/API wrapper.

## Release discipline

Every release must:

- keep the engine version, README status, changelog, bundle defaults/examples,
  PowerShell LTS patch pin, and release tag aligned;
- generate the synthetic fixture corpus before running Pester;
- pass the full Pester suite, security workflows, and the real `Scan.cmd`
  operator-chain smoke test;
- verify relative documentation links and the schema/CLI/exit-code tables;
- build and integrity-test the operator ZIP; and
- attach that ZIP to the GitHub release when the release is presented as
  operator-ready.

See [docs/maintainer-guide.md](docs/maintainer-guide.md) for commands and
[bundle/README.md](bundle/README.md) for bundle construction.
