# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). The `0.x` series predates the
frozen public contract; **1.0.0 marks the full-coverage milestone** (see [PLAN.md](PLAN.md) §5).

## [Unreleased]

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
- Test-environment runbook for isolated real-untrusted scanning ([docs/test-environment.md](docs/test-environment.md)).
- Project plan and feature roadmap ([PLAN.md](PLAN.md)).
- Pester suite (47 tests) + GitHub Actions CI on PowerShell 7.
