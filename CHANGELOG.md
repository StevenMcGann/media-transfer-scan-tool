# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). The `0.x` series predates the
frozen public contract; **1.0.0 marks the full-coverage milestone** (see [PLAN.md](PLAN.md) §5).

## [Unreleased]

### Added
- Initial repository scaffold: engine pipeline (discover → classify → dispatch → render),
  analyzer registry contract, normalized finding schema, and three-renderer report
  (canonical JSON + HTML + slim TXT).
- Test-environment runbook for isolated real-untrusted scanning ([docs/test-environment.md](docs/test-environment.md)).
- Project plan and feature roadmap ([PLAN.md](PLAN.md)).
