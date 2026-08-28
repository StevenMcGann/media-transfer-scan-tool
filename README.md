# media-transfer-scan-tool

[![Tests](https://github.com/StevenMcGann/media-transfer-scan-tool/actions/workflows/test.yml/badge.svg)](https://github.com/StevenMcGann/media-transfer-scan-tool/actions/workflows/test.yml)

Operator-driven **static** security scanner for media-transfer review: point it at a submission folder of untrusted artifacts and get a durable, per-submission report before anything is admitted to a trusted environment.

> **Status:** **v0.11.0** — all planned file types (Python · disguised scripts · Office/PDF · shell · PowerShell · VBA/VBScript · npm · ML/model) + archive hardening + offline deployment, plus **curated high-signal Python rules** (`PythonRules`, core), a Defender/AMSI-safe engine, and an **OSV.dev dependency-vulnerability audit** (`OsvScan`, core, default-on) covering PyPI `requirements.txt`, npm `package-lock.json`, and NuGet `.nupkg`. The public contract is **frozen** ([docs/contract.md](docs/contract.md)) and operator/maintainer guides are written; **v1.0.0 tags once validated on real untrusted transfers** on the isolated host. Ships as **0.x** while coverage and the JSON/CLI contract expand; **1.0.0 is reserved for the full-coverage milestone** (all planned ingress types working, contract frozen, validated on real untrusted transfers). See [PLAN.md](PLAN.md).

## What it is / is not

- **Is:** a classifier + analyzer-registry engine that routes each file to the right static analyzers and renders one finding model as **JSON (canonical) + HTML (human) + slim TXT**.
- **Is not:** a sandbox or detonation chamber. It never executes, imports, installs, or deserializes submitted content. *(Even so, run real untrusted transfers on an isolated host — see [docs/test-environment.md](docs/test-environment.md).)*

## Coverage (planned)

Python *(v0.1)* · disguised scripts *(v0.2)* · Office + PDF documents *(v0.3)* · shell *(v0.4)* · PowerShell *(v0.5)* · npm *(v0.6)* · ML/model files *(v0.7)* · archive hardening *(v0.8)* · VBA/VBScript *(v0.10)* · OSV.dev dependency-vulnerability audit *(v0.11)* → **v1.0.0 full-coverage milestone.**

## Runtime

PowerShell **7.4+ only**. The offline bundle vendors a portable `pwsh`; a thin bootstrapper launches the engine under it so the operator installs nothing. See PLAN.md §3.6.

## Quickstart (dev)

```powershell
# Requires PowerShell 7.4+
pwsh ./src/Invoke-MediaTransferScan.ps1 -Path .\sample-folder

# Run tests
pwsh ./tests/Run-Tests.ps1
```

## Lineage

Clean-room successor to [`scan-python-packages`](https://github.com/StevenMcGann/scan-python-packages), which **remains a separate, active tool** (not archived). This project is a superset that also scans Python.

## License

MIT — see [LICENSE](LICENSE).
