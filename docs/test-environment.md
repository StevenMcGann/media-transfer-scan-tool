# Test Environment Runbook

This project is run against **untrusted files**. There are **two distinct environments** — do not conflate them.

| Environment | Purpose | What runs there | Network |
|---|---|---|---|
| **Dev host** | Build the tool; run deterministic, *trusted* fixtures; Pester/smoke/CI | The engine + synthetic fixtures only | Normal (for tool install, advisory-DB refresh) |
| **Isolated test host** | Run the scanner against **real untrusted transfers** | The bundled scanner on genuinely hostile files | **None / egress-filtered** |

> ⚠ **Why isolation is mandatory.** The scanner is static — it never executes the *submission's* payload. But the **analyzer tooling itself** (oletools, pdfid/pdf-parser, pip's archive parsers, PE/image parsers, even `pwsh`/.NET) has its own parser attack surface, and these tools have had CVEs. A crafted file can target the analyzer rather than rely on being executed. **Static analysis is lower-risk than detonation, not zero-risk.** Treat the isolated host as potentially compromised after every real-untrusted run.

---

## Isolated test host — setup checklist

Recommended on this workstation: a **Hyper-V VM** (Windows 11 Pro for Workstations includes Hyper-V). A throwaway VM gives snapshots + network isolation cleanly.

**Provisioning (manual — must be done by the operator; cannot be scripted from the dev host):**

1. **Create a dedicated VM** (Hyper-V / VirtualBox / VMware). Generation 2 Hyper-V, Windows x64 guest to match the bundle target.
2. **Network: isolated.** Attach to a Hyper-V **Internal/Private virtual switch** with no uplink, or disable the vNIC entirely. If advisory-DB refresh is ever needed inside, do it via a *temporary* connection, then revert to isolated. Default state = no egress.
3. **Snapshot / checkpoint baseline.** Take a clean checkpoint *before* any untrusted file touches the VM. **Revert to it after each sample set** (or at minimum daily). This is the disposability that makes a parser exploit non-persistent.
4. **Least privilege.** Run the scanner under a **standard (non-admin) account**. The bundled `pwsh` + tools run from the user profile (no install needed — that's the §3.6 design).
5. **Disable convenience bridges to the host:** turn off clipboard sharing, drive/folder redirection, and shared folders in the VM integration settings. These are exfil/escape paths.
6. **Resource caps.** Cap vCPU/RAM and disk so a decompression bomb or runaway parser can't exhaust the *host*. Pair with the engine's own caps (§4 archive hardening, per-analyzer timeouts §3.2).
7. **File ingress (one-way).** Move submissions in via a **read-only** channel — a mounted read-only ISO/VHD built on the dev host, or a one-way copy. Avoid writable shared folders. Reports come *out* the same controlled way (copy the `.reports\` folder, or read it over the read-only mount after the run).

**Per-run workflow:**

```
1. (host)  Build read-only media containing the submission set.
2. (VM)    Revert to clean checkpoint.
3. (VM)    Mount submission media read-only.
4. (VM)    Run the scanner -> .reports\  (JSON + HTML + slim TXT).
5. (VM)    Copy reports out via the controlled channel.
6. (host)  Review reports. Triage findings.
7. (VM)    Revert to clean checkpoint (discard the VM state).
```

**Patching.** Keep the bundled `pwsh`/.NET and every analyzer current (ties to the §3.6 / §3.4 refresh cadence). An out-of-date parser is the most likely thing a hostile file would target. Rebuild the bundle on the dev host, re-deliver to the VM via read-only media.

---

## AV / EDR on the review host (Microsoft Defender, etc.)

A malware-handling host almost always has AV/EDR watching. There are **two
distinct interactions**, and they are not the same problem:

**1. The scanner tripping AV on its *own* code — should not happen, by design.**
The PowerShell analyzer's detection signatures (AMSI-tamper, Defender-preference,
downloader, encoded-command, etc.) are **assembled from string fragments at
runtime**, so the contiguous trigger strings never appear in the engine's source
on disk. Without that, simply *loading* the engine made Defender fire **“Possible
AMSI tampering” (DefenseEvasion, High)** — a false positive caused by our own
detection patterns. If you still see an AMSI/EDR alert attributed to the
scanner's own scripts (`src\...`), treat it as a regression and report it — do
**not** add a blanket exclusion for the engine to paper over it.

**2. AV acting on the *submissions* — expected, and it can hide findings.**
When you scan genuinely malicious files, the host's real-time AV will detect and
often **quarantine/delete the submission files itself** — independently of this
tool. That is a valid signal (a quarantined file is a strong “reject”), but it
has a side effect: **if AV removes a file before the scanner reads it, the
scanner can’t report on it**, so the report under-counts. To get a complete,
attributable scanner report on the isolated host, pick one:

- **Exclude the scan paths for the run** — add the submission folder **and** the
  scanner’s staging dir (`%TEMP%\mts-staging-*`) to Defender exclusions while you
  run, then remove the exclusions. The host stays protected for everything else.
- **Audit/passive mode** — put Defender in passive/audit on the *isolated,
  reverted* VM so it logs rather than quarantines. Only acceptable because the VM
  is disposable and offline.
- **Accept AV quarantine as the verdict** — if a file is quarantined, record that
  as the finding and move on. Simplest, but you lose the scanner’s detail.

Whichever you choose: the isolated VM should be a host where malware alerts are
**expected and understood**, not auto-escalated to a SOC as live incidents.

---

## Dev host — what it needs

For building and running the **trusted fixture** suite (no untrusted files here):

- **PowerShell 7.4+** (`pwsh`) — the tool is PS 7-only. *(Currently missing on this machine — install before running the engine.)*
- **Python 3.x** (for `build_fixtures.py` and the analyzer helpers' venv).
- **Pester 5.x** (present: 5.7.1) and **git** (present).

The dev host never sees real untrusted transfers — only the deterministic synthetic corpus under `tests/fixtures/`, which is safe by construction.
