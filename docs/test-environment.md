# Test Environment Runbook

This project is run against **untrusted files**. There are **two distinct environments** — do not conflate them.

| Environment | Purpose | What runs there | Network |
|---|---|---|---|
| **Dev host** | Build the tool; run deterministic, *trusted* fixtures; Pester/smoke/CI | The engine + synthetic fixtures only | Normal (for tool install, advisory-DB refresh) |
| **Isolated test host** | Run the scanner against **real untrusted transfers** | The bundled scanner on genuinely hostile files | **None / egress-filtered** |

> ⚠ **Why isolation is mandatory.** The scanner is static — it never executes the *submission's* payload. But the **analyzer tooling itself** (oletools, pdfid/pdf-parser, pip's archive parsers, PE/image parsers, even `pwsh`/.NET) has its own parser attack surface, and these tools have had CVEs. A crafted file can target the analyzer rather than rely on being executed. **Static analysis is lower-risk than detonation, not zero-risk.** Treat the isolated host as potentially compromised after every real-untrusted run.

---

## Isolated test host — setup checklist

Recommended on a Windows development workstation: a **Hyper-V VM** or an
equivalent disposable VM with checkpoints and network isolation.

**Provisioning (manual — must be done by the operator; cannot be scripted from the dev host):**

1. **Create a dedicated VM** (Hyper-V / VirtualBox / VMware). Generation 2 Hyper-V, Windows x64 guest to match the bundle target.
2. **Network: isolated.** Attach to a Hyper-V **Internal/Private virtual switch** with no uplink, or disable the vNIC entirely. If advisory-DB refresh is ever needed inside, do it via a *temporary* connection, then revert to isolated. Default state = no egress.
3. **Snapshot / checkpoint baseline.** Take a clean checkpoint *before* any untrusted file touches the VM. **Revert to it after each sample set** (or at minimum daily). This is the disposability that makes a parser exploit non-persistent.
4. **Least privilege.** Run the scanner under a **standard (non-admin) account**. The bundled `pwsh` and tools require no system installation.
5. **Disable convenience bridges to the host:** turn off clipboard sharing, drive/folder redirection, and shared folders in the VM integration settings. These are exfil/escape paths.
6. **Resource caps.** Cap vCPU/RAM and disk so a decompression bomb or runaway parser can't exhaust the *host*. Pair those controls with the engine's archive budgets and per-analyzer timeouts.
7. **File ingress and working copy.** Deliver submissions through a **read-only** channel, such as a read-only ISO/VHD built on the dev host. Copy them inside the disposable VM to a writable working directory such as `D:\scan-work\submission`; the scanner writes `.reports\` inside the scan root and therefore cannot scan directly from read-only media. Avoid writable host shares. Export only the completed `.reports\` directory through a separate controlled channel.

**Per-run workflow:**

```
1. (host)  Build read-only media containing the submission set.
2. (VM)    Revert to clean checkpoint.
3. (VM)    Mount submission media read-only.
4. (VM)    Copy the submission to a writable directory inside the disposable VM.
5. (VM)    Scan that working copy -> <scan-root>\.reports\ (JSON + HTML + slim TXT).
6. (VM)    Export only .reports\ through a separate controlled channel.
7. (host)  Review reports and AV/EDR alerts; triage findings.
8. (VM)    Revert to the clean checkpoint (discard the VM state).
```

**Patching.** Keep the bundled `pwsh`/.NET and every analyzer current. An
out-of-date parser is the most likely thing a hostile file would target. Rebuild
the bundle on the development host and re-deliver it to the VM via read-only
media.

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

### Application Control / Smart App Control blocks the scanner's own tools

Distinct from AV, and easy to misread. On a host enforcing **Smart App Control**
(default on many clean Windows 11 installs) or a WDAC/AppLocker policy, Windows
refuses to *start* unsigned binaries with no established reputation. The pip
console shims the scanner provisions — `bandit.exe`, `detect-secrets.exe`,
`shellcheck.exe`, `pip-audit.exe` — are exactly that, whether they come from a
live `pip install` or from the offline bundle's vendored venv:

```
An error occurred trying to start process '...\Scripts\bandit.exe'.
An Application Control policy has blocked this file.
```

Check the host with:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState
```

`0` = off, `1` = enforcing, `2` = evaluation.

**Why it matters:** the decision is a per-binary reputation lookup, so it is not
all-or-nothing — one tool in a venv can be blocked while its neighbour runs, and
the same tool can be blocked on one run and allowed on the next. That makes it
look like intermittent flakiness rather than a policy.

The scanner reports this rather than hiding it: a tool that cannot be started
produces **`MTS-TOOL-BLOCKED` (HIGH)**, stating that the unit was *not* analyzed.
Treat that as lost coverage, never as a clean result. To fix it properly, run the
scanner on a host where the policy permits the tool binaries (an isolated review
VM with Smart App Control off), or sign the vendored venv's binaries.

The Pester suite applies the same rule: `tests/TestTools.ps1` probes each
deep-tier binary before asserting on it and **skips loudly with the reason** when
the host cannot run it, so a policy block is never mistaken for a code
regression. Set `MTS_REQUIRE_DEEP_TOOLS=1` to turn that skip into a hard failure
on hosts and CI runners where the tools are expected to run.

---

## Dev host — what it needs

For building and running the **trusted fixture** suite (no untrusted files here):

- **PowerShell 7.4+** (`pwsh`) — the tool is PS 7-only.
- **Python 3.x** (for `build_fixtures.py` and the analyzer helpers' venv).
- **Pester 5.7.1** and **git**.

The dev host never sees real untrusted transfers — only the deterministic synthetic corpus under `tests/fixtures/`, which is safe by construction.
