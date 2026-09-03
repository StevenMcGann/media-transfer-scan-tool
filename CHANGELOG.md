# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/). The public schema/CLI contract
has been frozen since package v0.9.0. Package **v1.0.0 marks completion of isolated-host
validation against real untrusted transfers**, not a second contract freeze (see [PLAN.md](PLAN.md)).

## [Unreleased]

### Added
- Added a scan-wide, resource-bounded metadata-only dependency fallback for
  ZIP, wheel, NuGet, TAR, and TGZ containers that cannot be normally extracted
  without exceeding the shared archive-tree budget ([#39](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/39)).
- The fallback reads recognized dependency manifests without writing payloads
  to the staging tree, recursively inspects bounded nested containers, audits
  exact wheel/package identities and dependencies through the shared OSV client,
  and reports partial, limited, malformed, encrypted/unreadable, duplicate, and
  otherwise skipped coverage explicitly.
- Added shared parsers for wheel `METADATA`/`PKG-INFO`, `requirements*.txt`, npm
  lock/shrinkwrap files, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`,
  `uv.lock`, and `.nuspec` metadata. The normal and fallback paths use the same
  parser semantics, and non-exact dependency declarations remain visible as
  unaudited rather than being guessed.

### Changed
- Corrected pyproject dependency-array parsing so quoted extras, marker quotes,
  and comments cannot truncate the array; unsupported/malformed arrays now
  produce an explicit coverage finding.
- Included standard `[project.optional-dependencies]` groups in both manifest
  scan paths and report each unresolved Poetry/uv package block, even when
  other blocks contain valid identities.
- Recognized canonical `EGG-INFO/PKG-INFO` package identities in both normally
  extracted eggs and the bounded archive-metadata fallback.
- Added full-suite CI validation on the operator bundle's pinned PowerShell
  runtime, alongside the GitHub-hosted runtime.
- Reconciled the README, operator guide, test-environment runbook, public
  contract, maintainer guide, bundle guide, and roadmap with v0.13.0 behavior.
- Clarified writable scan-root requirements, source archives versus operator
  bundles, explicit offline-mode behavior, INFO-only overall-risk semantics,
  archive coverage-gap findings, and exit code 5.
- Updated the bundled PowerShell 7.4 LTS pin from 7.4.6 to 7.4.19.
- Pinned the maintainer and CI test path to Pester 5.7.1 so Pester 6 is not
  selected by an open-ended minimum-version constraint.
- Corrected the test runner to select Pester 5.7.1 exactly when a GitHub-hosted
  runner also exposes a newer Pester 5 release.
- Made the documented local Pester command return a nonzero process exit code
  on failures; XML test-result output remains specific to `-CI` runs.
- Enforced CRLF and ASCII-safe comments for `Scan.cmd` so the Windows operator
  entry point is parsed consistently outside GitHub Actions checkouts.
- Corrected offline provisioning so it no longer runs the pip/setuptools/wheel
  bootstrap upgrade before reporting unavailable tools.
- Made generated `.tgz` fixtures byte-for-byte reproducible by fixing the gzip
  header timestamp as well as each tar member timestamp.
- Clarified that online mode provisions missing pinned tools automatically and
  `-AutoInstall` remains only as a compatibility switch.
- Removed the obsolete pre-project planning transcript and replaced the
  pre-v0.1 roadmap with a current plan.

## [0.13.0] - 2026-08-29

> This section records the final release behavior first, followed by detailed
> engineering provenance from the review rounds. Every defect described in the
> review chronology was fixed before the v0.13.0 tag; it is not a list of known
> remaining defects.

### Added
- **Recursive archive-member dispatch** ([#31](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/31)).
  Contents of a generic `archive` unit (`.zip`, `.tgz`/`.tar.gz`) were previously
  only inspected for npm content (`NpmScan`) and model content
  (`PickleOpcodeScan`) — anything else extracted from a ZIP was never analyzed,
  and nothing said so. Every extracted member is now classified by content
  (`New-Unit`, reused as-is — a disguised script hiding behind an innocent
  extension, e.g. `payload.txt`, is caught for free) and dispatched through the
  full analyzer set (`Invoke-UnitDispatch`, factored out of the top-level scan
  loop for reuse), with findings folded onto the PARENT archive using the
  existing `archive!inner/path` label — members are never added as new
  top-level `Units`, so the v1 JSON schema and unit counts are unchanged.
  - A nested archive is extracted the same hardened way (zip-slip/
    decompression-bomb/symlink guards run before every extraction, at every
    depth) and recursed into, subject to a depth cap (default 5) and a
    cumulative member-count/byte budget (default 5000 members / 1GB) **shared
    across the whole scan run**, not reset per archive — many individually-small
    archives can't bypass the cap by splitting content across them. Exceeding
    either produces an explicit `MTS-ARCHIVE-DEPTH-CAP` /
    `MTS-ARCHIVE-BUDGET-EXCEEDED` finding naming the skipped member(s).
  - A member with no type-specific analyzer coverage is not given its own
    finding (that would be one warning per README/data file in a large
    archive) — uncovered members are aggregated into one
    `MTS-ARCHIVE-MEMBER-UNINSPECTED` INFO finding per parent archive, so a
    disabled or unsupported type never silently reads as "reviewed and clean".
  - Semantic containers (wheels/eggs, `.nupkg`, PyTorch `.pt/.pth`) are
    extracted but NOT member-dispatched — their existing whole-staging-tree
    analyzer (PythonRules/PipAudit/OsvScan/PickleOpcodeScan) already covers
    them, and recursing further would duplicate those findings. `NpmScan`,
    `PickleOpcodeScan`, and `OsvScan`'s old generic-`archive` whole-tree walks
    are removed (now redundant with, and would have duplicated, member
    dispatch's own per-member findings for the same files).
  - `MTS-EXTRACT-NESTED`'s wording no longer claims nested content is "scanned
    at top level only" — it now is opened and scanned, recursively.
  - Four rounds of independent review on the initial implementation found the
    budget/depth enforcement above checked too LATE, after the disk cost it
    was meant to prevent had already been paid, plus two coverage gaps and a
    double-counting bug:
    - The depth cap and shared byte budget are now checked **before**
      extracting a nested archive, not after — a would-be-too-deep or
      would-overflow archive is hashed but never decompressed.
    - The per-member byte check is now look-ahead
      (`ExpandedBytes + memberSize > MaxBytes`, checked before acceptance)
      instead of post-hoc, so the one member that crosses the cap can no
      longer slip through.
    - The top-level pre-extraction budget check is now also look-ahead — it
      estimates an archive's uncompressed size from its ZIP central
      directory (no extraction needed) and blocks it if that estimate
      exceeds remaining headroom, rather than only blocking once the budget
      was already fully exhausted. Falls back to a conservative 10MB
      safe-headroom threshold for tar/tgz, which has no equivalent cheap
      index.
    - A nested semantic container's (wheel/`.nupkg`) EXPANDED size is
      estimated from its own ZIP central directory and weighed against
      remaining headroom BEFORE it is extracted — not measured and charged
      after the fact, which let a zip bundling large wheels finish over
      budget (once by up to the compressed member's own size, and again
      when the earliest version of this fix still measured post-extraction)
      with no finding to show for it.
    - The budget/depth gates now key on the classified unit `Type ==
      'archive'` specifically, not "is a ZIP-format file" — a semantic
      container (wheel/egg/`.nupkg`) is never member-dispatched and does not
      itself consume this budget, so a TOP-LEVEL one must always be allowed
      to extract regardless of budget state (it's the unit's entire content,
      not one member among many). Gating on the broader check had silently
      broken `PythonRules`/`PipAudit` and NuGet `.nuspec` parsing for any
      submission after an earlier, unrelated generic archive had already
      used up the shared budget. A NESTED semantic container (one member
      inside an already budget-constrained parent archive) is still subject
      to the same look-ahead gate as a nested generic archive — see above.
    - `.bin`, `.h5`, `.hdf5`, `.pb`, `.onnx`, `.npy`, and `.npz` are now
      recognized as `model` type in `Classify.ps1`'s extension map.
      `PickleOpcodeScan`'s removed whole-archive walk used to cover these
      extensions; member dispatch only routes what the classifier recognizes
      as `model`, so a malicious pickle stored under e.g. `model.bin` inside
      a ZIP was silently missed until this was added.
    - Tarball (`.tgz`/`.tar.gz`) extraction is now streamed entry-by-entry via
      .NET's `System.Formats.Tar` — no external `tar` binary or Python
      fallback — checking the shared budget before writing EACH entry and
      stopping partway through (with an explicit `MTS-ARCHIVE-BUDGET-EXCEEDED`
      finding) rather than writing everything before any accounting could
      run. A tar's uncompressed size can't be read upfront the way a ZIP's
      central directory allows, so bulk extraction (the previous `tar -xzf`/
      Python `tarfile.extractall()` approach) was the one remaining path
      where a highly-compressible nested tarball could consume unbounded
      disk regardless of how tight the budget was. Also closes a pre-existing
      gap the ZIP path already had: a per-archive aggregate size cap and
      entry-count cap now apply to tarballs too (no per-entry compression
      ratio exists for a tar — the whole stream is one continuous gzip, not
      independently-compressed entries like ZIP).
    - The tar streaming extraction above and `Invoke-ArchiveMemberDispatch`'s
      per-member loop were both charging the shared budget for the same
      extracted files — once as each tar entry was written to disk, and again
      when dispatch walked those same files afterward. A tarball at or near
      the member/byte cap could have its budget exhausted by the extraction-
      time charge alone, so dispatch's own look-ahead check then skipped
      members that were already safely on disk — under-analyzing content the
      configured limits were meant to allow, not enforcing them correctly.
      Tar streaming now only *reads* the budget (a snapshot of remaining
      headroom, to decide when to stop writing) and never mutates it;
      `Invoke-ArchiveMemberDispatch` remains the sole point that charges
      `MemberCount`/`ExpandedBytes`, exactly as it already does for
      ZIP-extracted members.
    - A fifth review round found two more gaps and a mis-scoped budget check:
      - Streamed tar extraction (round 3) could leave partially-extracted
        content behind in the staging directory when a HARD-block (traversal,
        the aggregate size/entry-count caps) or a stream-read error fired
        after earlier entries in the SAME tarball had already been written —
        `StagingPath` is never set on failure, so those bytes were never
        charged and the leftovers sat until the whole scan's staging root was
        removed. Every early-failure path in `Expand-TarArchive` now deletes
        any partial content before returning.
      - A semantic container (wheel/egg/`.nupkg`) that happened to be the
        LAST admitted member of its parent archive (`MemberCount` already at
        `MaxMembers`) was blocked by the nested-container look-ahead gate's
        member-COUNT check, even though semantic containers are never
        member-dispatched and their entries never consume `MemberCount` —
        only their estimated bytes do. Order-dependent loss of Python/NuGet
        coverage for content that would easily have fit the byte budget.
        `Test-ArchiveWouldExceedBudget` now takes a `-SkipCountCheck` switch,
        applied only for a semantic-container child.
      - `Get-ArchiveExpansionEstimate`'s ZIP central-directory read counted
        explicit directory entries alongside file entries, but
        `Invoke-ArchiveMemberDispatch`'s member loop walks
        `Get-ChildItem -File`, which never charges a directory to
        `MemberCount` — a ZIP with 2,501 files and 2,501 matching directory
        entries estimated 5,002 and could be rejected even though only 2,501
        members would ever actually be charged. The estimate now excludes
        entries whose name ends in `/`.
      - A nested semantic container's pre-extraction byte estimate (round 3)
        is precharged to the shared budget BEFORE `Expand-UnitInPlace` runs.
        If extraction then failed (zip-slip guard, bomb/ratio guard, a
        corrupt archive), nothing was written to disk but the precharge
        stayed — a crafted, always-rejected container could exhaust the
        shared byte budget with phantom bytes and no content to show for it.
        The precharge is now a reservation, rolled back if `StagingPath`
        never gets set.
    - Also root-caused a CI-only Pester failure (9 tests in
      `ArchiveMemberDispatch.Tests.ps1`, never reproduced across several
      earlier attempts on identical pwsh/fixtures): `$stagingRoot`
      (`Invoke-Scan`) was built directly from `$env:TEMP` and used verbatim
      as the prefix for `$file.FullName.Substring(...)` throughout
      `Invoke-ArchiveMemberDispatch`. On a host where `$env:TEMP` resolves
      through an 8.3 short name (confirmed on GitHub Actions
      `windows-latest` runners: `C:\Users\RUNNER~1\...` for
      `C:\Users\runneradmin\...`), `Get-ChildItem`'s `FullName` — always the
      long form when it enumerates — no longer shares a character-for-
      character prefix with `StagingPath`, silently truncating every
      archive-member inner path by the length difference and swallowing the
      tail of the archive's own staging-dir name (e.g. `zip`, `tgz`) into
      what should have been the member's inner path alone. `$stagingRoot` is
      now canonicalized once, right after creation, via
      `(Get-Item -LiteralPath $stagingRoot).FullName` (which expands an 8.3
      alias; `Resolve-Path` does not) — a regression test reproduces the
      exact failure by pointing `$env:TEMP` at a deliberately long-named
      directory for one `Invoke-Scan` call, verified failing against the
      pre-fix code.
    - A sixth review round found two more gaps, both in how the shared
      budget's blocking decisions were scoped:
      - A top-level semantic container (wheel/egg/`.nupkg`) always extracts
        regardless of the shared archive-tree budget — by design, since
        blocking it because an unrelated earlier generic archive used up the
        budget would silently break Python/NuGet coverage (round 2). But
        with nothing else gating this category, many top-level wheels/eggs/
        `.nupkg` files — each individually allowed up to the 512MB
        per-archive decompression-bomb cap — could cumulatively exhaust disk
        with no run-wide limit at all. Now bounded by a genuinely SEPARATE
        cumulative counter (`Budget.TopLevelSemanticBytes`) that only this
        category ever charges or is blocked by, so an unrelated archive
        elsewhere still can never starve this coverage — but the FIRST
        top-level semantic container in a scan is always exempt from this
        new gate too, unconditionally, preserving the exact original
        guarantee (tested against a budget configured with `MaxBytes`/
        `MaxMembers = 0`, not just one exhausted by prior activity).
      - `Invoke-ArchiveMemberDispatch`'s per-member loop `break`ed out of the
        ENTIRE remaining walk the moment one member's own size didn't fit
        the remaining byte headroom, treating every member after it as
        skipped too — even a much smaller one that would easily have fit on
        its own. An attacker could place one oversized benign member right
        before a small malicious script to keep that script from ever being
        analyzed while budget remained. The member-count exhaustion check
        (once hit, truly a dead end — count only grows) still skips the
        whole remaining suffix in one go; an individual byte-budget miss now
        `continue`s past just that one member instead.
    - A seventh review round, on the sixth's own fix: the new
      `Budget.TopLevelSemanticBytes` tracking was added ALONGSIDE the
      pre-existing charge to the SHARED `Budget.ExpandedBytes`, not instead
      of it — so a top-level wheel/egg/`.nupkg` scanned before a generic
      archive still consumed the shared budget that gates GENERIC archives,
      making a later archive's coverage depend on filesystem enumeration
      order despite the whole point of the new counter being independence
      from this category. The shared-budget charge for a top-level semantic
      container's expanded size is removed; only `TopLevelSemanticBytes`
      charges now.
    - An eighth review round found two more gaps in the same area:
      - `Expand-TarArchive`'s per-entry streaming loop had the same
        break-vs-continue mistake as `Invoke-ArchiveMemberDispatch`'s
        per-member loop above: a per-entry byte miss `break`ed the WHOLE
        remaining stream, even though a later, smaller entry would still fit
        within remaining headroom on its own. A byte miss now only skips
        that one entry and keeps reading subsequent headers; the entry-count
        exhaustion check (a true dead end once hit) still stops the stream
        entirely.
      - The cumulative top-level semantic-container gate (this round's #6)
        checked bytes only. A package built mostly from empty files or
        directory entries estimates near-zero bytes regardless of how many
        real filesystem entries it creates — the byte gate never tripped,
        and each package's own 50,000-entry cap
        (`Test-ZipArchiveHazards`) is per-archive, not cumulative, so many
        such packages could still exhaust inodes despite the run-wide byte
        limit. A parallel `Budget.TopLevelSemanticEntries` counter, capped
        against `$script:ArchiveTreeMaxMembers`, now gates alongside bytes —
        same "first container always exempt" rule as before.
    - A ninth review round found the two remaining holes in that accounting:
      - Extraction writes a whole archive at once, so every member is
        already on disk before the member loop runs — only ANALYSIS is
        per-member. A member the budget refused was left in place:
        uncharged content still occupying disk. Combined with a nested
        semantic container's separately-charged expansion, the retained
        parent siblings could push real disk usage past the run-wide cap by
        nearly a full per-archive allowance. A refused member is now deleted
        from staging, restoring the invariant the budget exists to enforce —
        everything still staged has been charged for. (Safe: the parent
        unit's own analyzers run against `StagingPath` before member
        dispatch, and a refused member is by definition never dispatched or
        recursed into.)
      - The cumulative semantic-container entry cap counted FILES only, on
        both sides — `Get-ArchiveExpansionEstimate` excludes directory
        entries (correct for the generic-archive member count, which walks
        `Get-ChildItem -File`) and the post-extraction charge used `-File`
        too. A wheel/egg/`.nupkg` built purely from explicit directory
        entries therefore measured zero bytes AND zero entries, so neither
        gate ever activated while it still created arbitrarily many
        directories. The estimate now also reports `TotalEntries` (every
        entry, directories included), the top-level semantic gate compares
        against that via a new `-CountAllEntries` switch, and the charge
        counts extracted directories too — an inode bound measured in
        inodes, not in dispatchable files.
    - A tenth review round closed the same inode gap for NESTED semantic
      containers (a wheel/egg/`.nupkg` found as a member of a generic
      archive). Those charge their expanded bytes to the shared budget, but
      their internal entries were counted nowhere: the outer member loop
      charges the container as exactly ONE member however many entries it
      holds, and `Test-ZipArchiveHazards`' 50,000-entry limit resets per
      package — so a submission comfortably inside the byte cap could still
      stage millions of inodes. A `Budget.NestedSemanticEntries` pool now
      gates and charges them (`TotalEntries`, directories included, reserved
      before extraction and rolled back if it fails), kept separate from
      `MemberCount` so a semantic container is still never blocked merely
      because the dispatchable-member count is exhausted.
    - An eleventh review round closed the last two ways staged inodes could
      go uncounted — both cases where the entry accounting measured archive
      RECORDS rather than the filesystem entries extraction actually
      creates:
      - `Get-ArchiveExpansionEstimate`'s `TotalEntries` counted
        central-directory records, but `ExtractToDirectory` materializes
        every missing parent directory: one record for `a/b/c/payload.py`
        creates four inodes. A handful of deep paths could reserve one entry
        each while staging hundreds of directories. `TotalEntries` now
        counts files plus every distinct directory in their paths (implicit
        ancestors included, each shared ancestor counted once).
      - `Expand-TarArchive` incremented its budget counters for FILE entries
        only, while still creating every directory entry — and nothing
        downstream charged those either, since `MemberCount` counts
        dispatchable members and member dispatch enumerates
        `Get-ChildItem -File`. A directory-only tarball consumed no budget
        at all, and the per-archive 50,000-entry cap resets per tarball.
        Directory entries now consume the tar entry budget, and a new
        run-wide `Budget.StagedDirectories` counter — charged after every
        successful extraction and subtracted from the count headroom
        wherever an extraction is gated — makes the bound cumulative across
        archives rather than resetting for each one.

### Security
- **Detail-fetch loop could out-stall a flapping (not fully down) OSV
  endpoint** — the 0.12.0 fix above bounded `Get-OsvDependencyFindings`'s
  `GET /v1/vulns/{id}` loop with `-MaxConsecutiveFailures`, but that counter
  resets to 0 on every success (correct for its own purpose — a genuinely
  flaky-but-working endpoint shouldn't be treated as down). An endpoint that
  *alternates* failure/success never trips it, so a manifest resolving to
  many distinct advisories could still hold the scan for
  `uniqueIds.Count * TimeoutSec` with no upper bound. Added a second,
  independent `-MaxDetailFetches` parameter (default 500) capping total
  fetch *attempts* regardless of outcome; the consecutive-failure check is
  unchanged. Reaching either cap stops the loop the same way — remaining
  advisories reported as a coverage-gap finding, already-confirmed
  vulnerabilities still reported via the existing "detail unavailable"
  fallback, none silently dropped. Caught by independent review of #36
  after the 0.12.0 fix; regression test added (fail/succeed/fail/succeed/
  succeed against a 3-fetch cap, verified against the pre-fix code).

## [0.12.0] - 2026-08-28

### Security
- **NuGet identity spoofing via a nested decoy `<metadata>` block** — a
  `.nupkg` with exactly one root `.nuspec` (so it passes the existing
  multi-root-`.nuspec` ambiguity check) could still hide its real identity: the
  previous document-wide `//` XPath search matched the *first* `<metadata>`
  found anywhere in the file, in document order, so a decoy nested inside an
  unrelated wrapper element ahead of the real `<package><metadata>` was
  resolved instead — the package's real, possibly-vulnerable identity was
  never queried against OSV. `Get-NuGetDep` (`src/analyzers/OsvScan.ps1`) now
  reads only `<package>`'s direct-child `<metadata>`, and rejects (rather than
  guesses at) an unexpected shape — more than one `<metadata>`, or more than
  one `<id>`/`<version>` within it — the same fail-closed posture already
  applied to the multi-nuspec-file case. PoC verified before the fix, and a
  regression fixture (`nuget/nested_decoy`) added.
- **Unbounded per-advisory detail-fetch loop** — `Get-OsvDependencyFindings`
  (`src/lib/Osv.ps1`) bounds retries on the `POST /v1/querybatch` chunk loop
  after repeated consecutive failures, but the separate sequential
  `GET /v1/vulns/{id}` detail fetch (one call per distinct advisory) had no
  such bound. A manifest resolving to many distinct advisories during a
  detail-endpoint outage could hold an online scan for
  `uniqueIds.Count * TimeoutSec`. Now bounded by the same
  `-MaxConsecutiveFailures` parameter; a vulnerability already confirmed by
  querybatch still produces a finding via the existing "detail unavailable"
  fallback when the fetch stops early — none are silently dropped — and the
  skipped advisories are reported as an explicit coverage-gap finding, grouped
  by manifest. The stopped-early message also now reads "were skipped without
  an attempt (not just failed)" rather than the more ambiguous "were not
  fetched", to distinguish never-attempted advisories from attempted-and-failed
  ones (only the former count toward the reported number).

Both findings were caught by independent review of #33/#32 after it shipped
in 0.11.0; neither had a live exploit reported. Regression coverage added:
`nuget/nested_decoy` (plus direct fixtures for the new fail-closed shape
checks — two root `<metadata>` elements, a duplicate `<id>`, a missing
`<version>`) and a mocked failure→success→failure detail-fetch test.

## [0.11.0] - 2026-08-27

### Added
- **OSV.dev dependency-vulnerability audit — PyPI, npm, NuGet** ([#32](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/32)).
  New **`OsvScan`** analyzer (core, default-on — this tool always has network
  access to the connected/staging host, so the audit runs by default rather
  than opt-in): batch-queries `POST /v1/querybatch` and resolves every
  distinct advisory to full detail via `GET /v1/vulns/{id}` (severity,
  summary, fixed versions), scored with a real CVSS v3.1 base-score
  calculator plus a `database_specific.severity`/keyword fallback — not a
  flat severity for every hit.
  - **New `python-requirements` unit type** for a loose `requirements.txt`
    (its own type, not `python` — the Python-source analyzers must never
    parse it as source). Exact `==` pins are PEP 503-normalized and queried;
    a range, bare name, compound specifier, or VCS/URL requirement is
    reported as an explicit `OSV-PYPI-UNPINNED` finding rather than silently
    skipped.
  - **New `nuget` unit type** for `.nupkg` (routed through the existing
    hardened ZIP extraction path — zip-slip/bomb guards apply); the package's
    own id/version is read from its embedded `.nuspec` (namespace-agnostic —
    the schema URI varies by NuGet client version) and checked against OSV,
    since the artifact itself *is* the pinned dependency.
  - **npm** (`package-lock.json`, schema v1/v2/v3) moves from `NpmScan`'s old
    id-list-only layer into `OsvScan`, gaining the same full-detail scoring.
  - Shared query/scoring/PEP-503 logic lives in `src/lib/Osv.ps1` so every
    ecosystem — and any future one — reports the same way.
  - Adding two `UnitType` values is non-breaking under
    [docs/contract.md](docs/contract.md) §1.

### Fixed
- **`Finding.File` now carries the audited unit's path everywhere, not a
  `"dependency: name version"` descriptor.** `docs/contract.md` §1 defines
  `File` as a relative path; `PipAudit`'s CVE findings put a dependency label
  there instead. The dependency identity moved into `Issue`
  (`"Dependency 'name version': CVE-...: ..."`), matching the convention
  `OsvScan` uses. This also restores traceability when `Requires-Dist` is read
  from more than one wheel in a single scan.

## [0.10.0] - 2026-08-21

### Added
- **VB-family support — standalone VBA and VBScript** ([#25](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/25)).
  Embedded Office macros were already covered by `OleVbaScan`, but a VB module or
  script sitting loose in a submission classified as `unsupported` and was never
  analyzed: a `.bas` containing `Auto_Open` + `URLDownloadToFile` + `Shell` produced
  a SHA-256 line and nothing else. The same was true of `.vbs`/`.hta`, which matter
  more — a `.vbs` executes on double-click, an exported module does not.
  - **New `vba` unit type** covering `.bas .cls .frm .vba` and `.vbs .vbe .wsf .hta`.
    Adding a `UnitType` value is explicitly non-breaking under
    [docs/contract.md](docs/contract.md) §1.
  - **New `VbaRules` analyzer** (core, default-on): auto-exec entry points, shell and
    process launch, download primitives, native `Declare … Lib` imports, shellcode
    APIs (`VirtualAlloc`/`RtlMoveMemory`, CRITICAL), registry persistence, hidden or
    encoded PowerShell, and obfuscation (`Chr()` chains, `StrReverse`, `CallByName`).
    Combinations that only make sense in a dropper — download+execute, auto-exec+payload
    — escalate to CRITICAL, following the `PythonRules` precedent.
  - **Pure PowerShell**: no Python helper and no pip package, so unlike the Office path
    (which degrades to `OFFICE-OLEVBA-UNAVAIL` without oletools) this works air-gapped
    with zero provisioning.
  - **Disguise detection extended to VB**: a VBA module saved as `notes.txt` is now
    detected by content signature and raises `MTS-DISGUISE-002`, then gets the full
    rule pass. The signatures are deliberately VB-exclusive (`Sub`, never `Function`)
    so they cannot steal units from the JavaScript, batch, or PowerShell paths.
  - `.vbe` (Script Encoder output) reports `VBA-ENCODED-SOURCE` rather than a clean
    result — it is obfuscated by design and cannot be read statically.
  - Embedded Office macros are unchanged and stay with `OleVbaScan`. Running these
    rules over module source extracted from a container is a follow-up.

### Changed
- **A blocked external tool is now reported, not silent: `MTS-TOOL-BLOCKED` (HIGH).**
  On a host enforcing Application Control / Smart App Control, Windows refuses to
  start the unsigned pip console shims the scanner provisions (`bandit.exe`,
  `detect-secrets.exe`, `shellcheck.exe`, …). Previously `Invoke-BoundedProcess`
  threw, each analyzer caught it into a **LOW** `MTS-*-ERR`, and the practical
  result was a report that read as "this tool found nothing" when the tool never
  ran. `Invoke-BoundedProcess` now returns `Started`/`StartError` instead of
  throwing, and analyzers emit a HIGH finding saying the unit was **NOT** analyzed
  — the same treatment `MTS-ANALYZER-TIMEOUT` already got, for the same reason.
  `PythonRules` is unchanged: it already degrades to its regex fallback.
  See [docs/test-environment.md](docs/test-environment.md) for how to detect and
  clear the policy.
- **No silent coverage gaps: `MTS-NO-ANALYZER` (INFO).** A unit that no enabled
  analyzer claims — `unsupported` files, and `batch` units, which have never had an
  analyzer — now carries an explicit INFO finding saying it was hashed and listed but
  not inspected. Previously such a file produced only a hash line, which reads in a
  report as "reviewed, clean" when it means "never looked at."
  **Consumer impact:** `TotalFindings` rises on submissions containing ordinary
  unanalyzed files. Severity is INFO, so overall risk and exit codes are unaffected.
  **Known limitation:** this answers "did any analyzer claim this *unit*", not "was
  the content *inside* an archive inspected". A generic archive's contents are only
  inspected for npm and model content, and that gap is not yet reported — inferring
  it from analyzer descriptors was attempted and reverted, because descriptors cannot
  distinguish an analyzer that declined from one that inspected, which produced false
  warnings on every clean wheel and notebook. Tracked separately.
- `docs/contract.md` now documents `batch` in the `Type` enum. It was always
  producible from `.bat`/`.cmd`; the omission was a documentation bug, not a change.

### Fixed
- **`.hta`/`.wsf` were wrongly assumed to be VB**, caught in review of #28 and fixed
  before release. They are language-neutral wrappers that host JScript as readily as
  VBScript, so routing them to `VbaRules` by extension meant a JScript dropper
  (`new ActiveXObject("WScript.Shell").Run(...)`) matched no VB rule, reported clean,
  *and* suppressed `MTS-NO-ANALYZER` because a VB analyzer had claimed the unit —
  silent and falsely reassuring. Such a wrapper now reports `VBA-NON-VB-SCRIPT`
  (MEDIUM) saying the embedded script was not inspected. Genuine VBScript wrappers
  are unaffected.
- **Flaky deep-tier tests.** `BanditSecrets` and `Notebook` tests failed
  intermittently — a different one each run, each passing in isolation. The cause
  was not a race or PyPI: Smart App Control was blocking `bandit.exe` per-binary by
  reputation, so the analyzer produced no findings and the assertion failed with no
  diagnostic. `tests/TestTools.ps1` now probes whether each deep-tier binary can
  actually be executed and skips loudly with the reason when it cannot, so a host
  policy is never mistaken for a code regression. `MTS_REQUIRE_DEEP_TOOLS=1` makes
  an un-runnable tool a hard failure for CI and release validation.
- **UNC scan roots no longer crash the scan** ([#27](https://github.com/StevenMcGann/media-transfer-scan-tool/issues/27)).
  `Resolve-Path ... .Path` returns a provider-qualified string for a network path
  (`Microsoft.PowerShell.Core\FileSystem::\\server\share\...`). That string is longer
  than the plain `FullName` of the files under it, so the length-based `Substring`
  that derived each unit's relative path threw
  `startIndex cannot be larger than length of string` and the scan aborted with exit
  code 2. Both resolution sites (`Invoke-MediaTransferScan.ps1`, `Invoke-Scan` in
  `lib/Engine.ps1`) now use `.ProviderPath`, and `New-Unit` computes the relative path
  with `[System.IO.Path]::GetRelativePath` instead of string-length arithmetic.
  `bundle/build-bundle.ps1` had the same `.Path` hazard for a UNC output dir and was
  fixed alongside. Covered by `tests/PathResolution.Tests.ps1`: UNC cases run against
  the local admin share and announce themselves loudly when it is unreachable
  (`MTS_REQUIRE_UNC_TESTS=1` turns that skip into a failure), plus an
  environment-independent source guard that fails if `Resolve-Path ... .Path` is
  reintroduced anywhere under `src/` or `bundle/`.

## [0.9.0] - 2026-06-06

### Added
- **PythonRules — curated, high-signal Python analysis (core, default-on).** The
  Python analogue of the PowerShell/shell risky-pattern layers: it reports ONLY
  attacker-grade indicators relevant to ingress — `eval`/`exec`/`compile`,
  dynamic import, `os.system`/`os.popen`, `subprocess(shell=True)`, `pickle`/
  `marshal`/unsafe-`yaml` loads, network fetch (`urllib`/`requests`/`socket`),
  base64/zlib decode, `ctypes` native loads — plus file-level **combination**
  escalations (download-and-run, decode-then-exec, reverse-shell, ctypes
  shellcode). It deliberately omits the broad code-quality findings of the
  deep-tier Bandit analyzer: the "middle tier" between blind and noisy.
  - Backed by `src/helpers/scan_python.py` (stdlib `ast`, no pip package): real
    call sites, not substrings — no false hits on trigger words in comments or
    strings, verified by fixtures. Runs under the bundled venv or system Python,
    so it works **offline / air-gapped**.
  - Pure-PowerShell regex fallback when no Python interpreter is present (marked
    LOW/`PY-RULES-DEGRADED`) so a scan is never fully blind.
- **Frozen the public contract** ahead of the 1.0.0 release: JSON report
  `schemaVersion` set to `1.0.0`; [docs/contract.md](docs/contract.md) documents the
  stable JSON schema, CLI surface, and exit codes, and what a breaking change is.
- **Operator guide** ([docs/operator-guide.md](docs/operator-guide.md)) — running the
  bundle (`Scan.cmd`), reading the report, severities, exit codes.
- **Maintainer guide** ([docs/maintainer-guide.md](docs/maintainer-guide.md)) — dev
  setup, tests, CI, bundle build, adding analyzers, release steps.
- **Defender/AMSI self-check** (`tools/verify-amsi.ps1`): on a Windows + Defender
  host, snapshots the threat-detection history, loads the full engine in a fresh
  `pwsh`, and fails if any new detection appears — guards against an offensive
  token leaking back into shipped source. Documented in the maintainer guide.
- *(Remaining for the 1.0.0 tag: operator validation on real untrusted transfers
  on the isolated host.)*

### Fixed
- **AMSI/EDR false positive on the scanner's own code.** The PowerShell analyzer's
  detection signatures (AMSI-tamper, Defender-preference, downloader,
  encoded-command) and the classifier's PowerShell content-signatures previously
  sat as contiguous literal strings in the engine source. Microsoft Defender's
  AMSI inspection scanned that source as `pwsh` loaded it and fired **“Possible
  AMSI tampering” (DefenseEvasion, High)** — a false positive triggered by our own
  patterns, which would also let on-disk file AV quarantine the analyzer. These
  tokens are now **assembled from fragments at runtime**, so the contiguous
  strings never appear in any shipped file (detection behavior is unchanged;
  verified by the full suite). See `docs/test-environment.md` → *AV / EDR on the
  review host* for the operator-side AV guidance this surfaced.

### Changed
- Bootstrapper: when a vendored venv is present it now passes `-VenvDir` but no
  longer force-sets `-Mode offline`. An online host running the bundle reuses the
  vendored tools *and* keeps live CVE coverage (pip-audit / OSV); air-gapped use
  selects `-Mode offline` explicitly.

### Security / CI
- Added a `security` workflow: PSScriptAnalyzer over `src/` (fails on Error
  severity; tuned via `PSScriptAnalyzerSettings.psd1`), gitleaks secret scanning,
  and CodeQL static analysis of the Python helpers. Weekly schedule + on push/PR.
- Added Dependabot for the `github-actions` ecosystem (keeps action versions
  current — removes the Node-runtime-deprecation treadmill).
- Cleaned the engine to a clean PSScriptAnalyzer run (removed dead variables,
  made best-effort `catch` blocks explicit).

## [0.8.0] - 2026-05-30

### Added
- **Archive hardening (v0.8):** ZIP-family archives are inspected BEFORE extraction
  and hard-blocked (never written to disk) on a hazard:
  - **Zip-slip / path traversal** (`..`, absolute, drive-rooted) → HARD block.
  - **Decompression bomb** → HARD block: per-entry ratio (>100× over a 10 MB floor),
    512 MB aggregate-uncompressed cap, and a 50k entry-count cap.
  - **Symlink entries** (unix `S_IFLNK` in external attributes) → flagged (MEDIUM).
  - **Nested archives** → flagged (LOW; scanned at top level only).
  - tar (`.tgz`/`.tar.gz`): a `tar -tzf` listing is checked for traversal before
    extraction; the Python tarfile fallback uses the secure PEP 706 `data` filter.

### Changed
- Path-traversal handling moved from advisory to a true pre-extraction block.

## [0.7.0] - 2026-05-30

### Added
- **Model / pickle analysis (v0.7):** `PickleOpcodeScan` (core) + `helpers/scan_pickle.py`
  on `model` units (`.pkl .pickle .pt .pth .bin .joblib .h5 .pb .onnx .safetensors
  .gguf .npy .npz`) and model files inside extracted archives.
  - **Pickle opcode triage** via `pickletools.genops` — walks the opcode stream
    and is NEVER unpickled (unpickling executes code). Flags `REDUCE` (the
    code-exec primitive, CRITICAL), `GLOBAL`/`STACK_GLOBAL` arbitrary imports, and
    dangerous modules (`os`/`nt`/`subprocess`/`builtins`/...) as CRITICAL.
  - **Safe-format recognition:** safetensors and GGUF cleared as safe-by-design.
  - **Embedded pickles:** PyTorch `.pt`/`.pth` ZIP containers are opened and their
    `data.pkl` scanned; `.pt` is routed to `model` (not generic archive).
- Classifier: `model` added to the ZIP-container types (PyTorch `.pt` is a ZIP).

## [0.6.0] - 2026-05-30

### Added
- **npm analysis (v0.6):** `NpmScan` (core, dependency-free core) on `npm` units
  (loose `package.json` / `.js` / `.ts`) and extracted `.tgz` tarballs:
  1. **package.json lifecycle scripts** — `preinstall`/`install`/`postinstall`
     (run on `npm install`, the #1 npm supply-chain vector) flagged HIGH; their
     command strings inspected for risky tooling; `prepare`/`prepublish` MEDIUM;
     `bin` shims noted.
  2. **JavaScript risky patterns** — `child_process`/`exec`/`spawn`, `eval()`,
     `Function()` constructor, long hex-escape obfuscation.
  3. **OSV dependency audit** (online, no tool install — OSV.dev REST API): when a
     `package-lock.json` with exact versions is present, batch-queries OSV for
     known vulnerabilities. Offline / no lockfile → coverage-gap note.
- Classifier: `package.json` / `package-lock.json` routed to `npm` by filename;
  `.ts` added to npm extensions.

## [0.5.0] - 2026-05-30

### Added
- **PowerShell analysis (v0.5):** three-layer static analysis on `.ps1`/`.psm1`/`.psd1`
  units and PowerShell content detected via the classifier:
  1. **PSScriptAnalyzer** (PS module, installed on demand online / vendored offline):
     structural + security rules.
  2. **Custom risky-pattern rules** (always run): `IEX`/`Invoke-Expression`,
     `DownloadString`/`DownloadFile`, `-EncodedCommand`, `FromBase64String`,
     `-WindowStyle Hidden`, AMSI tampering, Defender preference tampering,
     `-ExecutionPolicy Bypass`.
  3. **Authenticode signature status** — `HashMismatch` (tampered signed file) is
     HIGH; valid/unsigned recorded as INFO.
- Provisioning: PS-module install-on-demand (online) via `Resolve-PsModuleTool`;
  the Python venv is now created **only when a pip-based analyzer is enabled**, so
  PowerShell-only scans no longer require Python.

### Changed
- Release titles are now the bare version (no descriptive suffix).

## [0.4.0] - 2026-05-29

Shell script analysis — ShellCheck + risky-pattern rules.

### Added
- **Shell script analysis (v0.4):** two-layer analysis on `.sh`/`.bash`/`.zsh`/`.ksh`
  units and shell content detected via the classifier (v0.2 disguised scripts):
  1. **ShellCheck** (via `shellcheck-py` pip package, which bundles the binary):
     full structural static analysis — quoting bugs, undefined variables, command
     injection, deprecated constructs (SC-coded findings).
  2. **Custom risky-pattern rules** (pure PowerShell, always runs): catches
     `curl|bash`, `base64 -d|bash`, `eval` with expansion, `chmod 777`, and
     hardcoded IPv4 addresses. These are intentionally not ShellCheck errors
     (syntactically valid shell) but operationally dangerous in a media-transfer
     context.

## [0.3.0] - 2026-05-29

Document analysis — Office + PDF triage.

### Added
- **Document analysis (v0.3) — Office + PDF:**
  - **PdfTriage** (core, pure PowerShell, no dependency): static keyword triage of
    PDFs — `/JS` `/JavaScript`, `/OpenAction` `/AA` `/Launch`, `/EmbeddedFile`,
    `/URI`, `/RichMedia`, and `/Encrypt` — with PDF name hex-escape de-obfuscation
    (`/#4A...`). Reading bytes only; never renders the PDF or runs JavaScript.
    Deliberately dependency-free to avoid a heavy PDF-parser attack surface.
  - **OleVbaScan** (core) + `helpers/scan_office.py`: Office triage via stdlib zip
    inspection (VBA `vbaProject.bin` presence, DDE/DDEAUTO fields, remote-template
    injection) plus deep VBA analysis (auto-exec / suspicious keywords) through
    `oletools` when available. Documents are parsed structurally — never opened in
    Office, never executed.
  - New finding categories `macro` / `active-content`; new analyzer test corpus
    (PDF + OOXML fixtures, generated by `build_fixtures.py`).

## [0.2.0] - 2026-05-29

Disguised-script detection — the first new file-type capability beyond Python parity.

### Added
- **Disguised-script detection (v0.2):** content-signature classification
  scores a file's text against PowerShell / Python / shell / batch
  signatures, catching a script hidden in an innocent extension (e.g. `.txt`,
  `.log`, `.dat`) with **no shebang** — the classic media-transfer evasion. The
  router uses the detected type (content over extension), emits a `disguised-file`
  finding (`MTS-DISGUISE-001/002`, severity scaled by how innocent the extension
  is), and dispatches the unit to the matching analyzer as those analyzers land.
  Includes a text-likeness gate (binaries skipped) and a ≥2-distinct-signature
  threshold so ordinary prose is not flagged. `.bat`/`.cmd` recognized as `batch`.

## [0.1.0] - 2026-05-29

First tagged release. Engine + full **Python** analyzer set + offline deployment.
Parity with `scan-python-packages` v1.6.1 on the new file-type-agnostic engine.

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
- **Deployment:** 5.1-safe `bootstrap.ps1` + `Scan.cmd` operator entry point that
  resolves PowerShell 7.4+ (bundled-authoritative → PATH → fail) and re-launches the
  engine; `-VenvDir` engine override; `bundle/build-bundle.ps1` offline-bundle builder
  (portable pwsh 7.4 LTS + scanner venv + manifest).
- Documented exit codes (0 clean / 10 findings / 2 error / 3 bad input / 4 no runtime).
- Test-environment runbook for isolated real-untrusted scanning ([docs/test-environment.md](docs/test-environment.md)).
- Project plan and feature roadmap ([PLAN.md](PLAN.md)).
- Pester suite (53 tests) + GitHub Actions CI on PowerShell 7.
