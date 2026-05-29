#!/usr/bin/env python3
"""Static triage of Office documents for macros / DDE / remote-template injection.

The document is parsed structurally and NEVER opened in Office or executed.
- OOXML (.docx/.xlsm/...) are ZIPs: inspected with stdlib zipfile for a VBA
  project, external (remote) template references, and DDE fields — these work
  even when oletools is unavailable.
- oletools (olevba) adds deep VBA analysis (auto-exec / suspicious keywords /
  IOCs) and legacy OLE (.doc/.xls) support when importable.

Output JSON: {file, format, valid, findings:[{severity,confidence,testId,issue,category}]}
Mirrors inspect_binary.py so the PowerShell analyzer reuses the same shape.
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path


def finding(severity, confidence, test_id, issue, category="macro"):
    return {"severity": severity, "confidence": confidence,
            "testId": test_id, "issue": issue, "category": category}


def inspect_ooxml(path: Path, findings: list) -> bool:
    """Stdlib-only checks on an OOXML zip. Returns True if it was a zip."""
    try:
        z = zipfile.ZipFile(path)
    except Exception:
        return False
    with z:
        names = z.namelist()

        # 1. VBA macro project present (macro-enabled document)
        vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if vba:
            findings.append(finding(
                "HIGH", "HIGH", "OFFICE-VBA-PRESENT",
                f"Document contains a VBA macro project ({vba[0]}) — macro-enabled.",
                "macro"))

        # 2. Remote template injection (external attachedTemplate)
        for n in names:
            if n.lower().endswith(".rels"):
                try:
                    data = z.read(n).decode("utf-8", "replace")
                except Exception:
                    continue
                if "attachedTemplate" in data and 'TargetMode="External"' in data:
                    m = re.search(r'attachedTemplate.*?Target="([^"]+)"', data, re.I | re.S)
                    target = m.group(1) if m else "?"
                    findings.append(finding(
                        "HIGH", "HIGH", "OFFICE-REMOTE-TEMPLATE",
                        f"Remote template injection: external attachedTemplate -> {target}",
                        "active-content"))

        # 3. DDE / DDEAUTO fields in the main document part
        for n in names:
            if n.lower() in ("word/document.xml", "word/document2.xml"):
                try:
                    data = z.read(n).decode("utf-8", "replace").upper()
                except Exception:
                    continue
                if "DDEAUTO" in data or "DDE " in data:
                    findings.append(finding(
                        "HIGH", "MEDIUM", "OFFICE-DDE",
                        "DDE/DDEAUTO field present — can execute external commands on open.",
                        "active-content"))
    return True


def analyze_with_olevba(path: Path, findings: list) -> None:
    """Deep VBA analysis via oletools, if importable."""
    try:
        from oletools.olevba import VBA_Parser
    except Exception:
        findings.append(finding(
            "INFO", "HIGH", "OFFICE-OLEVBA-UNAVAIL",
            "oletools not available — deep VBA keyword analysis skipped.",
            "parser"))
        return

    try:
        vp = VBA_Parser(str(path))
    except Exception as exc:
        findings.append(finding(
            "MEDIUM", "MEDIUM", "OFFICE-PARSE-FAIL",
            f"Document could not be parsed for macros (possibly encrypted): {exc}",
            "parser"))
        return

    sev_by_type = {
        "AutoExec": "HIGH", "Suspicious": "HIGH", "Dridex string": "HIGH",
        "IOC": "MEDIUM", "VBA obfuscated Strings": "MEDIUM",
        "Hex String": "LOW", "Base64 String": "LOW",
    }
    try:
        if vp.detect_vba_macros():
            for entry in (vp.analyze_macros() or []):
                # entry: (type, keyword, description)
                typ, keyword, desc = entry[0], entry[1], entry[2]
                sev = sev_by_type.get(typ, "MEDIUM")
                tid = "OFFICE-VBA-" + re.sub(r"[^A-Z0-9]+", "-", str(typ).upper()).strip("-")
                findings.append(finding(
                    sev, "MEDIUM", tid, f"VBA {typ}: {keyword} — {desc}", "macro"))
    except Exception as exc:
        findings.append(finding(
            "LOW", "LOW", "OFFICE-ANALYZE-ERR",
            f"olevba analysis error: {exc}", "parser"))
    finally:
        try:
            vp.close()
        except Exception:
            pass


def inspect(path: Path) -> dict:
    findings: list = []
    is_zip = inspect_ooxml(path, findings)
    analyze_with_olevba(path, findings)
    return {
        "file": str(path),
        "format": "OOXML" if is_zip else "OLE/other",
        "valid": True,
        "findings": findings,
    }


def main(argv: list) -> int:
    if len(argv) < 2 or len(argv) > 3:
        print(json.dumps({"error": "usage: scan_office.py <path> [output_json]"}))
        return 2
    path = Path(argv[1]).resolve()
    result = json.dumps(inspect(path), sort_keys=True)
    if len(argv) == 3:
        Path(argv[2]).write_text(result, encoding="utf-8")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
