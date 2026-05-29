#!/usr/bin/env python3
"""Static triage inspection for native Python package artifacts."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path


SUSPICIOUS_APIS = {
    "createremotethread": "process injection capability",
    "virtualallocex": "remote memory allocation capability",
    "writeprocessmemory": "remote process memory write capability",
    "openprocess": "process manipulation capability",
    "ntcreatethreadex": "native process injection capability",
    "setwindowshookex": "Windows hook injection capability",
    "queueuserapc": "APC injection capability",
    "rtlcreateuserthread": "native thread injection capability",
    "isdebuggerpresent": "anti-analysis capability",
    "checkremotedebuggerpresent": "anti-analysis capability",
    "ntqueryinformationprocess": "anti-analysis capability",
}
NETWORK_DLLS = {"ws2_32.dll", "winhttp.dll", "wininet.dll"}
SENSITIVE_APIS = {
    "regopenkeyex": "registry access capability",
    "credread": "credential access capability",
    "cryptunprotectdata": "DPAPI credential decryption capability",
}
NORMAL_PE_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".edata",
    ".idata", ".pdata", ".tls", ".CRT",
}
NORMAL_ELF_SECTIONS = {
    "", ".text", ".data", ".bss", ".rodata", ".symtab", ".strtab",
    ".dynsym", ".dynstr", ".plt", ".got", ".init", ".fini", ".eh_frame",
    ".dynamic", ".hash", ".gnu.hash", ".got.plt", ".init_array",
    ".fini_array", ".comment", ".shstrtab",
}


def finding(severity: str, confidence: str, test_id: str, issue: str) -> dict[str, str]:
    return {
        "severity": severity,
        "confidence": confidence,
        "testId": test_id,
        "issue": issue,
    }


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    ent = -sum((count / total) * math.log(count / total, 2) for count in counts if count)
    return ent if ent > 0.0 else 0.0


def is_normal_elf_section(name: str) -> bool:
    return (
        name in NORMAL_ELF_SECTIONS
        or name.startswith(".rel.")
        or name.startswith(".rela.")
        or name.startswith(".note.")
    )


def invalid_result(path: Path, expected: str) -> dict[str, object]:
    suffix = path.suffix.lower() or "native"
    return {
        "file": str(path),
        "format": "UNKNOWN",
        "valid": False,
        "findings": [
            finding(
                "HIGH",
                "HIGH",
                "BINARY-INVALID-FORMAT",
                f"File has {suffix} extension but is not a valid {expected} binary - may be disguised or corrupt",
            )
        ],
    }


def inspect_pe(path: Path) -> dict[str, object]:
    try:
        import pefile
    except Exception as exc:  # pragma: no cover - exercised by PowerShell degradation path
        raise RuntimeError(f"pefile import failed: {exc}") from exc

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception:
        return invalid_result(path, "PE")

    result: dict[str, object] = {
        "file": str(path),
        "format": "PE",
        "valid": True,
        "signed": False,
        "sections": [],
        "imports": {},
        "findings": [],
    }
    findings = result["findings"]

    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    result["signed"] = bool(security_dir.VirtualAddress and security_dir.Size)

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")
        section_entropy = round(entropy(section.get_data()), 2)
        suspicious = section_entropy > 7.0 or name not in NORMAL_PE_SECTIONS
        result["sections"].append({"name": name, "entropy": section_entropy, "suspicious": suspicious})
        if section_entropy > 7.0:
            findings.append(
                finding(
                    "MEDIUM",
                    "MEDIUM",
                    "BINARY-HIGH-ENTROPY",
                    f"Section '{name}' has entropy {section_entropy} (threshold 7.0) - possible packing or encryption",
                )
            )
        if name not in NORMAL_PE_SECTIONS:
            findings.append(
                finding(
                    "LOW",
                    "MEDIUM",
                    "BINARY-UNUSUAL-SECTION",
                    f"Section '{name}' has a non-standard PE section name",
                )
            )

    imports: dict[str, list[str]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", "replace").lower()
        funcs: list[str] = []
        for imported in entry.imports:
            if imported.name:
                funcs.append(imported.name.decode("utf-8", "replace"))
            elif imported.ordinal is not None:
                funcs.append(f"ordinal_{imported.ordinal}")
        imports[dll] = funcs

        if dll in NETWORK_DLLS:
            findings.append(
                finding(
                    "MEDIUM",
                    "MEDIUM",
                    "BINARY-NETWORK-IMPORT",
                    f"Unexpected network import library: {dll}",
                )
            )
        for func in funcs:
            func_key = func.lower()
            if func_key in SUSPICIOUS_APIS:
                findings.append(
                    finding(
                        "HIGH",
                        "HIGH",
                        "BINARY-SUSPICIOUS-IMPORT",
                        f"Suspicious import: {func} from {dll} ({SUSPICIOUS_APIS[func_key]})",
                    )
                )
            if func_key in SENSITIVE_APIS:
                findings.append(
                    finding(
                        "MEDIUM",
                        "MEDIUM",
                        "BINARY-SENSITIVE-IMPORT",
                        f"Sensitive import: {func} from {dll} ({SENSITIVE_APIS[func_key]})",
                    )
                )
    result["imports"] = imports
    return result


def inspect_elf(path: Path) -> dict[str, object]:
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
    except Exception as exc:  # pragma: no cover - exercised by PowerShell degradation path
        raise RuntimeError(f"pyelftools import failed: {exc}") from exc

    try:
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            result: dict[str, object] = {
                "file": str(path),
                "format": "ELF",
                "valid": True,
                "sections": [],
                "imports": {},
                "findings": [],
            }
            findings = result["findings"]

            for section in elf.iter_sections():
                name = section.name
                data = section.data() if section.header["sh_type"] != "SHT_NOBITS" else b""
                section_entropy = round(entropy(data), 2)
                suspicious = section_entropy > 7.0 or not is_normal_elf_section(name)
                result["sections"].append({"name": name, "entropy": section_entropy, "suspicious": suspicious})
                if section_entropy > 7.0:
                    findings.append(
                        finding(
                            "MEDIUM",
                            "MEDIUM",
                            "BINARY-HIGH-ENTROPY",
                            f"Section '{name}' has entropy {section_entropy} (threshold 7.0) - possible packing or encryption",
                        )
                    )
                if not is_normal_elf_section(name):
                    findings.append(
                        finding(
                            "LOW",
                            "MEDIUM",
                            "BINARY-UNUSUAL-SECTION",
                            f"Section '{name}' has a non-standard ELF section name",
                        )
                    )

            needed = []
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(str(tag.needed))

            result["imports"] = {"needed": needed}
            network_libs = [lib for lib in needed if "libcurl" in lib.lower() or "libssl" in lib.lower()]
            if network_libs:
                issue = "Unexpected network/crypto shared library import: " + ", ".join(network_libs)
                if any("pthread" in lib.lower() for lib in needed):
                    issue += " (combined with threading library)"
                findings.append(finding("MEDIUM", "MEDIUM", "BINARY-NETWORK-IMPORT", issue))

            if elf.get_section_by_name(".symtab") is None:
                findings.append(
                    finding(
                        "LOW",
                        "HIGH",
                        "BINARY-STRIPPED-SYMBOLS",
                        "ELF symbol table is stripped; common for release builds but limits manual symbol review",
                    )
                )
            return result
    except ELFError:
        return invalid_result(path, "ELF")
    except Exception:
        return invalid_result(path, "ELF")


def inspect(path: Path) -> dict[str, object]:
    suffix = path.suffix.lower()
    if suffix in {".pyd", ".dll"}:
        return inspect_pe(path)
    if suffix == ".so":
        return inspect_elf(path)

    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic[:2] == b"MZ":
        return inspect_pe(path)
    if magic == b"\x7fELF":
        return inspect_elf(path)
    return invalid_result(path, "native")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or len(argv) > 3:
        print(json.dumps({"error": "usage: inspect_binary.py <path> [output_json]"}))
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
