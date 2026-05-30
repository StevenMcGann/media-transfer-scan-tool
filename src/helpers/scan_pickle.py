#!/usr/bin/env python3
"""Static opcode triage for Python pickle / ML model files.

CRITICAL: pickle deserialization executes arbitrary code. This scanner NEVER
unpickles. It uses pickletools.genops, which walks the opcode stream WITHOUT
running it, and flags the opcodes that enable arbitrary code execution on load:

    GLOBAL / STACK_GLOBAL  -> import an arbitrary module attribute (callable)
    REDUCE                 -> call a callable with arguments (the exec primitive)
    INST / OBJ / NEWOBJ /
    NEWOBJ_EX / BUILD      -> instantiate / build arbitrary objects

It also recognizes safe-by-design model formats (safetensors, GGUF) and finds
pickles embedded inside ZIP-based model containers (PyTorch .pt/.pth, which are
ZIPs containing data.pkl), and inside numpy .npy/.npz.

Output JSON: {file, format, valid, findings:[{severity,confidence,testId,issue,category}]}
Mirrors inspect_binary.py / scan_office.py so the PowerShell analyzer reuses it.
"""

from __future__ import annotations

import io
import json
import pickletools
import sys
import zipfile
from pathlib import Path


# Module.attribute references that are dangerous when imported via GLOBAL.
SUSPICIOUS_GLOBALS = {
    "os": "operating-system command execution",
    "nt": "operating-system command execution",
    "posix": "operating-system command execution",
    "subprocess": "subprocess execution",
    "builtins": "builtin eval/exec/__import__ access",
    "__builtin__": "builtin eval/exec/__import__ access",
    "socket": "network access",
    "shutil": "filesystem manipulation",
    "sys": "interpreter manipulation",
    "code": "dynamic code execution",
    "pty": "pseudo-terminal / shell access",
    "commands": "shell command execution",
    "webbrowser": "process launch via browser",
    "importlib": "dynamic import",
    "runpy": "module execution",
}


def finding(severity, confidence, test_id, issue, category="deserialization"):
    return {"severity": severity, "confidence": confidence,
            "testId": test_id, "issue": issue, "category": category}


def scan_pickle_bytes(data: bytes, label: str, findings: list) -> None:
    """Disassemble a pickle opcode stream statically (never executes)."""
    saw_global, saw_reduce = False, False
    # Track recent string operands so STACK_GLOBAL (proto 4+, where module/name
    # are pushed as separate strings rather than a GLOBAL arg) can be resolved.
    recent_strings: list[str] = []
    str_ops = ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
               "SHORT_BINSTRING", "BINSTRING", "STRING")
    try:
        for opcode, arg, _pos in pickletools.genops(data):
            name = opcode.name
            if name in str_ops and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)
            if name in ("GLOBAL", "STACK_GLOBAL"):
                saw_global = True
                module = ""
                qual = arg or "?"
                if name == "GLOBAL" and isinstance(arg, str):
                    module = arg.split(" ")[0].split(".")[0]
                elif name == "STACK_GLOBAL" and len(recent_strings) >= 2:
                    module = recent_strings[-2].split(".")[0]
                    qual = f"{recent_strings[-2]} {recent_strings[-1]}"
                reason = SUSPICIOUS_GLOBALS.get(module)
                if reason:
                    findings.append(finding(
                        "CRITICAL", "HIGH", "PICKLE-DANGEROUS-IMPORT",
                        f"{label}: pickle imports '{qual}' ({reason}) — arbitrary code on load."))
                else:
                    findings.append(finding(
                        "HIGH", "MEDIUM", "PICKLE-GLOBAL-IMPORT",
                        f"{label}: pickle GLOBAL import '{qual}' — can reference arbitrary callables."))
            elif name == "REDUCE":
                saw_reduce = True
            elif name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"):
                pass  # object construction; only notable alongside GLOBAL/REDUCE
    except Exception as exc:
        findings.append(finding(
            "MEDIUM", "LOW", "PICKLE-PARSE-ERROR",
            f"{label}: pickle opcode stream could not be fully parsed ({exc}) — treat as suspect.",
            "parser"))
        return

    if saw_reduce:
        findings.append(finding(
            "CRITICAL", "HIGH", "PICKLE-REDUCE",
            f"{label}: pickle uses REDUCE — invokes a callable on load (the code-execution primitive)."))
    elif saw_global:
        findings.append(finding(
            "HIGH", "MEDIUM", "PICKLE-GLOBAL",
            f"{label}: pickle references imported globals; review the imports above."))


def looks_like_pickle(data: bytes) -> bool:
    # Pickle protocol 2+ starts with PROTO opcode (0x80) then a version byte.
    # Protocol 0/1 start with a printable opcode; we still try genops.
    return len(data) >= 2 and (data[0] == 0x80 or data[0:1] in (b"(", b"]", b"}", b"c"))


def inspect(path: Path) -> dict:
    findings: list = []
    suffix = path.suffix.lower()
    fmt = "pickle"

    head = b""
    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except Exception as exc:
        return {"file": str(path), "format": "UNKNOWN", "valid": False,
                "findings": [finding("LOW", "LOW", "MODEL-READ-ERROR", f"Could not read file: {exc}", "parser")]}

    # Safe-by-design formats: recognize and clear them.
    if suffix == ".safetensors" or head[8:].startswith(b"{"):
        if suffix == ".safetensors":
            return {"file": str(path), "format": "safetensors", "valid": True,
                    "findings": [finding("INFO", "HIGH", "MODEL-SAFE-FORMAT",
                                 "safetensors — safe-by-design tensor format (no code execution on load).", "parser")]}
    if suffix == ".gguf" or head.startswith(b"GGUF"):
        return {"file": str(path), "format": "gguf", "valid": True,
                "findings": [finding("INFO", "HIGH", "MODEL-SAFE-FORMAT",
                             "GGUF — safe-by-design model format (no code execution on load).", "parser")]}

    # Non-pickle tensor/graph formats: real risk is not pickle code-exec.
    if suffix in (".h5", ".hdf5", ".pb", ".onnx"):
        return {"file": str(path), "format": suffix.lstrip("."), "valid": True,
                "findings": [finding("INFO", "MEDIUM", "MODEL-NON-PICKLE",
                             f"{suffix} is not a pickle-based format — no pickle deserialization surface.", "parser")]}

    pickle_suffixes = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".npy", ".npz", ".model", ".dat")
    try:
        if zipfile.is_zipfile(path):
            fmt = "torch-zip"
            with zipfile.ZipFile(path) as z:
                pkls = [n for n in z.namelist() if n.endswith(".pkl") or n.endswith("data.pkl")]
                if not pkls:
                    findings.append(finding("LOW", "MEDIUM", "MODEL-ZIP-NO-PICKLE",
                        "ZIP-based model contains no .pkl — no pickle code-exec surface found.", "parser"))
                for n in pkls:
                    scan_pickle_bytes(z.read(n), n, findings)
        else:
            data = path.read_bytes()
            if looks_like_pickle(data) or suffix in pickle_suffixes:
                fmt = "pickle"
                scan_pickle_bytes(data, path.name, findings)
            else:
                findings.append(finding("INFO", "LOW", "MODEL-UNKNOWN-FORMAT",
                    f"{path.name}: not recognized as a pickle or known model format.", "parser"))
    except Exception as exc:
        findings.append(finding("MEDIUM", "LOW", "MODEL-PARSE-ERROR",
            f"Model could not be parsed: {exc}", "parser"))

    return {"file": str(path), "format": fmt, "valid": True, "findings": findings}


def main(argv: list) -> int:
    if len(argv) < 2 or len(argv) > 3:
        print(json.dumps({"error": "usage: scan_pickle.py <path> [output_json]"}))
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
