#!/usr/bin/env python3
"""Curated high-signal static scan of Python source (the 'middle tier').

Python analogue of the PowerShell/shell risky-pattern layers: reports ONLY
attacker-grade indicators for media-transfer ingress (dynamic code-exec, unsafe
deserialization, command/process spawn, download-and-run, decode-then-exec,
native/shellcode injection, install-time hooks). It does NOT emit the broad
code-quality findings a full linter (Bandit) produces.

AST-based (stdlib `ast`): matches are real call sites, not substrings in
comments/strings. Needs a Python interpreter but NO pip package, so it runs
offline / air-gapped. NEVER imports or executes the target — only parses it.

Accepts a .py file OR a directory (walked recursively, *.py).
Output JSON: {root, scanned, findings:[{file,line,severity,confidence,testId,issue,category}]}
"""
from __future__ import annotations
import ast, json, sys
from pathlib import Path

MAX_FILES = 500
MAX_BYTES = 5_000_000


def F(line, sev, conf, tid, issue, cat="risky-code"):
    return {"line": line, "severity": sev, "confidence": conf,
            "testId": tid, "issue": issue, "category": cat}


# resolved-name -> (sev, conf, testId, category, message)
CALL_RULES = {
    "eval":       ("HIGH",   "HIGH",   "PY-EVAL",           "risky-code",      "eval() executes a dynamically-built expression."),
    "exec":       ("HIGH",   "HIGH",   "PY-EXEC",           "risky-code",      "exec() executes a dynamically-built code string."),
    "compile":    ("MEDIUM", "MEDIUM", "PY-COMPILE",        "risky-code",      "compile() builds code objects at runtime (often paired with exec/eval)."),
    "__import__": ("MEDIUM", "MEDIUM", "PY-DYNAMIC-IMPORT", "risky-code",      "__import__() dynamic import can hide which module loads."),
    "importlib.import_module": ("MEDIUM", "MEDIUM", "PY-DYNAMIC-IMPORT", "risky-code", "importlib.import_module() dynamic import."),
    "os.system":  ("HIGH",   "HIGH",   "PY-OS-SYSTEM",      "risky-code",      "os.system() runs an OS shell command."),
    "os.popen":   ("HIGH",   "HIGH",   "PY-OS-POPEN",       "risky-code",      "os.popen() runs an OS shell command."),
    "pty.spawn":  ("HIGH",   "HIGH",   "PY-PTY-SPAWN",      "risky-code",      "pty.spawn() launches an interactive shell/process."),
    "commands.getoutput":       ("HIGH", "HIGH", "PY-OS-SYSTEM", "risky-code", "commands.getoutput() runs a shell command (py2)."),
    "commands.getstatusoutput": ("HIGH", "HIGH", "PY-OS-SYSTEM", "risky-code", "commands.getstatusoutput() runs a shell command (py2)."),
    "pickle.loads":  ("HIGH", "HIGH",   "PY-PICKLE-LOAD",    "deserialization", "pickle.loads() executes arbitrary code on load."),
    "pickle.load":   ("HIGH", "HIGH",   "PY-PICKLE-LOAD",    "deserialization", "pickle.load() executes arbitrary code on load."),
    "cPickle.loads": ("HIGH", "HIGH",   "PY-PICKLE-LOAD",    "deserialization", "cPickle.loads() executes arbitrary code on load."),
    "cPickle.load":  ("HIGH", "HIGH",   "PY-PICKLE-LOAD",    "deserialization", "cPickle.load() executes arbitrary code on load."),
    "marshal.loads": ("HIGH", "MEDIUM", "PY-MARSHAL-LOAD",   "deserialization", "marshal.loads() loads code objects."),
    "marshal.load":  ("HIGH", "MEDIUM", "PY-MARSHAL-LOAD",   "deserialization", "marshal.load() loads code objects."),
    "yaml.load":     ("MEDIUM","MEDIUM","PY-YAML-LOAD",      "deserialization", "yaml.load() without SafeLoader can build arbitrary objects — use safe_load."),
    "socket.socket": ("MEDIUM","MEDIUM","PY-SOCKET",         "network",         "Raw socket created — network egress / C2 channel."),
    "urllib.request.urlopen": ("MEDIUM","MEDIUM","PY-NET-FETCH","network",      "urllib opens a network URL — remote fetch."),
    "urllib.urlopen":         ("MEDIUM","MEDIUM","PY-NET-FETCH","network",      "urllib opens a network URL — remote fetch."),
    "urllib2.urlopen":        ("MEDIUM","MEDIUM","PY-NET-FETCH","network",      "urllib2 opens a network URL — remote fetch."),
}
BUILTIN_ALIASES = {"builtins.eval": "eval", "builtins.exec": "exec",
                   "builtins.compile": "compile", "builtins.__import__": "__import__",
                   "__builtin__.eval": "eval", "__builtin__.exec": "exec"}
NET_METHODS = {"get", "post", "put", "patch", "delete", "head", "request"}
NET_MODULES = {"requests", "httpx", "urllib3", "aiohttp"}
SUBPROCESS_FUNCS = {"Popen", "call", "run", "check_output", "check_call",
                    "getoutput", "getstatusoutput"}
DECODE_NAMES = {"base64.b64decode", "base64.b85decode", "base64.a85decode",
                "base64.standard_b64decode", "base64.urlsafe_b64decode",
                "codecs.decode", "binascii.unhexlify", "binascii.a2b_base64",
                "zlib.decompress", "gzip.decompress", "bz2.decompress"}
CTYPES_CALLS = {"ctypes.CDLL", "ctypes.WinDLL", "ctypes.OleDLL", "ctypes.PyDLL"}
SHELLCODE_NAMES = {"VirtualAlloc", "VirtualProtect", "CreateThread",
                   "memmove", "RtlMoveMemory", "WriteProcessMemory", "CreateRemoteThread"}
def dotted(node):
    """Return the dotted name for a Name/Attribute chain, else None."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None


class Visitor(ast.NodeVisitor):
    def __init__(self):
        self.aliases = {}      # local name -> resolved module/attr
        self.findings = []
        self.flags = {}        # marker -> line, for file-level combinations
        self.names = set()     # bare identifiers referenced (for shellcode combo)

    def resolve(self, name):
        if not name:
            return None
        parts = name.split(".")
        root = parts[0]
        if root in self.aliases:
            base = self.aliases[root]
            return base if len(parts) == 1 else base + "." + ".".join(parts[1:])
        return name

    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
        self.generic_visit(node)

    def visit_Name(self, node):
        self.names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.names.add(node.attr)
        self.generic_visit(node)
    def visit_Call(self, node):
        raw = dotted(node.func)
        name = self.resolve(raw)
        name = BUILTIN_ALIASES.get(name, name)
        ln = getattr(node, "lineno", 0)
        if name:
            rule = CALL_RULES.get(name)
            if rule:
                sev, conf, tid, cat, msg = rule
                self.findings.append(F(ln, sev, conf, tid, msg, cat))
                if tid in ("PY-EVAL", "PY-EXEC"):
                    self.flags.setdefault("exec", ln)
                if cat == "network":
                    self.flags.setdefault("net", ln)
                if tid == "PY-SOCKET":
                    self.flags.setdefault("socket", ln)
            if name in DECODE_NAMES:
                self.findings.append(F(ln, "LOW", "MEDIUM", "PY-DECODE",
                    f"{name}() decodes/decompresses data (often used to unpack a payload).", "obfuscation"))
                self.flags.setdefault("decode", ln)
            if name in CTYPES_CALLS:
                self.findings.append(F(ln, "MEDIUM", "MEDIUM", "PY-CTYPES",
                    f"{name}() loads a native library via ctypes.", "risky-code"))
                self.flags.setdefault("ctypes", ln)
            # subprocess with shell=True
            if name.startswith("subprocess.") and name.split(".")[-1] in SUBPROCESS_FUNCS:
                shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                            and k.value.value is True for k in node.keywords)
                self.flags.setdefault("cmd", ln)
                if shell:
                    self.findings.append(F(ln, "HIGH", "HIGH", "PY-SUBPROCESS-SHELL",
                        "subprocess called with shell=True — command-injection surface.", "risky-code"))
            # os.exec* / os.spawn*
            if name.startswith("os.exec") or name.startswith("os.spawn"):
                self.flags.setdefault("cmd", ln)
                self.findings.append(F(ln, "MEDIUM", "MEDIUM", "PY-PROCESS-SPAWN",
                    f"{name}() launches another process.", "risky-code"))
            if name == "os.system" or name == "os.popen":
                self.flags.setdefault("cmd", ln)
            # requests-style network: <netmod>.<method>()
            if raw and "." in raw:
                r0, rmeth = raw.split(".")[0], raw.split(".")[-1]
                if self.resolve(r0) in NET_MODULES and rmeth in NET_METHODS:
                    self.findings.append(F(ln, "MEDIUM", "MEDIUM", "PY-NET-FETCH",
                        f"{raw}() performs a network request — remote fetch.", "network"))
                    self.flags.setdefault("net", ln)
        self.generic_visit(node)


def combos(v):
    """File-level escalations from co-occurring primitives."""
    out = []
    fl = v.flags
    if "net" in fl and ("exec" in fl or "cmd" in fl):
        out.append(F(fl.get("exec", fl.get("cmd")), "HIGH", "MEDIUM", "PY-DOWNLOAD-EXEC",
            "Download-and-run pattern: network fetch combined with code/command execution.", "risky-code"))
    if "decode" in fl and "exec" in fl:
        out.append(F(fl["exec"], "HIGH", "MEDIUM", "PY-DECODE-EXEC",
            "Obfuscation pattern: decoded/decompressed data is then executed.", "obfuscation"))
    if "socket" in fl and "cmd" in fl and "dup2" in v.names:
        out.append(F(fl["socket"], "CRITICAL", "MEDIUM", "PY-REVERSE-SHELL",
            "Reverse-shell pattern: socket + process spawn + os.dup2 redirection.", "risky-code"))
    if "ctypes" in fl and (v.names & SHELLCODE_NAMES):
        out.append(F(fl["ctypes"], "HIGH", "MEDIUM", "PY-SHELLCODE",
            "Native-injection pattern: ctypes paired with memory/thread APIs.", "risky-code"))
    return out


def scan_file(path: Path, root: Path):
    rel = str(path.relative_to(root)) if root != path else path.name
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [dict(F(0, "LOW", "LOW", "PY-READ-ERROR", f"Could not read: {exc}", "parser"), file=rel)]
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        return [dict(F(getattr(exc, "lineno", 0) or 0, "LOW", "LOW", "PY-PARSE-ERROR",
                       f"Python did not parse ({exc.msg}) — may be obfuscated or not Python.", "parser"), file=rel)]
    v = Visitor()
    v.visit(tree)
    all_f = v.findings + combos(v)
    return [dict(f, file=rel) for f in all_f]


def main(argv):
    if len(argv) < 2 or len(argv) > 3:
        print(json.dumps({"error": "usage: scan_python.py <path> [output_json]"}))
        return 2
    target = Path(argv[1]).resolve()
    findings, scanned = [], 0
    if target.is_dir():
        for p in sorted(target.rglob("*.py")):
            if scanned >= MAX_FILES:
                break
            findings.extend(scan_file(p, target))
            scanned += 1
    elif target.is_file():
        findings.extend(scan_file(target, target))
        scanned = 1
    else:
        print(json.dumps({"error": f"not found: {target}"}))
        return 2
    result = json.dumps({"root": str(target), "scanned": scanned, "findings": findings}, sort_keys=True)
    if len(argv) == 3:
        Path(argv[2]).write_text(result, encoding="utf-8")
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
