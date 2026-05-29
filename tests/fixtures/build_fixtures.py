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
os.makedirs(PYTHON_DIR, exist_ok=True)
os.makedirs(NATIVE_DIR, exist_ok=True)
os.makedirs(PYSRC_DIR, exist_ok=True)

RANDOM_SEED   = 13371337
FIXED_ZIP_DT  = (2026, 1, 1, 0, 0, 0)


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
write_text = lambda p, s: (open(p, 'w', encoding='utf-8').write(s), print(f'  wrote {p}'))[1]
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
    }
}
with open(os.path.join(CORPUS_DIR, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
print(f"  wrote {os.path.join(CORPUS_DIR, 'manifest.json')}")
print('Done.')
