"""
build_fixtures.py — deterministic fixture generator for media-transfer-scan-tool.

Run from the repo root:  python tests/fixtures/build_fixtures.py

Generates the fixtures consumed by the Pester test suite.
Static .whl fixtures are committed directly (corpus/python/).
This script generates the synthetic ones that are harder to ship as files.
"""

import io
import json
import os
import zipfile

FIXTURES_DIR = os.path.dirname(__file__)
CORPUS_DIR   = os.path.join(FIXTURES_DIR, 'corpus')
PYTHON_DIR   = os.path.join(CORPUS_DIR, 'python')
os.makedirs(PYTHON_DIR, exist_ok=True)

# ── 1. Corrupt ZIP (not a valid ZIP) ────────────────────────────────────────
corrupt_path = os.path.join(PYTHON_DIR, 'corrupt_pkg-1.0-py3-none-any.whl')
with open(corrupt_path, 'wb') as f:
    f.write(b'This is not a ZIP file\x00\x01\x02\x03')
print(f'  wrote {corrupt_path}')

# ── 2. Path-traversal ZIP ────────────────────────────────────────────────────
traversal_path = os.path.join(PYTHON_DIR, 'traversal_pkg-1.0-py3-none-any.whl')
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('safe/file.py', 'x = 1\n')
    z.writestr('../../../evil.py', 'import os; os.system("echo pwned")\n')
with open(traversal_path, 'wb') as f:
    f.write(buf.getvalue())
print(f'  wrote {traversal_path}')

# ── 3. Manifest ──────────────────────────────────────────────────────────────
manifest = {
    "schemaVersion": "0.1.0",
    "fixtures": {
        "clean_pkg-1.0-py3-none-any.whl":       {"expectCves": False, "expectSbom": False},
        "vulnerable_deps_pkg-1.0-py3-none-any.whl": {"expectCves": True,  "expectSbom": True},
        "corrupt_pkg-1.0-py3-none-any.whl":     {"expectExtractFailure": True},
        "traversal_pkg-1.0-py3-none-any.whl":   {"expectFinding": "MTS-EXTRACT-TRAVERSAL"},
    }
}
manifest_path = os.path.join(CORPUS_DIR, 'manifest.json')
with open(manifest_path, 'w') as f:
    json.dump(manifest, f, indent=2)
print(f'  wrote {manifest_path}')

print('Done.')
