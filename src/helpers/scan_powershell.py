#!/usr/bin/env python3
"""Static token scan for high-risk PowerShell constructs.

The rule table contains only SHA-256 identities.  Indicator text is never
stored, assembled, evaluated, or returned by this helper.  The target is read
as inert text and candidate tokens are normalized and hashed before lookup.

Usage: scan_powershell.py <input_file> [output_json]
Output: {scanned, findings:[{line,severity,confidence,testId,issue,category}]}
"""
from __future__ import annotations

import codecs
import hashlib
import json
import re
import sys
from pathlib import Path


MAX_BYTES = 5_000_000
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(?:-[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9_-]*)(?![A-Za-z0-9_])")

# digest -> (severity, test id, context, optional pair-tail digest, message)
RULES = {
    "9902663A76D7A84D5A9BBE338FA9817CDE901A67DD64314E22945801D183A09D":
        ("HIGH", "PS-IEX", "any", None, "Dynamic expression execution primitive."),
    "7BDC79A32A635567A95C3BCC72754B623A417A21FA78154FE21E8CB8A963E47E":
        ("HIGH", "PS-IEX", "any", None, "Dynamic expression execution primitive."),
    "BB68081F43AE625A17063283B37A727EB79FA9F346CAEFBF729DFC0977403AA5":
        ("HIGH", "PS-DOWNLOAD", "member_call", None, "Network-client download method used for remote payload retrieval."),
    "8D6F40E97020332EC4A9C077949B03190C586F074D928C6923A9DEAF87B98346":
        ("HIGH", "PS-DOWNLOAD", "member_call", None, "Network-client download method used for remote payload retrieval."),
    "64523F7FB90D30E3203C13AB70DB6BD00F46C5804681E888E6F660C643CE5E25":
        ("HIGH", "PS-DOWNLOAD", "member_call", None, "Network-client download method used for remote payload retrieval."),
    "D6B832EC499CBAB5CD8344D8107DCEC54FBE5049CCA7249113E4BCB37EBD3043":
        ("HIGH", "PS-ENCODED-COMMAND", "any", None, "Encoded command-line content (common obfuscation)."),
    "8DE76D1DF3B6088F24383D86D51A8F4C60CC25BD8A8DCCF4753B743335D12F06":
        ("HIGH", "PS-ENCODED-COMMAND", "any", None, "Encoded command-line content (common obfuscation)."),
    "CB9050410D3B62CB67F5811C5F8242A67DA1BA49422AA0358D1AE0B6DF98D5CF":
        ("MEDIUM", "PS-BASE64-DECODE", "call", None, "Base64 decoding of embedded data."),
    "B3AF578FDDE04CC108AB5A71AC2417388BB5599124EA52F498BA9154BEDAA3B7":
        ("MEDIUM", "PS-HIDDEN-WINDOW", "pair", "E564B4081D7A9EA4B00DADA53BDAE70C99B87B6FCE869F0C3DD4D2BFA1E53E1C", "Hidden-window process launch."),
    "F4C5F28A8DFEC938CC0CE22256D33705EDF19F1ABF2F4A3A4035A84744908F80":
        ("HIGH", "PS-AMSI-TAMPER", "any", None, "Antimalware interface tampering reference."),
    "0669320B5058F4CFE827E208D721D8EBF76BC2E1BBF453766B054007C3AACD36":
        ("HIGH", "PS-AMSI-TAMPER", "any", None, "Antimalware interface tampering reference."),
    "2352DBCF9022952AD733DB2D079043E851230601A7833BB88A913A8361F737A5":
        ("HIGH", "PS-AMSI-TAMPER", "any", None, "Antimalware interface tampering reference."),
    "832735B8ABDDF1BEEF8D167B0F30B73DB49828A45BFF6AD4CD58A944B37B3633":
        ("HIGH", "PS-DEFENDER-TAMPER", "any", None, "Endpoint-protection preference modification."),
    "2F99DD1021CFC36E99910F971A36E02B11CBF110E35F82276EFBBBE4DC09AA34":
        ("HIGH", "PS-DEFENDER-TAMPER", "any", None, "Endpoint-protection preference modification."),
    "38413B5546EBB90054237B770EC2700448B9EE419F76770FEC82856CF45D6154":
        ("LOW", "PS-EXEC-BYPASS", "pair", "F271A122BF4230C7C217B4CB8A66F8B4325B9C1821627DCA16924FFF32D6AA71", "Execution-policy bypass."),
}


def digest(token: str) -> str:
    return hashlib.sha256(token.casefold().encode("utf-8")).hexdigest().upper()


def previous_non_whitespace(text: str, start: int) -> str:
    while start >= 0:
        if not text[start].isspace():
            return text[start]
        start -= 1
    return ""


def next_non_whitespace(text: str, start: int) -> str:
    while start < len(text):
        if not text[start].isspace():
            return text[start]
        start += 1
    return ""


def decode_source(data: bytes) -> str:
    """Decode the BOM-aware text formats recognized by PowerShell/.NET."""
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif data.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    else:
        encoding = "utf-8"

    text = data.decode(encoding, errors="replace")
    # Path.read_text() used universal newlines; retain that behavior now that
    # decoding starts from bytes.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def scan_text(text: str) -> list[dict]:
    tokens = list(TOKEN_RE.finditer(text))
    digests = [digest(match.group(0)) for match in tokens]
    findings = []

    for index, match in enumerate(tokens):
        rule = RULES.get(digests[index])
        if not rule:
            continue
        severity, test_id, context, pair_digest, issue = rule
        if context == "member_call":
            applies = (previous_non_whitespace(text, match.start() - 1) == "." and
                       next_non_whitespace(text, match.end()) == "(")
        elif context == "call":
            applies = next_non_whitespace(text, match.end()) == "("
        elif context == "pair":
            applies = index + 1 < len(tokens) and digests[index + 1] == pair_digest
        else:
            applies = True
        if not applies:
            continue

        findings.append({
            "line": text.count("\n", 0, match.start()) + 1,
            "severity": severity,
            "confidence": "MEDIUM",
            "testId": test_id,
            "issue": issue,
            "category": "risky-code",
        })
    return findings


def scan_file(path: Path) -> dict:
    if not path.is_file():
        return {"scanned": 0, "findings": [], "error": f"not found: {path}"}
    if path.stat().st_size > MAX_BYTES:
        return {"scanned": 0, "findings": [], "error": "input exceeds static-rule size limit"}
    try:
        text = decode_source(path.read_bytes())
    except OSError as exc:
        return {"scanned": 0, "findings": [], "error": f"could not read input: {exc}"}
    return {"scanned": 1, "findings": scan_text(text)}


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(json.dumps({"error": "usage: scan_powershell.py <input_file> [output_json]"}))
        return 2

    result = scan_file(Path(argv[1]).resolve())
    payload = json.dumps(result, indent=2)
    if len(argv) == 3:
        Path(argv[2]).write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0 if result.get("scanned") == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
