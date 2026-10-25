"""Scan one source file and build a CycloneDX 1.6 CBOM from what was found.

The file below plants MD5 on line 3 and a 2048-bit RSA key on line 4. The script checks that the scanner
reports exactly those two assets on those lines, and that the CBOM carries both as components.
"""
import os
import tempfile

from pqblocks_scan.cbom import CBOMGenerator
from pqblocks_scan.discovery import Discovery

SOURCE = (
    "import hashlib\n"
    "from Crypto.PublicKey import RSA\n"
    "digest = hashlib.md5(b'data').hexdigest()\n"
    "key = RSA.generate(2048)\n"
)

with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "legacy.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(SOURCE)
    assets = Discovery().discover_file(path).assets

found = sorted((a.algorithm, a.line_number, a.is_quantum_vulnerable) for a in assets)
cbom = CBOMGenerator.generate(assets, component_name="legacy-app")

print("assets found:", found)
print("CBOM:", cbom["bomFormat"], cbom["specVersion"], "with", len(cbom["components"]), "components")
ok = found == [("MD5", 3, True), ("RSA-2048", 4, True)] and cbom["specVersion"] == "1.6" and len(cbom["components"]) == 2
print("check passed:", ok)
assert ok
