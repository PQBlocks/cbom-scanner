"""Run the command-line scanner the way a CI job would, and check its exit code and output files.

A temporary repository gets one file with MD5 and a 1024-bit RSA key. The run writes a CBOM and a SARIF file
and uses --fail-on D, so a grade of D or worse must give exit code 1. The SARIF file must carry one result
per quantum-vulnerable asset.
"""
import json
import os
import tempfile

from pqblocks_scan.cli import main

with tempfile.TemporaryDirectory() as repo:
    with open(os.path.join(repo, "auth.py"), "w", encoding="utf-8") as fh:
        fh.write("import hashlib\nfrom Crypto.PublicKey import RSA\n"
                 "pw = hashlib.md5(b'secret').hexdigest()\nkey = RSA.generate(1024)\n")
    cbom_path, sarif_path = os.path.join(repo, "cbom.json"), os.path.join(repo, "scan.sarif")
    rc = main([repo, "--cbom", cbom_path, "--sarif", sarif_path, "--fail-on", "D"])
    cbom = json.load(open(cbom_path, encoding="utf-8"))
    sarif = json.load(open(sarif_path, encoding="utf-8"))

names = sorted(c["name"] for c in cbom["components"])
rules = sorted(r["ruleId"] for r in sarif["runs"][0]["results"])
print("exit code:", rc)
print("CBOM components:", names)
print("SARIF", sarif["version"], "results:", rules)
ok = rc == 1 and names == ["MD5", "RSA-1024"] and sarif["version"] == "2.1.0" and rules == ["PQC002", "PQC002"]
print("check passed:", ok)
assert ok
