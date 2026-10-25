"""Classify TLS cipher-suite names offline, without opening a network connection.

parse_cipher_suite() reads the primitives out of a cipher-suite name. The expected lists below are read by hand
from the names themselves. Note that a name never carries the RSA or ECDSA key size: the parser assumes
RSA-2048 and ECDSA-P256 (see README, Limitations).
"""
from pqblocks_scan.tls_probe import cipher_to_assets, parse_cipher_suite

CASES = {
    "TLS_AES_256_GCM_SHA384": [("AES-256", 256), ("SHA-384", 384)],
    "ECDHE-RSA-AES128-GCM-SHA256": [("RSA-2048", 2048), ("AES-128", 128), ("SHA-256", 256)],
    "ECDHE-ECDSA-CHACHA20-POLY1305": [("ECDSA-P256", 256), ("CHACHA20", 256)],
}

ok = True
for name, expected in CASES.items():
    got = parse_cipher_suite(name)
    print(f"{name:32} -> {got}")
    ok &= got == expected

assets = cipher_to_assets("ECDHE-RSA-AES128-GCM-SHA256", "example.org", 443)
print("asset ids:", [a.asset_id for a in assets])
ok &= [a.asset_id for a in assets] == ["tls://example.org:443:1", "tls://example.org:443:2", "tls://example.org:443:3"]
print("check passed:", bool(ok))
assert ok
