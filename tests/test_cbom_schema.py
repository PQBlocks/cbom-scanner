"""CBOM output must validate against the official CycloneDX 1.6 JSON schema."""
import hashlib
import json
import os

import jsonschema
from referencing import Registry, Resource

from pqblocks_scan.cbom import CBOMGenerator
from pqblocks_scan.discovery import Discovery, make_asset
from pqblocks_scan.tls_probe import cipher_to_assets, cert_to_asset

HERE = os.path.dirname(__file__)
SCHEMAS = os.path.join(HERE, "schemas")
PINNED_SHA256 = {
    "bom-1.6.schema.json": "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
    "spdx.schema.json": "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359",
    "jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
}
ALL_ALGS = ["RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384",
            "ECDSA-P521", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "AES-128",
            "AES-192", "AES-256", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44",
            "ML-DSA-65", "ML-DSA-87", "X25519", "ED25519"]


def _load(name):
    with open(os.path.join(SCHEMAS, name), "rb") as f:
        raw = f.read()
    assert hashlib.sha256(raw).hexdigest() == PINNED_SHA256[name], f"{name} was modified"
    return json.loads(raw)


def _validator():
    spdx, jsf = _load("spdx.schema.json"), _load("jsf-0.82.schema.json")
    registry = Registry().with_resources([
        (u, Resource.from_contents(s)) for u, s in (
            ("spdx.schema.json", spdx), ("jsf-0.82.schema.json", jsf),
            ("http://cyclonedx.org/schema/spdx.schema.json", spdx),
            ("http://cyclonedx.org/schema/jsf-0.82.schema.json", jsf))])
    return jsonschema.Draft7Validator(_load("bom-1.6.schema.json"), registry=registry)


def _errors(doc):
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:160]}"
            for e in _validator().iter_errors(doc)]


def test_cbom_validates_for_every_known_algorithm():
    assets = [make_asset(a, "f.py", i) for i, a in enumerate(ALL_ALGS, start=1)]
    assert _errors(CBOMGenerator.generate(assets)) == []


def test_cbom_validates_for_scanned_files_and_tls_assets():
    d = Discovery()
    assets = []
    for name in ("gold01_legacy.py", "gold02_hybrid.py"):
        assets += d.discover_file(os.path.join(HERE, "golden", name)).assets
    assets += cipher_to_assets("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "example.org")
    assets += cipher_to_assets("TLS_AES_128_GCM_SHA256", "example.org")
    assets.append(cert_to_asset({"sig_alg": "sha256WithRSAEncryption", "key_size": 2048}, "example.org"))
    assert assets
    assert _errors(CBOMGenerator.generate(assets)) == []


def test_empty_cbom_validates():
    assert _errors(CBOMGenerator.generate([])) == []


def test_schema_validator_rejects_a_bad_document():
    """Guard against a vacuous validator."""
    bad = CBOMGenerator.generate([make_asset("MD5", "f.py", 1)])
    bad["components"][0]["cryptoProperties"]["algorithmProperties"]["executionEnvironment"] = "software-plain"
    assert _errors(bad)
