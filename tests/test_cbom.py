"""Tests for CycloneDX 1.6 CBOM Serializer."""

from pqblocks_scan.models import CryptoAsset
from pqblocks_scan.cbom import CBOMGenerator


def test_cbom_generation():
    asset1 = CryptoAsset("app.py:10", "RSA-2048", 2048, "TLS 1.2", "app.py", 10, True, 2031, False)
    asset2 = CryptoAsset("lib.py:20", "ML-KEM-768", 768, None, "lib.py", 20, False, None, True)

    cbom = CBOMGenerator.generate([asset1, asset2])
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 2

    comp1 = cbom["components"][0]
    assert comp1["name"] == "RSA-2048"
    assert comp1["cryptoProperties"]["assetType"] == "algorithm"
    assert "nistQuantumSecurityLevel" not in comp1["cryptoProperties"]["algorithmProperties"]

    comp2 = cbom["components"][1]
    assert comp2["name"] == "ML-KEM-768"
    assert comp2["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
