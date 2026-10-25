"""Tests for SARIF 2.1.0 Generator."""

from pqblocks_scan.models import CryptoAsset
from pqblocks_scan.deadlines import DeadlineMapper
from pqblocks_scan.sarif import SARIFGenerator


def test_sarif_generation():
    asset = CryptoAsset("app.py:15", "RSA-2048", 2048, None, "app.py", 15, True, 2031, False)
    deadlines = DeadlineMapper.map_all([asset])
    sarif = SARIFGenerator.generate([asset], deadlines)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqblocks-scan"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "PQC001"
    assert res["level"] == "warning"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
