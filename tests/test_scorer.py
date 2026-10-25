"""Tests for CARS Maturity Scoring Engine."""

from pqblocks_scan.models import CryptoAsset
from pqblocks_scan.scorer import CARSScorer


def test_scorer_all_vulnerable():
    asset = CryptoAsset("test.py:1", "RSA-2048", 2048, None, "test.py", 1, True, 2031, False)
    res = CARSScorer.evaluate([asset], has_ci_workflow=False, has_migration_policy=False)
    assert res.score < 40.0
    assert res.letter == "F"


def test_scorer_pqc_compliant():
    asset = CryptoAsset("test.py:1", "ML-KEM-768", 768, None, "test.py", 1, False, None, True)
    res = CARSScorer.evaluate([asset], has_ci_workflow=True, has_migration_policy=True)
    assert res.score >= 85.0
    assert res.letter == "A"


def test_scorer_weights_sum_to_one():
    assert round(sum(CARSScorer.WEIGHTS), 2) == 1.00
