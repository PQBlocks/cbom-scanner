"""
Golden instances integration test for pqblocks-scan.
"""
import os
import pytest
from pqblocks_scan.discovery import Discovery
from pqblocks_scan.scorer import CARSScorer

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")

def test_gold01_legacy():
    path = os.path.join(GOLDEN_DIR, "gold01_legacy.py")
    assert os.path.isfile(path), f"Missing golden instance {path}"
    d = Discovery()
    res = d.discover_file(path)
    eval_res = CARSScorer.evaluate(res.assets, has_ci_workflow=False, has_migration_policy=False)
    assert eval_res.letter == "F", f"Expected Grade F, got {eval_res.letter}"
    assert eval_res.score < 40.0

def test_gold02_hybrid():
    path = os.path.join(GOLDEN_DIR, "gold02_hybrid.py")
    assert os.path.isfile(path), f"Missing golden instance {path}"
    d = Discovery()
    res = d.discover_file(path)
    eval_res = CARSScorer.evaluate(res.assets, has_ci_workflow=True, has_migration_policy=True)
    assert eval_res.letter == "A", f"Expected Grade A, got {eval_res.letter}"
    assert eval_res.score >= 85.0
