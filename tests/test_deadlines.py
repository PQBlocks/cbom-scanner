"""Tests for Regulatory Deadline Mapper."""

from pqblocks_scan.models import CryptoAsset
from pqblocks_scan.deadlines import DeadlineMapper


def test_deadline_mapping_prohibited():
    asset = CryptoAsset("app.py:5", "MD5", 128, None, "app.py", 5, True, 2026, False)
    finding = DeadlineMapper.map_asset(asset)
    assert finding is not None
    assert finding.cnsa2_category == "prohibited"
    assert finding.cnsa2_deadline_year == 2026


def test_deadline_mapping_migration():
    asset = CryptoAsset("app.py:12", "RSA-2048", 2048, None, "app.py", 12, True, 2031, False)
    finding = DeadlineMapper.map_asset(asset)
    assert finding is not None
    assert finding.cnsa2_category == "migration"
    assert finding.cnsa2_deadline_year == 2031


def test_deadline_mapping_pqc_returns_none():
    asset = CryptoAsset("app.py:20", "ML-DSA-65", 65, None, "app.py", 20, False, None, True)
    finding = DeadlineMapper.map_asset(asset)
    assert finding is None
