"""
Tests for models.py
Tests for: CryptoAsset, CBOMReport, GradeResult, DeadlineFinding
"""
import pytest
from dataclasses import dataclass, fields
from typing import Optional


class TestCryptoAsset:
    def test_crypto_asset_defaults(self):
        from pqblocks_scan.models import CryptoAsset
        
        asset = CryptoAsset(
            asset_id="test-001",
            algorithm="RSA-2048",
            key_size=2048,
            protocol="TLS",
            file_path="crypto.py",
            line_number=42,
            is_quantum_vulnerable=True,
            cnsa2_deadline_year=2031,
            abstraction_isolated=False
        )
        
        assert asset.asset_id == "test-001"
        assert asset.algorithm == "RSA-2048"
        assert asset.key_size == 2048
        assert asset.protocol == "TLS"
        assert asset.file_path == "crypto.py"
        assert asset.line_number == 42
        assert asset.is_quantum_vulnerable is True
        assert asset.cnsa2_deadline_year == 2031
        assert asset.abstraction_isolated is False

    def test_crypto_asset_is_quantum_vulnerable_for_legacy(self):
        from pqblocks_scan.models import CryptoAsset
        
        legacy = CryptoAsset(
            asset_id="legacy-001",
            algorithm="RSA-2048",
            key_size=2048,
            protocol="TLS",
            file_path="app.py",
            line_number=100,
            is_quantum_vulnerable=True,
            cnsa2_deadline_year=2030,
            abstraction_isolated=False
        )
        assert legacy.is_quantum_vulnerable is True

    def test_crypto_asset_not_quantum_vulnerable_for_pqc(self):
        from pqblocks_scan.models import CryptoAsset
        
        pqc = CryptoAsset(
            asset_id="pqc-001",
            algorithm="ML-KEM-768",
            key_size=768,
            protocol="KEM",
            file_path="kem.py",
            line_number=50,
            is_quantum_vulnerable=False,
            cnsa2_deadline_year=2035,
            abstraction_isolated=True
        )
        assert pqc.is_quantum_vulnerable is False

    def test_crypto_asset_protocol_optional(self):
        from pqblocks_scan.models import CryptoAsset
        
        asset = CryptoAsset(
            asset_id="hash-001",
            algorithm="SHA-256",
            key_size=256,
            protocol=None,
            file_path="hash.py",
            line_number=10,
            is_quantum_vulnerable=False,
            cnsa2_deadline_year=None,
            abstraction_isolated=False
        )
        assert asset.protocol is None


class TestCBOMReport:
    def test_cbom_report_is_dict(self):
        from pqblocks_scan.models import CBOMReport
        
        cbom = CBOMReport(
            bom_format="CycloneDX",
            version="1.6",
            components=[]
        )
        
        result = cbom.to_dict()
        assert isinstance(result, dict)
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.6"
        assert result["components"] == []

    def test_cbom_report_with_components(self):
        from pqblocks_scan.models import CBOMReport, CryptoAsset
        
        asset = CryptoAsset(
            asset_id="test-001",
            algorithm="AES-256",
            key_size=256,
            protocol="TLS",
            file_path="crypto.py",
            line_number=42,
            is_quantum_vulnerable=False,
            cnsa2_deadline_year=None,
            abstraction_isolated=True
        )
        
        cbom = CBOMReport(
            bom_format="CycloneDX",
            version="1.6",
            components=[asset]
        )
        
        result = cbom.to_dict()
        assert len(result["components"]) == 1
        comp = result["components"][0]
        assert comp["name"] == "AES-256"

    def test_cbom_report_component_has_crypto_properties(self):
        from pqblocks_scan.models import CBOMReport, CryptoAsset
        
        asset = CryptoAsset(
            asset_id="test-001",
            algorithm="RSA-2048",
            key_size=2048,
            protocol="TLS",
            file_path="crypto.py",
            line_number=42,
            is_quantum_vulnerable=True,
            cnsa2_deadline_year=2031,
            abstraction_isolated=False
        )
        
        cbom = CBOMReport(
            bom_format="CycloneDX",
            version="1.6",
            components=[asset]
        )
        
        result = cbom.to_dict()
        comp = result["components"][0]
        assert "cryptoProperties" in comp
        assert "assetType" in comp["cryptoProperties"]
        assert "nistQuantumSecurityLevel" in comp["cryptoProperties"]


class TestGradeResult:
    def test_grade_result_a_grade(self):
        from pqblocks_scan.models import GradeResult
        
        grade = GradeResult(
            score=90.0,
            letter="A",
            dimensions={
                "d1": 0.9,
                "d2": 0.8,
                "d3": 0.85,
                "d4": 0.7,
                "d5": 0.75
            }
        )
        
        assert grade.letter == "A"
        assert grade.score == 90.0

    def test_grade_result_f_grade(self):
        from pqblocks_scan.models import GradeResult
        
        grade = GradeResult(
            score=25.0,
            letter="F",
            dimensions={
                "d1": 0.1,
                "d2": 0.05,
                "d3": 0.2,
                "d4": 0.1,
                "d5": 0.05
            }
        )
        
        assert grade.letter == "F"

    def test_grade_result_c_grade(self):
        from pqblocks_scan.models import GradeResult
        
        grade = GradeResult(
            score=62.5,
            letter="C",
            dimensions={
                "d1": 0.5,
                "d2": 0.4,
                "d3": 0.45,
                "d4": 0.3,
                "d5": 0.35
            }
        )
        
        assert grade.letter == "C"


class TestDeadlineFinding:
    def test_deadline_finding_rsa_cnsa2_2031(self):
        from pqblocks_scan.models import DeadlineFinding
        
        finding = DeadlineFinding(
            asset_id="rsa-001",
            algorithm="RSA-2048",
            cnsa2_category="migration",
            cnsa2_deadline_year=2031,
            action_required="Migrate to ML-KEM-768 or RSA-3072 before 2031"
        )
        
        assert finding.algorithm == "RSA-2048"
        assert finding.cnsa2_category == "migration"
        assert finding.cnsa2_deadline_year == 2031

    def test_deadline_finding_md5_fips140_2_sunset(self):
        from pqblocks_scan.models import DeadlineFinding
        
        finding = DeadlineFinding(
            asset_id="md5-001",
            algorithm="MD5",
            cnsa2_category="deprecated",
            cnsa2_deadline_year=2026,
            action_required="Replace immediately - FIPS 140-2 sunset"
        )
        
        assert finding.algorithm == "MD5"
        assert finding.cnsa2_deadline_year == 2026


class TestModelValidation:
    def test_invalid_key_size_raises_error(self):
        from pqblocks_scan.models import CryptoAsset
        
        with pytest.raises(ValueError, match="key_size must be positive"):
            CryptoAsset(
                asset_id="bad-001",
                algorithm="RSA",
                key_size=-100,
                protocol="TLS",
                file_path="crypto.py",
                line_number=10,
                is_quantum_vulnerable=True,
                cnsa2_deadline_year=None,
                abstraction_isolated=False
            )

    def test_invalid_line_number_raises_error(self):
        from pqblocks_scan.models import CryptoAsset
        
        with pytest.raises(ValueError, match="line_number must be positive"):
            CryptoAsset(
                asset_id="bad-002",
                algorithm="RSA-2048",
                key_size=2048,
                protocol="TLS",
                file_path="crypto.py",
                line_number=-1,
                is_quantum_vulnerable=True,
                cnsa2_deadline_year=None,
                abstraction_isolated=False
            )


class TestModelExtendedMethods:
    def test_cbom_report_to_dict(self):
        from pqblocks_scan.models import CBOMReport, CryptoAsset

        asset = CryptoAsset("a1", "ML-KEM-768", 768, "TLS", "a.py", 1, False, None, True)
        report = CBOMReport(bom_format="CycloneDX", version="1.6", components=[asset])
        d = report.to_dict()
        assert d["bomFormat"] == "CycloneDX"
        assert d["specVersion"] == "1.6"
        assert len(d["components"]) == 1

    def test_grade_result_to_dict_and_validation(self):
        from pqblocks_scan.models import GradeResult
        
        with pytest.raises(ValueError, match="must be in"):
            GradeResult(score=-5.0, letter="F", dimensions={})
            
        with pytest.raises(ValueError, match="must be in"):
            GradeResult(score=105.0, letter="F", dimensions={})

        with pytest.raises(ValueError, match="must be one of"):
            GradeResult(score=90.0, letter="Z", dimensions={})

        with pytest.raises(ValueError, match="must be in"):
            GradeResult(score=90.0, letter="A", dimensions={"d1": 1.5})

        with pytest.raises(ValueError, match="must be in"):
            GradeResult(score=90.0, letter="A", dimensions={"d1": -0.5})

        res = GradeResult(score=95.0, letter="A", dimensions={"d1": 1.0, "d2": 0.8})
        d = res.to_dict()
        assert d["score"] == 95.0
        assert d["letter"] == "A"
        assert d["dimensions"]["d1"] == 1.0

    def test_deadline_finding_to_dict_and_validation(self):
        from pqblocks_scan.models import DeadlineFinding
        
        with pytest.raises(ValueError, match="must be one of"):
            DeadlineFinding("id1", "RSA-1024", "invalid_cat", 2026, "replace")
            
        with pytest.raises(ValueError, match="positive year"):
            DeadlineFinding("id1", "RSA-1024", "prohibited", -1, "replace")

        df = DeadlineFinding("id1", "RSA-1024", "prohibited", 2026, "replace")
        d = df.to_dict()
        assert d["asset_id"] == "id1"
        assert d["algorithm"] == "RSA-1024"
        assert d["cnsa2_category"] == "prohibited"

    def test_nist_security_levels_and_parameter_ids(self):
        from pqblocks_scan.models import CryptoAsset, _nist_quantum_security_level, _parameter_set_identifier, _crypto_properties

        algs = [
            ("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5),
            ("ML-DSA-44", 2), ("ML-DSA-65", 3), ("ML-DSA-87", 5),
            ("ECDSA-P256", 0), ("RSA-2048", 0), ("MD5", 0), ("SHA-1", 0),
            ("SHA-256", 0), ("AES-256", 0), ("UNKNOWN_ALG", 0)
        ]
        for alg, expected_level in algs:
            asset = CryptoAsset(f"id-{alg}", alg, 128, None, "test.py", 1, expected_level == 0, None, True)
            assert _nist_quantum_security_level(asset) == expected_level
            pid = _parameter_set_identifier(asset)
            assert isinstance(pid, str)
            props = _crypto_properties(asset)
            assert "assetType" in props