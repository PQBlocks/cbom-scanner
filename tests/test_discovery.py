"""
Tests for discovery.py
Tests for: ASTDiscovery, RegexDiscovery, Discovery, DiscoveryResult, make_asset
Coverage:
  - Detection of legacy RSA-2048, ECDSA P-256, MD5, SHA-1
  - Recognition of NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65)
"""
import os
import tempfile

import pytest

from pqblocks_scan.discovery import (
    ASTDiscovery,
    Discovery,
    DiscoveryResult,
    RegexDiscovery,
    make_asset,
)
from pqblocks_scan.models import CryptoAsset


# ---------------------------------------------------------------------------
# make_asset helper
# ---------------------------------------------------------------------------

class TestMakeAsset:
    def test_creates_crypto_asset_with_meta(self):
        asset = make_asset("RSA-2048", "app.py", 10)
        assert asset.algorithm == "RSA-2048"
        assert asset.key_size == 2048
        assert asset.file_path == "app.py"
        assert asset.line_number == 10
        assert asset.is_quantum_vulnerable is True
        assert asset.cnsa2_deadline_year == 2031
        assert asset.protocol is None
        assert asset.abstraction_isolated is False
        assert asset.asset_id == "app.py:10"

    def test_creates_crypto_asset_with_protocol(self):
        asset = make_asset("RSA-2048", "app.py", 5, protocol="TLS")
        assert asset.protocol == "TLS"

    def test_unknown_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unknown algorithm"):
            make_asset("SUPER-SECRET-9000", "app.py", 1)


# ---------------------------------------------------------------------------
# ASTDiscovery — Python source analysis
# ---------------------------------------------------------------------------

class TestASTDiscoveryDetects:
    """detection of legacy RSA-2048, ECDSA P-256, MD5, SHA-1."""

    def test_detects_md5(self):
        source = "import hashlib\nh = hashlib.md5(b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "MD5" in [a.algorithm for a in assets]

    def test_detects_sha1(self):
        source = "import hashlib\nh = hashlib.sha1(b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "SHA-1" in [a.algorithm for a in assets]

    def test_detects_rsa_2048_pycryptodome(self):
        source = (
            "from Crypto.PublicKey import RSA\n"
            "key = RSA.generate(2048)\n"
        )
        assets = ASTDiscovery().scan(source, "test.py")
        assert "RSA-2048" in [a.algorithm for a in assets]

    def test_detects_rsa_2048_cryptography_lib(self):
        source = (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        )
        assets = ASTDiscovery().scan(source, "test.py")
        assert "RSA-2048" in [a.algorithm for a in assets]

    def test_detects_ecdsa_p256(self):
        source = (
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "key = ec.generate_private_key(ec.SECP256R1())\n"
        )
        assets = ASTDiscovery().scan(source, "test.py")
        assert "ECDSA-P256" in [a.algorithm for a in assets]

    def test_detects_aes(self):
        source = (
            "from Crypto.Cipher import AES\n"
            "cipher = AES.new(key, AES.MODE_CBC)\n"
        )
        assets = ASTDiscovery().scan(source, "test.py")
        assert "AES-256" in [a.algorithm for a in assets]

    def test_detects_sha256(self):
        source = "import hashlib\nh = hashlib.sha256(b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "SHA-256" in [a.algorithm for a in assets]

    def test_detects_hashlib_new_md5(self):
        source = "import hashlib\nh = hashlib.new('md5', b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "MD5" in [a.algorithm for a in assets]

    def test_detects_hashlib_new_sha1(self):
        source = "import hashlib\nh = hashlib.new('sha1', b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "SHA-1" in [a.algorithm for a in assets]


class TestASTDiscoveryPQC:
    """recognition of FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65)."""

    def test_detects_ml_kem_768(self):
        source = "from pqcrypto.kem import ml_kem_768\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "ML-KEM-768" in [a.algorithm for a in assets]

    def test_detects_ml_dsa_65(self):
        source = "from pqcrypto.sign import ml_dsa_65\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert "ML-DSA-65" in [a.algorithm for a in assets]


class TestASTDiscoveryEdgeCases:
    def test_returns_line_numbers(self):
        source = "import hashlib\nh = hashlib.md5(b'data')\n"
        assets = ASTDiscovery().scan(source, "test.py")
        md5_assets = [a for a in assets if a.algorithm == "MD5"]
        assert len(md5_assets) == 1
        assert md5_assets[0].line_number == 2

    def test_empty_source_returns_no_assets(self):
        assets = ASTDiscovery().scan("", "test.py")
        assert len(assets) == 0

    def test_invalid_python_raises_syntax_error(self):
        source = "this is not valid python!!!"
        with pytest.raises(SyntaxError):
            ASTDiscovery().scan(source, "test.py")

    def test_no_crypto_returns_no_assets(self):
        source = "def foo():\n    return 42\n"
        assets = ASTDiscovery().scan(source, "test.py")
        assert len(assets) == 0

    def test_file_path_in_assets(self):
        source = "import hashlib\nhashlib.md5(b'data')\n"
        assets = ASTDiscovery().scan(source, "myproject/crypto.py")
        assert all(a.file_path == "myproject/crypto.py" for a in assets)


# ---------------------------------------------------------------------------
# RegexDiscovery — text-based source analysis
# ---------------------------------------------------------------------------

class TestRegexDiscoveryDetects:
    """regex detection of RSA-2048, ECDSA P-256, MD5, SHA-1, ML-KEM-768, ML-DSA-65."""

    def test_detects_rsa_2048(self):
        source = "# Using RSA-2048 for key exchange"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "RSA-2048" in [a.algorithm for a in assets]

    def test_detects_md5(self):
        source = "hash = md5(data)"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "MD5" in [a.algorithm for a in assets]

    def test_detects_sha1(self):
        source = "h = sha1(input)"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "SHA-1" in [a.algorithm for a in assets]

    def test_detects_sha256(self):
        source = "digest = sha256(content)"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "SHA-256" in [a.algorithm for a in assets]

    def test_detects_ml_kem_768(self):
        source = "algorithm: str = 'ML-KEM-768'"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "ML-KEM-768" in [a.algorithm for a in assets]

    def test_detects_ml_dsa_65(self):
        source = "# FIPS 204: use ML-DSA-65 for signatures"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "ML-DSA-65" in [a.algorithm for a in assets]

    def test_detects_ecdsa_p256(self):
        source = "ECDSA with curve P-256 for signing"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "ECDSA-P256" in [a.algorithm for a in assets]

    def test_detects_x25519(self):
        source = "kem = X25519()"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "X25519" in [a.algorithm for a in assets]

    def test_detects_aes_256(self):
        source = "# AES-256-GCM encryption"
        assets = RegexDiscovery().scan(source, "test.py")
        assert "AES-256" in [a.algorithm for a in assets]


class TestRegexDiscoveryEdgeCases:
    def test_empty_source_returns_no_assets(self):
        assets = RegexDiscovery().scan("", "test.py")
        assert len(assets) == 0

    def test_no_crypto_returns_no_assets(self):
        source = "def calculate_sum(a, b):\n    return a + b\n"
        assets = RegexDiscovery().scan(source, "test.py")
        assert len(assets) == 0

    def test_case_insensitive_matching(self):
        source = "rsa-2048 and RSA-2048 and Rsa-2048"
        assets = RegexDiscovery().scan(source, "test.py")
        rsa_assets = [a for a in assets if a.algorithm == "RSA-2048"]
        assert len(rsa_assets) == 1

    def test_returns_line_numbers(self):
        source = "line one\n# RSA-2048 on line 2\nline three\n"
        assets = RegexDiscovery().scan(source, "test.py")
        rsa_assets = [a for a in assets if a.algorithm == "RSA-2048"]
        assert len(rsa_assets) == 1
        assert rsa_assets[0].line_number == 2

    def test_does_not_match_inside_words(self):
        source = "xmd5y"  # not a standalone MD5 reference
        assets = RegexDiscovery().scan(source, "test.py")
        assert len(assets) == 0


# ---------------------------------------------------------------------------
# Discovery — combined AST + regex engine
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_combined_detection(self):
        source = (
            "import hashlib\n"
            "from Crypto.PublicKey import RSA\n"
            "h = hashlib.sha1(b'data')\n"
            "key = RSA.generate(2048)\n"
        )
        result = Discovery().discover_source(source, "test.py")
        assert isinstance(result, DiscoveryResult)
        algos = set(a.algorithm for a in result.assets)
        assert "SHA-1" in algos
        assert "RSA-2048" in algos

    def test_deduplicates_same_line(self):
        source = "import hashlib\nh = hashlib.md5(b'data')\n"
        result = Discovery().discover_source(source, "test.py")
        md5_assets = [a for a in result.assets if a.algorithm == "MD5"]
        assert len(md5_assets) == 1

    def test_discover_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write("import hashlib\nh = hashlib.md5(b'data')\n")
            f.flush()
            tmp_path = f.name
        try:
            result = Discovery().discover_file(tmp_path)
            assert "MD5" in [a.algorithm for a in result.assets]
        finally:
            os.unlink(tmp_path)

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            Discovery().discover_file("/nonexistent/path/file.py")

    def test_non_string_source_raises_type_error(self):
        with pytest.raises(TypeError, match="source must be a string"):
            Discovery().discover_source(None, "test.py")  # type: ignore[arg-type]

    def test_non_integer_line_not_accepted_by_make_asset(self):
        with pytest.raises(ValueError, match="line_number must be positive"):
            make_asset("MD5", "test.py", 0)

    def test_asset_has_correct_fields(self):
        source = "# RSA-2048"
        result = Discovery().discover_source(source, "test.py")
        asset = result.assets[0]
        assert asset.file_path == "test.py"
        assert asset.algorithm == "RSA-2048"
        assert asset.key_size == 2048
        assert asset.is_quantum_vulnerable is True
        assert asset.cnsa2_deadline_year == 2031
        assert asset.line_number == 1

    def test_ml_kem_768_not_vulnerable(self):
        source = "ML-KEM-768"
        result = Discovery().discover_source(source, "test.py")
        asset = [a for a in result.assets if a.algorithm == "ML-KEM-768"][0]
        assert asset.is_quantum_vulnerable is False

    def test_ml_dsa_65_not_vulnerable(self):
        source = "ML-DSA-65"
        result = Discovery().discover_source(source, "test.py")
        asset = [a for a in result.assets if a.algorithm == "ML-DSA-65"][0]
        assert asset.is_quantum_vulnerable is False

    def test_sha1_has_deadline(self):
        source = "sha1"
        result = Discovery().discover_source(source, "test.py")
        asset = [a for a in result.assets if a.algorithm == "SHA-1"][0]
        assert asset.cnsa2_deadline_year == 2026

    def test_sha256_no_deadline(self):
        source = "SHA-256"
        result = Discovery().discover_source(source, "test.py")
        asset = result.assets[0]
        assert asset.cnsa2_deadline_year is None

    def test_empty_source(self):
        result = Discovery().discover_source("", "test.py")
        assert result.asset_count == 0
        assert len(result.assets) == 0

    def test_non_python_source_regex_only(self):
        source = "# RSA-2048 in a C comment"
        result = Discovery().discover_source(source, "test.c")
        algos = set(a.algorithm for a in result.assets)
        assert "RSA-2048" in algos

    def test_asset_count_property(self):
        source = "RSA-2048\nMD5"
        result = Discovery().discover_source(source, "test.py")
        assert result.asset_count == 2

    def test_get_algorithms_unique(self):
        source = "RSA-2048\nRSA-2048\nMD5"
        result = Discovery().discover_source(source, "test.py")
        algos = result.get_algorithms()
        assert set(algos) == {"RSA-2048", "MD5"}

    def test_discovery_result_to_dict(self):
        source = "MD5"
        result = Discovery().discover_source(source, "test.py")
        d = result.to_dict()
        assert d["file_path"] == "test.py"
        assert len(d["assets"]) == 1
        assert d["assets"][0]["algorithm"] == "MD5"
