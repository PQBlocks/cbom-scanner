"""Tests for tls_probe.py.

Coverage: live TLS handshake cipher suite and
certificate analyzer. Design constraints honoured here:
- No test touches the network: the live connector is injectable.
- Outputs are CryptoAsset records (models.py), protocol="TLS",
  file_path="tls://host:port", line_number positive.
- Quantum-vulnerability/deadline mapping matches discovery.py:
  PQC (ML-KEM/ML-DSA) not vulnerable; MD5/SHA-1 -> 2026;
  RSA -> 2031; other classical -> vulnerable, no deadline.
"""
import pytest

from pqblocks_scan.models import CryptoAsset


# ---------------------------------------------------------------------------
# parse_cipher_suite — pure substring heuristic over IANA cipher-suite names
# ---------------------------------------------------------------------------

class TestParseCipherSuite:
    def test_rsa_aes_gcm_sha384(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        found = dict(parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
        assert found["RSA-2048"] == 2048
        assert found["AES-256"] == 256
        assert found["SHA-384"] == 384

    def test_ecdsa_aes128_sha256(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        found = dict(parse_cipher_suite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"))
        assert found["ECDSA-P256"] == 256
        assert found["AES-128"] == 128
        assert found["SHA-256"] == 256

    def test_x25519_chacha(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        found = dict(parse_cipher_suite("TLS_ECDHE_X25519_WITH_CHACHA20_POLY1305_SHA256"))
        assert found["X25519"] == 255

    def test_hybrid_kem_maps_to_ml_kem(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        found = dict(parse_cipher_suite("TLS_X25519_MLKEM768_WITH_AES_256_GCM_SHA384"))
        assert found["ML-KEM-768"] == 768

    def test_empty_raises(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        with pytest.raises(ValueError, match="cipher_name must be a non-empty string"):
            parse_cipher_suite("")

    def test_non_string_raises(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        with pytest.raises(TypeError, match="cipher_name must be a string"):
            parse_cipher_suite(None)  # type: ignore[arg-type]

    def test_unknown_cipher_raises(self):
        from pqblocks_scan.tls_probe import parse_cipher_suite
        with pytest.raises(ValueError, match="no known primitives"):
            parse_cipher_suite("TLS_BOGUS_FROBNICATE_WITH_NOTHING")


# ---------------------------------------------------------------------------
# cipher_to_assets — cipher string -> CryptoAsset list
# ---------------------------------------------------------------------------

class TestCipherToAssets:
    def test_assets_carry_tls_context(self):
        from pqblocks_scan.tls_probe import cipher_to_assets
        assets = cipher_to_assets("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "example.com", 443)
        assert len(assets) >= 2
        assert all(isinstance(a, CryptoAsset) for a in assets)
        assert all(a.protocol == "TLS" for a in assets)
        assert all(a.file_path == "tls://example.com:443" for a in assets)
        assert all(a.line_number >= 1 for a in assets)
        algos = {a.algorithm for a in assets}
        assert "RSA-2048" in algos
        assert "AES-256" in algos

    def test_rsa_asset_is_vulnerable_with_deadline(self):
        from pqblocks_scan.tls_probe import cipher_to_assets
        assets = cipher_to_assets("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "example.com", 443)
        rsa = [a for a in assets if a.algorithm == "RSA-2048"][0]
        assert rsa.is_quantum_vulnerable is True
        assert rsa.cnsa2_deadline_year == 2031

    def test_ml_kem_asset_not_vulnerable(self):
        from pqblocks_scan.tls_probe import cipher_to_assets
        assets = cipher_to_assets("TLS_X25519_MLKEM768_WITH_AES_256_GCM_SHA384",
                                  "example.com", 443)
        kem = [a for a in assets if a.algorithm == "ML-KEM-768"][0]
        assert kem.is_quantum_vulnerable is False
        assert kem.cnsa2_deadline_year is None


# ---------------------------------------------------------------------------
# cert_to_asset — simplified peer-cert dict -> CryptoAsset
# ---------------------------------------------------------------------------

class TestCertToAsset:
    def test_rsa_cert(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        asset = cert_to_asset(
            {"sig_alg": "sha256WithRSAEncryption", "key_size": 2048},
            "example.com", 443)
        assert asset.algorithm == "RSA-2048"
        assert asset.key_size == 2048
        assert asset.protocol == "TLS"
        assert asset.is_quantum_vulnerable is True
        assert asset.cnsa2_deadline_year == 2031

    def test_ecdsa_cert(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        asset = cert_to_asset(
            {"sig_alg": "ecdsa-with-SHA256", "key_size": 256},
            "example.com", 443)
        assert asset.algorithm == "ECDSA-P256"
        assert asset.is_quantum_vulnerable is True

    def test_md5_cert_has_2026_deadline(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        asset = cert_to_asset(
            {"sig_alg": "md5WithRSAEncryption", "key_size": 1024},
            "example.com", 443)
        assert asset.algorithm == "RSA-1024"
        assert asset.cnsa2_deadline_year == 2026

    def test_ml_dsa_cert_not_vulnerable(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        asset = cert_to_asset(
            {"sig_alg": "ML-DSA-65", "key_size": 65},
            "example.com", 443)
        assert asset.is_quantum_vulnerable is False
        assert asset.cnsa2_deadline_year is None

    def test_missing_sig_alg_raises(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        with pytest.raises(ValueError, match="sig_alg"):
            cert_to_asset({"key_size": 2048}, "example.com", 443)

    def test_missing_key_size_raises(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        with pytest.raises(ValueError, match="key_size"):
            cert_to_asset({"sig_alg": "sha256WithRSAEncryption"},
                          "example.com", 443)

    def test_unknown_sig_alg_raises(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        with pytest.raises(ValueError, match="Unknown certificate signature algorithm"):
            cert_to_asset({"sig_alg": "frobnicate-9000", "key_size": 128},
                          "example.com", 443)

    def test_nonpositive_key_size_raises(self):
        from pqblocks_scan.tls_probe import cert_to_asset
        with pytest.raises(ValueError, match="key_size must be positive"):
            cert_to_asset({"sig_alg": "sha256WithRSAEncryption", "key_size": 0},
                          "example.com", 443)


# ---------------------------------------------------------------------------
# probe_endpoint — injected connector, no network
# ---------------------------------------------------------------------------

def _fake_connector(host, port, timeout):
    assert host == "example.com"
    return (
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", 256),
        {"sig_alg": "sha256WithRSAEncryption", "key_size": 2048},
    )


class TestProbeEndpoint:
    def test_combines_cipher_and_cert(self):
        from pqblocks_scan.tls_probe import probe_endpoint
        result = probe_endpoint("example.com", 443, 5.0,
                                connector=_fake_connector)
        assert result.host == "example.com"
        assert result.port == 443
        assert result.cipher_name == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        assert result.protocol_version == "TLSv1.3"
        algos = {a.algorithm for a in result.assets}
        assert "RSA-2048" in algos
        assert "AES-256" in algos
        assert result.asset_count == len(result.assets) >= 2

    def test_to_dict_shape(self):
        from pqblocks_scan.tls_probe import probe_endpoint
        result = probe_endpoint("example.com", 443, 5.0,
                                connector=_fake_connector)
        d = result.to_dict()
        assert d["host"] == "example.com"
        assert d["port"] == 443
        assert d["cipher"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        assert isinstance(d["assets"], list) and len(d["assets"]) >= 2
        assert all("algorithm" in a and "is_quantum_vulnerable" in a
                   for a in d["assets"])

    def test_no_cert_still_reports_cipher(self):
        from pqblocks_scan.tls_probe import probe_endpoint

        def no_cert(host, port, timeout):
            return (("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", 128),
                    None)

        result = probe_endpoint("example.com", 443, 5.0, connector=no_cert)
        assert {a.algorithm for a in result.assets} >= {"ECDSA-P256", "AES-128"}

    def test_empty_host_raises(self):
        from pqblocks_scan.tls_probe import probe_endpoint
        with pytest.raises(ValueError, match="host must be a non-empty string"):
            probe_endpoint("", 443, 5.0, connector=_fake_connector)

    def test_bad_port_raises(self):
        from pqblocks_scan.tls_probe import probe_endpoint
        with pytest.raises(ValueError, match="port must be an integer"):
            probe_endpoint("example.com", 0, 5.0, connector=_fake_connector)

    def test_bad_timeout_raises(self):
        from pqblocks_scan.tls_probe import probe_endpoint
        with pytest.raises(ValueError, match="timeout must be positive"):
            probe_endpoint("example.com", 443, -1.0, connector=_fake_connector)

    def test_connector_errors_propagate_loudly(self):
        from pqblocks_scan.tls_probe import probe_endpoint

        def boom(host, port, timeout):
            raise ConnectionError("handshake failed")

        with pytest.raises(ConnectionError, match="handshake failed"):
            probe_endpoint("example.com", 443, 5.0, connector=boom)
