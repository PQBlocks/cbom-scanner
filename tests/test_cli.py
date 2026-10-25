"""Tests for CLI Runner and Build Gating."""

import tempfile
import os
from pqblocks_scan.cli import main


def test_cli_clean_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "secure.py")
        with open(test_file, "w") as f:
            f.write("import hashlib\n# no crypto\n")
        rc = main([tmpdir, "--fail-on", "D"])
        assert rc == 0


def test_cli_cbom_and_sarif_export():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "legacy.py")
        with open(test_file, "w") as f:
            f.write("import hashlib\nh = hashlib.md5(b'test')\n")

        cbom_out = os.path.join(tmpdir, "cbom.json")
        sarif_out = os.path.join(tmpdir, "sarif.json")

        rc = main([test_file, "--cbom", cbom_out, "--sarif", sarif_out])
        assert rc == 0
        assert os.path.isfile(cbom_out)
        assert os.path.isfile(sarif_out)


def test_cli_fail_on_trigger():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "vuln.py")
        with open(test_file, "w") as f:
            f.write("import hashlib\nh = hashlib.md5(b'test')\n")
        rc = main([test_file, "--fail-on", "B", "--json"])
        assert rc == 1


def test_cli_tls_host_mock(monkeypatch):
    from pqblocks_scan import tls_probe
    from pqblocks_scan.models import CryptoAsset
    
    asset = CryptoAsset("a1", "ML-KEM-768", 768, "TLS", "tls", 1, False, None, True)
    dummy_res = tls_probe.ProbeResult("test.com", 443, "TLS_AES_256_GCM_SHA384", "TLSv1.3", [asset])
    monkeypatch.setattr(tls_probe, "probe_endpoint", lambda host, port: dummy_res)
    rc = main(["--tls-host", "test.com", "--tls-port", "443"])
    assert rc == 0
