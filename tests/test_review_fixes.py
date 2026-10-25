"""Regression tests for the crypto-integration review defects (fail-open scan, NIST levels, d4/d5, TLS claim)."""
import os
import ssl

import pytest

from pqblocks_scan.cbom import CBOMGenerator
from pqblocks_scan.cli import main, scan_path
from pqblocks_scan.discovery import Discovery, make_asset
from pqblocks_scan import tls_probe


def _write(d, name, data, mode="w"):
    p = os.path.join(d, name)
    with open(p, mode) as f:
        f.write(data)
    return p


# --- HIGH: fail-open scan --------------------------------------------------
WEAK = ("import hashlib\nfrom Crypto.PublicKey import RSA\n"
        "h = hashlib.md5(b'x')\nk = RSA.generate(512)\n")


def test_reproducer_md5_rsa512_is_reported_and_gate_fails(tmp_path, capsys):
    _write(tmp_path, "weak.py", WEAK)
    assert main([str(tmp_path), "--fail-on", "D"]) == 1
    out = capsys.readouterr().out
    assert "CI GATE PASSED" not in out
    assets = scan_path(str(tmp_path))
    assert {"MD5", "RSA-512"} <= {a.algorithm for a in assets}
    assert next(a for a in assets if a.algorithm == "RSA-512").is_quantum_vulnerable


def test_latin1_file_is_scanned_not_dropped(tmp_path):
    _write(tmp_path, "latin1.py", "# caf\xe9\nimport hashlib\nh = hashlib.md5(b'x')\n".encode("latin-1"), "wb")
    errors = []
    assets = scan_path(str(tmp_path), errors)
    assert "MD5" in {a.algorithm for a in assets}
    assert errors == []


def test_unreadable_file_is_a_scan_error_and_fails_gate(tmp_path, capsys):
    p = _write(tmp_path, "locked.py", "import hashlib\n")
    os.chmod(p, 0)
    if os.access(p, os.R_OK):
        pytest.skip("running as a user that ignores file modes")
    errors = []
    assert scan_path(str(tmp_path), errors) == []
    assert len(errors) == 1 and "locked.py" in errors[0][0]
    assert main([str(tmp_path), "--fail-on", "F"]) == 2
    out = capsys.readouterr().out
    assert "locked.py" in out and "CI GATE PASSED" not in out and "CI GATE FAILED" in out


def test_syntax_error_python_file_is_a_scan_error(tmp_path):
    _write(tmp_path, "py2.py", "print 'x'\n")
    errors = []
    scan_path(str(tmp_path), errors)
    assert len(errors) == 1 and "syntax" in errors[0][1].lower()
    assert main([str(tmp_path), "--fail-on", "F"]) == 2


def test_scan_errors_exit_2_even_without_fail_on(tmp_path):
    _write(tmp_path, "py2.py", "print 'x'\n")
    assert main([str(tmp_path)]) == 2


def test_missing_path_is_an_error_not_a_clean_pass(tmp_path, capsys):
    assert main([str(tmp_path / "nope"), "--fail-on", "D"]) == 2
    assert "CI GATE PASSED" not in capsys.readouterr().out


def test_unknown_key_sizes_become_findings():
    src = "from Crypto.PublicKey import RSA\nRSA.generate(512)\nRSA.generate(1)\n"
    algs = {a.algorithm for a in Discovery().discover_source(src, "k.py").assets}
    assert {"RSA-512", "RSA-1"} <= algs


def test_make_asset_still_rejects_nonsense():
    with pytest.raises(ValueError, match="Unknown algorithm"):
        make_asset("RSA-", "a.py", 1)


# --- MEDIUM: NIST levels (FIPS 203 / 204) -----------------------------------
@pytest.mark.parametrize("alg,level", [
    ("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5),
    ("ML-DSA-44", 2), ("ML-DSA-65", 3), ("ML-DSA-87", 5)])
def test_nist_levels_per_fips_203_204(alg, level):
    props = CBOMGenerator.asset_to_crypto_properties(make_asset(alg, "f.py", 1))
    assert props["algorithmProperties"]["nistQuantumSecurityLevel"] == level


def test_models_serializer_agrees_with_cbom_levels():
    from pqblocks_scan.models import _nist_quantum_security_level
    for alg, level in [("ML-KEM-768", 3), ("ML-KEM-1024", 5), ("ML-DSA-44", 2)]:
        assert _nist_quantum_security_level(make_asset(alg, "f.py", 1)) == level


def test_unmapped_level_is_omitted_not_guessed():
    props = CBOMGenerator.asset_to_crypto_properties(make_asset("SHA-512", "f.py", 1))
    assert "nistQuantumSecurityLevel" not in props["algorithmProperties"]


# --- MEDIUM: d4 / d5 are declared, never assumed ---------------------------
def test_d4_d5_default_to_unset_and_flags_declare_them(tmp_path, capsys):
    import json
    p = _write(tmp_path, "v.py", "import hashlib\nhashlib.md5(b'x')\n")
    main([p, "--json"])
    d = json.loads(capsys.readouterr().out)["dimensions"]
    assert (d["d4"], d["d5"]) == (0.4, 0.3)
    main([p, "--json", "--has-ci", "--has-policy"])
    d = json.loads(capsys.readouterr().out)["dimensions"]
    assert (d["d4"], d["d5"]) == (1.0, 1.0)


# --- MEDIUM: TLS probe does not claim certificate inspection ---------------
def test_live_connector_never_reads_a_certificate(monkeypatch):
    class FakeTLS:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def cipher(self): return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        def getpeercert(self, *a, **k): raise AssertionError("certificate must not be read")

    class FakeCtx:
        def wrap_socket(self, raw, server_hostname=None): return FakeTLS()

    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeCtx())
    monkeypatch.setattr(tls_probe.socket, "create_connection", lambda *a, **k: FakeSock())
    res = tls_probe.probe_endpoint("h.example", 443)
    assert all(not a.asset_id.endswith(":cert") for a in res.assets)


def test_cli_help_does_not_claim_certificates(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "certificate" not in capsys.readouterr().out.lower()


def test_tls_module_doc_states_no_certificate_inspection():
    assert "does not inspect" in tls_probe.__doc__
