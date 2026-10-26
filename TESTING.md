# Testing: pqblocks-scan

**Status at release 0.1.0:**
- 130 of 130 tests pass on Python 3.11, 3.12, 3.13 and 3.14.
- Each run used the built wheel, installed in a fresh virtual environment with dependencies from PyPI.
- Statement coverage is 96 % (668 statements, 27 missed).
- No test opens a network connection.

## How to run

```bash
pip install "pqblocks-scan[test]"
pytest -q                                   # from a checkout: pip install -e ".[test]" first
pytest -q --cov=pqblocks_scan --cov-report=term-missing   # needs pytest-cov
```

## Results (measured 2026-10-26 UTC)

| Python | Install source | Tests | Examples |
|---|---|---|---|
| 3.11 | wheel + PyPI dependencies | 130 passed | 3 / 3 passed |
| 3.12 | wheel + PyPI dependencies | 130 passed | 3 / 3 passed |
| 3.13 | wheel + PyPI dependencies | 130 passed | 3 / 3 passed |
| 3.14 | wheel + PyPI dependencies | 130 passed | 3 / 3 passed |

The package has no runtime dependencies. The test extra is pytest, jsonschema and referencing; it resolved to pytest 9.1.1, jsonschema 4.26.0 and referencing 0.37.0.

### Coverage (Python 3.14, from source)

| Module | Statements | Missed | Coverage | Not covered |
|---|---|---|---|---|
| `__init__.py` | 0 | 0 | 100 % | |
| `cbom.py` | 44 | 1 | 98 % | the `other` primitive branch |
| `cli.py` | 99 | 5 | 95 % | the error handlers when the path is a single file; `__main__` |
| `deadlines.py` | 29 | 0 | 100 % | |
| `discovery.py` | 178 | 8 | 96 % | the fallback key size, non-string source, `hashlib.new("sha256")`, keyword key sizes (`bits=` / `key_size=`) |
| `models.py` | 108 | 3 | 97 % | the protocol asset type, the default PQC level, SLH-DSA parameter ids |
| `sarif.py` | 28 | 1 | 96 % | skipping non-vulnerable assets |
| `scorer.py` | 60 | 3 | 95 % | hybrid-signature pairing, NaN rejection, grade C |
| `tls_probe.py` | 122 | 6 | 95 % | SHA-1/MD5 cipher names, non-dict certificate, X25519 certificates, a handshake that returns no cipher |
| **Total** | **668** | **27** | **96 %** | |

## What the tests check

| File | Tests | What it checks |
|---|---|---|
| `test_discovery.py` | 49 | Syntax-tree detection of `hashlib.md5/sha1/sha256` and `hashlib.new(...)`, PyCryptodome and `cryptography` RSA, `ec.SECP256R1`, `AES.new`, `pqcrypto` ML-KEM-768 / ML-DSA-65. Pattern detection of 10 names, case-insensitivity, no match inside words. Exact line numbers. Deduplication. Empty and crypto-free sources. `SyntaxError` / `TypeError` / `FileNotFoundError` / unknown-algorithm `ValueError`. Vulnerability and deadline flags. The `DiscoveryResult` API. |
| `test_tls_probe.py` | 25 | `parse_cipher_suite` on RSA, ECDSA, X25519/ChaCha20 and hybrid ML-KEM names, plus empty, non-string and unknown names. `cipher_to_assets` context and flags. `cert_to_asset` for RSA, ECDSA, MD5-signed and ML-DSA certificates, and its rejections. `probe_endpoint` with an injected connector (no network): cipher + certificate combination, `to_dict` shape, the no-certificate case, host/port/timeout validation, connector errors propagate. |
| `test_models.py` | 18 | `CryptoAsset` fields and validation. `CBOMReport.to_dict` (`specVersion "1.6"`, `cryptoProperties`). `GradeResult` bounds and letters. `DeadlineFinding` categories and years. NIST levels and parameter-set identifiers of the `models` serializer. |
| `test_cli.py` | 4 | Crypto-free directory with `--fail-on D` → exit 0. CBOM and SARIF files written. `--fail-on B` on MD5 → exit 1. `--tls-host` with a patched probe. |
| `test_deadlines.py` | 3 | MD5 → prohibited 2026; RSA-2048 → migration 2031; ML-DSA-65 → no finding. |
| `test_scorer.py` | 3 | All-vulnerable → F (< 40). PQC-only with CI and policy → A (≥ 85). Weights sum to 1. |
| `test_golden.py` | 2 | End-to-end on `tests/golden/`: the legacy MD5 + RSA-1024 file grades F (30.5), the ML-KEM-768 + X25519 hybrid file grades A (90.0). |
| `test_cbom.py` | 1 | CBOM envelope, component names, `assetType`, levels 0 and 3. |
| `test_sarif.py` | 1 | SARIF version, driver name `pqblocks-scan`, rule `PQC001`, level and location. |
| `test_cbom_schema.py` | 4 | CBOM validates against the pinned CycloneDX 1.6 schema |
| `test_review_fixes.py` | 20 | scan errors exit 2, latin-1 fallback, RSA-512, FIPS levels, d4/d5 flags, no certificate read |

## Output validated against the official schemas (run for this release)

Method: a CBOM and a SARIF log were generated from `tests/golden/gold01_legacy.py`, plus the assets of the cipher `ECDHE-RSA-AES128-GCM-SHA256` and an RSA-2048 certificate (8 assets in total). Both were validated with `jsonschema` 4.26.0 against the official schemas, downloaded on 2026-10-25.

| Output | Schema | Result |
|---|---|---|
| SARIF | OASIS `sarif-schema-2.1.0.json` (errata01) | **0 errors** |
| CBOM | CycloneDX bom-1.6.schema.json (+ spdx, jsf-0.82) | **0 errors** (`tests/test_cbom_schema.py`) |

`tests/test_cbom_schema.py` validates `CBOMGenerator` output for all 23 known algorithms, scanned files and TLS assets against the vendored, sha256-pinned schema.

## Official vectors

None apply. The package performs no cryptographic operations, so there are no NIST or ACVP vectors to check. The closest equivalents are the schema validation above and the golden fixtures.

## Examples run as tests

| Example | Check |
|---|---|
| `examples/quickstart.py` | finds exactly MD5 on line 3 and RSA-2048 on line 4; CBOM `specVersion` 1.6 with 2 components |
| `examples/ci_gate.py` | `--fail-on D` exits 1; the CBOM holds MD5 and RSA-1024; SARIF 2.1.0 has two `PQC002` results |
| `examples/tls_cipher_names.py` | three cipher-suite names parse to the hand-derived primitive lists; asset ids are `tls://host:port:n` |

## What is not covered

- **Detection accuracy on real repositories:** precision and recall were not measured.
