# pqblocks-scan

Cryptography inventory scanner for the post-quantum transition. It finds classical and post-quantum algorithms in source code (Python by syntax tree, other languages by pattern) and in a live TLS endpoint's negotiated cipher suite. It then writes a **CycloneDX 1.6** CBOM (Cryptography Bill of Materials), a **SARIF 2.1.0** report and an A–F readiness grade.
Use it to get a first inventory of where RSA, ECC, MD5, SHA-1, AES, ML-KEM and ML-DSA appear in a code base, and to gate CI on it.
It follows CycloneDX 1.6 (`specVersion: "1.6"`), OASIS SARIF 2.1.0, the CNSA 2.0 and NIST IR 8547 transition timelines, and the CARS readiness score (Costa, IACR ePrint 2026/1467).

> **Status: alpha, with known defects.** The pre-release review found one HIGH issue: the CLI silently skips files it cannot read or classify, so a CI gate can pass on code that contains weak cryptography. The CBOM also does not yet validate against the official CycloneDX 1.6 JSON schema. Read [Limitations](#limitations) before relying on it.

```bash
pip install pqblocks-scan
```

```python
from pqblocks_scan.discovery import Discovery
from pqblocks_scan.scorer import CARSScorer
from pqblocks_scan.cbom import CBOMGenerator

src = "import hashlib\nh = hashlib.sha1(b'x').hexdigest()\nfrom pqcrypto.kem import ml_kem_768\n"
assets = Discovery().discover_source(src, "app.py").assets
print([(a.algorithm, a.line_number, a.is_quantum_vulnerable) for a in assets])
# [('ML-KEM-768', 3, False), ('SHA-1', 2, True)]
grade = CARSScorer.evaluate(assets)
print(grade.score, grade.letter)                      # 55.5 C
print(CBOMGenerator.generate(assets)["specVersion"])  # 1.6
```

Command line:

```bash
pqblocks-scan path/to/repo --cbom cbom.json --sarif scan.sarif --fail-on D
pqblocks-scan --tls-host example.org --tls-port 443 --json
```

## Why PQBlocks

- **No runtime dependencies:** standard library only (`ast`, `re`, `ssl`, `socket`, `json`). It runs offline except for `--tls-host`.
- **Tested:** 106 tests, 94 % statement coverage. No test touches the network.
- **Honest:** the CBOM schema gaps, the fail-open CLI path and every heuristic are written down below and in [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md).
- **Licence:** Apache-2.0.

## Usage

**Pipeline.** `Discovery` finds assets, then `DeadlineMapper` attaches CNSA 2.0 / FIPS transition years. `CARSScorer` grades the result, and `CBOMGenerator` and `SARIFGenerator` export it.

**Discovery.**
- `.py` files are parsed with `ast` to catch `hashlib.md5/sha1/sha256`, `hashlib.new("md5"|"sha1"|"sha256")`, `RSA.generate(bits)`, `rsa.generate_private_key(key_size=…)`, `ec.generate_private_key(ec.SECP256R1()|SECP256K1())`, `AES.new(…)` and `from pqcrypto… import ml_kem_768 | ml_dsa_65`.
- Every file, including `.py`, is also scanned line by line with case-insensitive patterns for RSA-1024, RSA-2048, MD5, SHA-1, SHA-256, AES-256, ECDSA-P256, ML-KEM-768, ML-DSA-65, X25519 and Ed25519.
- Hits are deduplicated per (algorithm, line).
- The CLI walks these extensions: `.py .go .rs .js .ts .java .c .cpp`.

**TLS.** `probe_endpoint(host, port)` makes one verified TLS handshake (`ssl.create_default_context()`) and classifies the negotiated cipher-suite name. The certificate is **not** inspected by the live probe. `cert_to_asset()` classifies a certificate only when you pass a normalised dict (`{"sig_alg": ..., "key_size": ...}`).

**Grade.** CARS score `S = 0.20·d1 + 0.25·d2 + 0.25·d3 + 0.15·d4 + 0.15·d5`, each dimension in [0, 100]. Grade bands: A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, else F. With zero assets every dimension is 0, so the grade is F.

**CI gate.** `--fail-on X` returns exit code 1 when the grade is **at or below** X (`--fail-on D` fails on D and F). When no assets are found it returns 0 and prints `CI GATE PASSED`.

## API reference

| Call | Returns / raises |
|---|---|
| `Discovery().discover_source(source: str, file_path: str) -> DiscoveryResult` | `.assets`, `.asset_count`, `.get_algorithms()`, `.to_dict()`. `TypeError` if `source` is not a string. |
| `Discovery().discover_file(path: str) -> DiscoveryResult` | Reads the file as UTF-8. Raises `FileNotFoundError`, `UnicodeDecodeError`, and `ValueError("Unknown algorithm …")` for a key size outside the known set (e.g. `RSA.generate(512)`). |
| `make_asset(algorithm, file_path, line_number, protocol=None, abstraction_isolated=None) -> CryptoAsset` | `ValueError` for an algorithm outside the 23 known names. |
| `probe_endpoint(host, port=443, timeout=5.0, connector=None) -> ProbeResult` | `ValueError` on empty host, a port outside 1..65535 or a timeout ≤ 0. Network and certificate-verification errors propagate. |
| `parse_cipher_suite(name) -> list[(algorithm, key_size)]`, `cipher_to_assets(name, host, port=443)`, `cert_to_asset(cert: dict, host, port=443)` | `TypeError` / `ValueError` on bad input or an unknown name. |
| `CARSScorer.evaluate(assets, has_ci_workflow=False, has_migration_policy=False) -> GradeResult` | `.score`, `.letter`, `.dimensions` (d1..d5 in [0, 1]). `calculate_score` raises `ValueError` on NaN. |
| `DeadlineMapper.map_asset(asset) -> DeadlineFinding \| None`, `DeadlineMapper.map_all(assets)` | Findings sorted by deadline year. |
| `CBOMGenerator.generate(assets, component_name="scanned-application") -> dict`, `CBOMGenerator.to_json(cbom, indent=2)` | CycloneDX 1.6 document. |
| `SARIFGenerator.generate(assets, deadline_findings) -> dict`, `SARIFGenerator.to_json(doc, indent=2)` | SARIF 2.1.0 log. Rule `PQC001` (quantum-vulnerable, warning) or `PQC002` (prohibited, error). |
| `cli.main(argv=None) -> int`, `cli.scan_path(path) -> list[CryptoAsset]` | Console script `pqblocks-scan`. |

`CryptoAsset(asset_id, algorithm, key_size, protocol, file_path, line_number, is_quantum_vulnerable, cnsa2_deadline_year, abstraction_isolated)` rejects `key_size <= 0` and `line_number <= 0`.

## Limitations

- **The CLI fails open (HIGH).** `scan_path` drops any file that raises, without telling you. That covers non-UTF-8 files, unreadable files, and Python files with a key size outside the known set, such as `RSA.generate(512)`. A repository holding only such files reports 0 assets, and `--fail-on` then **passes**. Until this is fixed, do not use the CLI as the only CI gate. Call `Discovery().discover_file` yourself and handle the exceptions.
- **The CBOM does not validate against the official CycloneDX 1.6 JSON schema.** Four distinct violations:
  - `nistQuantumSecurityLevel` is placed directly under `cryptoProperties`; the schema puts it inside `algorithmProperties`.
  - `algorithmProperties.name` is not a schema field.
  - `executionEnvironment: "software-plain"` is not an allowed value.
  - `protocolProperties.type: "TLS"` must be lower-case `tls`.

  Strict consumers may reject the file. SARIF output validates against the OASIS 2.1.0 schema with 0 errors (see [TESTING.md](TESTING.md)).
- **NIST security levels in the CBOM are a heuristic.** A non-vulnerable asset gets level 3 if its name contains "768" or "65", otherwise 5. So ML-KEM-512 and ML-DSA-44 are reported as level 5, where FIPS 203 and FIPS 204 assign categories 1 and 2. Every quantum-vulnerable asset gets 0.
- **Classification differs between paths.**
  - Source discovery marks AES-128 as quantum-vulnerable and AES-256 / SHA-256/384/512 as not.
  - The TLS path marks every non-PQC primitive as vulnerable, AES-256 included.
- **The TLS probe guesses key sizes.** Cipher-suite names carry no key size, so RSA is reported as RSA-2048 and ECDSA as ECDSA-P256. The live probe does not read the certificate. Endpoints with certificates that fail verification raise an error and are not scanned.
- **CLI grades assume CI and policy.** `main()` calls `CARSScorer.evaluate(..., has_ci_workflow=True, has_migration_policy=True)`, so d4 and d5 are always 100 from the CLI. That can add up to 19.5 points. Call `CARSScorer.evaluate` directly for an unbiased grade.
- **The patterns are narrow.**
  - Only the algorithm names listed above are recognised.
  - Comments and docstrings count as hits.
  - `sha[-_]?1` also matches longer tokens that begin with `sha1`.
  - Non-Python languages are covered by these patterns only, not by a parser.
  - Binaries, dynamic or obfuscated names, and dependency manifests are not analysed.
- **CARS:** the grade bands and the default dimension values (d1 = 100 whenever assets exist, d4/d5 = 40/30 when false) are this package's choices. The score has not been compared with the published CARS corpus scores.

## Security notes

The scanner reads files and opens one outbound TLS connection when asked. It performs no cryptography itself. See [SECURITY_NOTES.md](SECURITY_NOTES.md).

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds open, tested building blocks for the post-quantum transition. This package is its cryptography inventory scanner.
