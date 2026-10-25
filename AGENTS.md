# AGENTS.md: pqblocks-scan

Guidance for AI coding agents using this package.

- **Use it for:** a first-pass inventory of cryptographic algorithms in source code or a TLS cipher-suite name, exported as a CycloneDX 1.6 CBOM or SARIF 2.1.0.
- **Install:** `pip install pqblocks-scan`. There are no runtime dependencies.
- **Correct imports:**
  - `from pqblocks_scan.discovery import Discovery`
  - `from pqblocks_scan.cbom import CBOMGenerator`
  - `from pqblocks_scan.sarif import SARIFGenerator`
  - `from pqblocks_scan.deadlines import DeadlineMapper`
  - `from pqblocks_scan.scorer import CARSScorer`
- **Calls:**
  - `assets = Discovery().discover_file(path).assets`
  - `cbom = CBOMGenerator.generate(assets)`
  - `sarif = SARIFGenerator.generate(assets, DeadlineMapper.map_all(assets))`
  - `grade = CARSScorer.evaluate(assets, has_ci_workflow=..., has_migration_policy=...)`
- **CLI:** `pqblocks-scan <path> --cbom cbom.json --sarif scan.sarif --fail-on D`. Exit code 1 means the grade is at or below `D`.

## Pitfalls

- **Do not treat 0 assets as clean.** The CLI silently skips files that raise (non-UTF-8, unknown key size such as `RSA.generate(512)`). If you walk a tree yourself, call `discover_file` and handle `UnicodeDecodeError` and `ValueError` explicitly.
- **The CBOM fails strict CycloneDX 1.6 schema validation** (four known field issues). Do not promise schema-valid output.
- **`nistQuantumSecurityLevel` is a heuristic**, wrong for ML-KEM-512 and ML-DSA-44. Do not quote it as the FIPS category.
- **CLI grades assume CI and a migration policy exist** (d4 = d5 = 100). Use `CARSScorer.evaluate` with real flags for an honest grade.
- **TLS key sizes are guessed** (RSA-2048, ECDSA-P256), and the live probe does not read the certificate.

## Do not

- Do not present the grade as a compliance determination, or the deadline years as verified NSA dates.
- Do not use this package to encrypt, sign or validate anything. It only detects.
- Do not run `--tls-host` against hosts you are not allowed to probe.
