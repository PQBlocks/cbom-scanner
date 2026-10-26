# AGENTS.md: pqblocks-scan

Guidance for AI coding agents using this package.

- **Use it for:** a first-pass inventory of cryptographic algorithms in source code or a TLS cipher-suite name, exported as a CycloneDX 1.6 CBOM or SARIF 2.1.0.
- **Install:** `pip install git+https://github.com/PQBlocks/cbom-scanner`. There are no runtime dependencies.
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

- **Do not treat 0 assets as clean.** Exit code 2 means scan errors; 0 assets with exit 0 can still mean unrecognised crypto.
- **Use `CBOMGenerator`, not `models.CBOMReport`,** for schema-valid CycloneDX 1.6.
- **CLI d4/d5 come from `--has-ci` / `--has-policy`** and are not verified.
- **TLS key sizes are guessed** (RSA-2048, ECDSA-P256), and the live probe does not read the certificate.

## Do not

- Do not present the grade as a compliance determination, or the deadline years as verified NSA dates.
- Do not use this package to encrypt, sign or validate anything. It only detects.
- Do not run `--tls-host` against hosts you are not allowed to probe.
