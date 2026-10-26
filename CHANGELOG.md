# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-25

### Added
- Source discovery for Python, using the syntax tree plus patterns, and for other text files, using patterns: RSA, ECDSA, MD5, SHA-1/256, AES, ML-KEM-768, ML-DSA-65, X25519 and Ed25519.
- TLS probe and offline cipher-suite and certificate classifiers.
- CycloneDX 1.6 CBOM export with `cryptoProperties`, and SARIF 2.1.0 export with rules `PQC001` and `PQC002`.
- CNSA 2.0 / NIST transition deadline mapping.
- CARS five-dimension readiness score with A–F grade.
- `pqblocks-scan` command line with `--cbom`, `--sarif`, `--json`, `--fail-on`, `--tls-host`, `--tls-port`, `--has-ci` and `--has-policy`; exit code 2 on scan errors.
- Examples: quickstart inventory, CI gate, offline TLS cipher classification.
