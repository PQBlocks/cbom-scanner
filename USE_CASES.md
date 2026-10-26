# Use cases: pqblocks-scan

Each runnable script below lives in `examples/` and prints its own check.

## 1. First cryptography inventory of a code base

You need to know where MD5, SHA-1, RSA and ECC live before planning a migration to ML-KEM and ML-DSA, and you want it as a CycloneDX 1.6 CBOM.

```bash
python examples/quickstart.py
```

```
assets found: [('MD5', 3, True), ('RSA-2048', 4, True)]
CBOM: CycloneDX 1.6 with 2 components
check passed: True
```

On a real tree: `pqblocks-scan path/to/repo --cbom cbom.json`. Unreadable or unparsable files are reported as scan errors, and the CLI exits 2.

## 2. Code-scanning results and a CI gate

You want findings in GitHub code scanning (SARIF) and a build that fails on prohibited algorithms.

```bash
python examples/ci_gate.py
```

```
exit code: 1
CBOM components: ['MD5', 'RSA-1024']
SARIF 2.1.0 results: ['PQC002', 'PQC002']
check passed: True
```

`--fail-on D` fails on grade D or F. Exit code 2 means some files could not be scanned. Also fail the job when the scan reports 0 assets on a tree you know uses cryptography.

## 3. Classifying TLS cipher suites offline

You have cipher-suite names from server logs or a TLS scanner, and want each primitive classified without connecting anywhere.

```bash
python examples/tls_cipher_names.py
```

```
TLS_AES_256_GCM_SHA384           -> [('AES-256', 256), ('SHA-384', 384)]
ECDHE-RSA-AES128-GCM-SHA256      -> [('RSA-2048', 2048), ('AES-128', 128), ('SHA-256', 256)]
ECDHE-ECDSA-CHACHA20-POLY1305    -> [('ECDSA-P256', 256), ('CHACHA20', 256)]
check passed: True
```

Against a live server: `pqblocks-scan --tls-host example.org --json`. Only the negotiated cipher is read, not the certificate.

## When to use something else

- **You need a complete, audit-grade inventory.** This scanner recognises 23 algorithm names with narrow patterns. Use it as a first pass next to a full SAST tool or a binary scanner.
- **A strict consumer must accept the CBOM.** `CBOMGenerator` output validates against the CycloneDX 1.6 schema; `models.CBOMReport.to_dict()` output does not.
- **You need certificate-chain analysis.** The live probe does not read certificates.
