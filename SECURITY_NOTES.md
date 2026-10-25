# Security notes: pqblocks-scan

## What this package is

A **detector**, not a cryptographic library. It reads source files and, if you ask, one TLS handshake, then reports which algorithms it recognised.
- It encrypts, signs, derives and stores nothing.
- There are no keys, no secret material and no constant-time concerns in its own code.
- Its output is an aid for migration planning. It is not a compliance determination.

## What it does not protect against

**Missed findings (known defect, HIGH).**
- The CLI's directory walk skips any file that raises an exception, and does not say so. That includes non-UTF-8 files, unreadable files, and Python files where a key size outside the known set appears, e.g. `RSA.generate(512)`.
- Such files contribute no assets. A tree made only of them reports 0 assets, and `--fail-on` **passes**.
- Mitigation until it is fixed:
  - Do not use the CLI as the only gate.
  - Treat 0 assets on a crypto-using tree as a failure.
  - Or walk the tree yourself with `Discovery().discover_file` and handle `UnicodeDecodeError` and `ValueError`.

**Narrow coverage.**
- 23 algorithm names, matched by patterns. Python syntax-tree detection only for the call shapes listed in the README.
- Dynamic names, binaries, configuration semantics and dependency manifests are not analysed.

**Over-stated levels (MEDIUM).** The CBOM's `nistQuantumSecurityLevel` is a heuristic. It reports level 5 for ML-KEM-512 and ML-DSA-44 (FIPS categories 1 and 2) and for AES-256 / SHA-256.

**Lenient CLI grade (MEDIUM).** The CLI always assumes a CI workflow and a migration policy (d4 = d5 = 100), which raises the grade by up to 19.5 points.

**TLS probe.**
- Reads only the negotiated cipher-suite name. The certificate is not inspected.
- RSA and ECDSA key sizes are assumed (2048, P-256).
- Every non-PQC TLS primitive is marked quantum-vulnerable, including AES-256, which differs from source discovery.

**Deadline years.** These are indicative. The NSA CNSA 2.0 primary documents could not be re-fetched for this release (see EVIDENCE.md).

## Backend and network

- **Backend:** Python standard library only (`ast`, `re`, `ssl`, `socket`, `json`, `uuid`).
- **Network:** only `--tls-host` / `probe_endpoint`. It makes one outbound TCP connection and one handshake with `ssl.create_default_context()`, so certificate and hostname verification are on. Endpoints whose certificate fails verification raise an error and are not reported. Only probe hosts you are authorised to test.

## RNG and zeroization

- **RNG:** `uuid.uuid4()` generates document serial numbers. It is not used for anything secret.
- **Zeroization:** not applicable. No secrets are handled.

## Input handling

- Files are read whole as UTF-8, with no size limit, and parsed with `ast.parse` when they end in `.py`.
- On untrusted trees, cap the input size and run the scanner in a sandbox. Deeply nested Python can exhaust the parser, which is standard-library behaviour.
- The directory walk does not follow directory symlinks, but it does read symlinked files, which can point outside the tree.
- Library entry points validate their arguments: `CryptoAsset` rejects non-positive sizes and lines, `probe_endpoint` checks host, port and timeout, `parse_cipher_suite` and `cert_to_asset` check types. Invalid input raises `ValueError` or `TypeError`.
- Reports contain file paths and line numbers of the scanned tree. Treat them as internal documents.

## Dependencies

There are none at runtime. Tests need `pytest`.

## Audit status

- The package has been checked by its own test suite, by schema validation of its output, and by an internal read-only review whose findings are listed above.
- It has had no external third-party audit.
- It is not a cryptographic module, so FIPS/CMVP validation does not apply. It is not FIPS or CMVP validated.
