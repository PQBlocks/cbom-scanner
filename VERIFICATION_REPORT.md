# Verification report: pqblocks-scan 0.1.0

This is a **self-verification** report: what was checked, how, and with what result. It is not a third-party audit or external validation of any kind.

**Release status: not ready.** The release review found one HIGH defect: the CLI fails open on files it cannot read or classify. Under the PQBlocks release policy, a HIGH finding blocks release until it is fixed.

## Summary

| Area | Result |
|---|---|
| Correctness | 106/106 tests pass; 2 golden end-to-end fixtures |
| Coverage | 94 % statements (640 statements, 38 missed) |
| Install as a user gets it | wheel installed from scratch with PyPI dependencies on Python 3.11, 3.12, 3.13 and 3.14: all tests and all 3 examples pass |
| Packaging | sdist and wheel build cleanly; `twine check --strict` passes |
| Dependencies | none at runtime |
| Output formats | SARIF validates against OASIS 2.1.0 (0 errors). CBOM **fails** the CycloneDX 1.6 schema (28 errors, 4 causes) |
| Benchmarks | throughput only; no baselines and no accuracy measurement ([BENCHMARKS.md](BENCHMARKS.md)) |
| Release review | **1 HIGH**, 4 MEDIUM, 4 LOW findings (below) |

## Review checks completed before release

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Scope, sources and standards identified | Pass |
| Check 2 (spec review) | Data model, scoring formula and outputs specified | Pass |
| Check 3 (correctness) | Test suite, golden fixtures, coverage | Pass (106/106, 94 %) |
| Check 4 (benchmark review) | Throughput scaling over 4 sizes | Pass for what was measured (no baselines) |
| Check 5 (adversarial review) | Pathological input, false-safety bugs | Passed at the time, after fixes (listed below). It did not catch the fail-open path below |
| Release check (this report) | Build, metadata, fresh installs on four Pythons, schema validation, read-only security review | **Blocked** by one HIGH finding |

## Release-check evidence (2026-10-25 UTC)

```
build sdist+wheel                  PASS  pqblocks_scan-0.1.0-py3-none-any.whl
twine check --strict               PASS
python 3.11: tests                 PASS  106 passed
python 3.12: tests                 PASS  106 passed
python 3.13: tests                 PASS  106 passed
python 3.14: tests                 PASS  106 passed
examples (ci_gate, quickstart, tls_cipher_names)  PASS on all four versions
leak gate (folder + wheel + sdist) PASS  0 hits
SARIF 2.1.0 schema validation      0 errors
CycloneDX 1.6 schema validation    28 errors (4 causes)
```

## Findings of the release review

| Severity | Where | Finding |
|---|---|---|
| HIGH | `cli.py` `scan_path` | Files that raise are skipped silently: non-UTF-8, unreadable, or a `ValueError` for an unknown key size such as `RSA.generate(512)`. Reproduced: a directory holding MD5 + RSA-512 in one file and a latin-1 file using MD5 reports 0 assets, and `--fail-on D` prints `CI GATE PASSED`, exit 0. |
| MEDIUM | `cbom.py` | `nistQuantumSecurityLevel` heuristic: ML-KEM-512 and ML-DSA-44 are reported as level 5 (FIPS categories 1 and 2). |
| MEDIUM | `cbom.py` | The CBOM fails the CycloneDX 1.6 schema in four fields. |
| MEDIUM | `cli.py` | The CLI grade assumes a CI workflow and a migration policy (d4 = d5 = 100). |
| MEDIUM | `tls_probe.py` | The live probe never reads the certificate. Key sizes are guessed. TLS AES-256 / SHA-384 are marked quantum-vulnerable, which is inconsistent with source discovery. |
| LOW | `cli.py` | `--fail-on X` fails at or below X; the help says "below". |
| LOW | `sarif.py` | The `$schema` URL returns HTTP 404. |
| LOW | `discovery.py` | Loose `sha1` pattern; comments count as hits; no file-size cap; symlinked files are followed. |
| LOW | `cbom.py` | The `bom-ref` prefix and `serialNumber` use different UUIDs. |

## Defects found and fixed before release

Found by the adversarial review and fixed, each confirmed by re-test:
- `make_asset("ED25519")` crashed with key size 0; it now gets 256.
- Non-Python files were fed to the Python parser and then dropped; they now get pattern scanning only.
- An empty asset list scored 100 / A; it now scores 0 / F.
- AES-256 and SHA-256 were marked quantum-vulnerable in source discovery; they no longer are.
- A NaN dimension gave a score of 100; it now raises `ValueError`.
- X25519 was serialised as primitive `other`; it is now `key-exchange`.
- The TLS probe was not reachable from the CLI; `--tls-host` and `--tls-port` were added.

Fixed during this release check:
- Runtime brand strings now read `pqblocks-scan` / `PQBlocks`: the CBOM tool metadata, the SARIF driver and the CLI banner.
- The SARIF `informationUri` now points to https://github.com/PQBlocks/cbom-scanner. The one test asserting the SARIF driver name was updated to the new name.
- The golden fixtures moved to `tests/golden/`, so the suite runs from an installed wheel.

## Known limitations

See the README's Limitations section. In short:
- Narrow pattern coverage (23 algorithm names).
- The live probe does not inspect certificates.
- Deadline years are indicative; the CNSA 2.0 primary documents could not be re-fetched.
- The CARS grade bands are this package's choice and were not compared with published CARS scores.

## Validation status

Not FIPS or CMVP validated, and no such validation applies: this is not a cryptographic module.
