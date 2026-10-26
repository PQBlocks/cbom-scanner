# Evidence: pqblocks-scan

This file lists where each part of the scanner comes from, and how the code maps to each source. Every DOI below was checked through the Crossref API, and every URL was fetched, on 2026-10-25. Where a check failed, that is stated. When the code departs from a source, the code is authoritative, and the departure is listed.

## Primary sources

### Output formats

1. **CycloneDX Bill of Materials Standard, version 1.6.** OWASP Foundation, released 9 April 2024.
   - JSON schema: `http://cyclonedx.org/schema/bom-1.6.schema.json`, fetched and used for the validation in [TESTING.md](TESTING.md).
   - Reference: https://cyclonedx.org/docs/1.6/json/
   - This is the version the package emits (`"specVersion": "1.6"`), including the 1.6 additions it uses: component type `cryptographic-asset`, `cryptoProperties`, and `evidence.occurrences[].line`.
   - ECMA-424 2nd edition (December 2025) standardises **CycloneDX 1.7**, which this package does **not** emit. The ECMA page lists the 1st edition as June 2024. https://ecma-international.org/publications-and-standards/standards/ecma-424/
2. **Static Analysis Results Interchange Format (SARIF) Version 2.1.0.** OASIS Standard. https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
   - Schema used for validation: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json

### Algorithm standards

3. NIST **FIPS 203**, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 13 August 2024. doi:[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
4. NIST **FIPS 204**, *Module-Lattice-Based Digital Signature Standard*, 13 August 2024. doi:[10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
5. NIST **FIPS 205**, *Stateless Hash-Based Digital Signature Standard*, 13 August 2024. doi:[10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205)

### Transition guidance

6. NIST **IR 8547** (Initial Public Draft), *Transition to Post-Quantum Cryptography Standards*, November 2024. doi:[10.6028/NIST.IR.8547.ipd](https://doi.org/10.6028/NIST.IR.8547.ipd)
   - Used as the `helpUri` of SARIF rule `PQC001`.
7. NIST **SP 800-131A Rev. 2**, *Transitioning the Use of Cryptographic Algorithms and Key Lengths*, March 2019. doi:[10.6028/NIST.SP.800-131Ar2](https://doi.org/10.6028/NIST.SP.800-131Ar2)
   - The SHA-1 deadline text cites it.
8. NIST **SP 800-67 Rev. 2**, *Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher*, November 2017. doi:[10.6028/NIST.SP.800-67r2](https://doi.org/10.6028/NIST.SP.800-67r2)
   - The 3DES deadline text cites it.
9. NIST **FIPS 140-3**, *Security Requirements for Cryptographic Modules*, 2019. doi:[10.6028/NIST.FIPS.140-3](https://doi.org/10.6028/NIST.FIPS.140-3)
   - The DES text and SARIF rule `PQC002` cite it. The MD5 text cites the FIPS 140-2 sunset (21 September 2026).
10. IETF **RFC 7465**, *Prohibiting RC4 Cipher Suites*, February 2015. doi:[10.17487/RFC7465](https://doi.org/10.17487/RFC7465)
11. NSA, *Commercial National Security Algorithm Suite 2.0* (CNSA 2.0) advisory and FAQ.
    - The official PDFs on media.defense.gov returned HTTP 403 to automated fetches, so the deadline years in `deadlines.py` were **not re-checked against the primary document** for this release. Treat them as indicative and confirm against the NSA publication before using them for compliance.

### Readiness score

12. A. D. B. Costa, *Quantum-Safe Cryptography: A Migration Framework for Legacy Systems Toward NIST PQC Standards with the Crypto-Agility Readiness Score*. IACR Cryptology ePrint Archive, 2026/1467 (CC BY). https://eprint.iacr.org/2026/1467
    - The abstract confirms CARS as a five-dimension weighted composite: Inventory Completeness, Algorithm Compliance, Architectural Decoupling, Toolchain Readiness, Governance & Compliance Alignment.
    - The weights (0.20, 0.25, 0.25, 0.15, 0.15) come from the pre-release reading of the paper and could not be re-checked against the PDF for this release, because the download was blocked.
    - The A–F bands and the per-dimension values used by `CARSScorer` are this package's own operationalisation, not the paper's.

## Method to code

| Element | Source | Implementation |
|---|---|---|
| Document envelope | CycloneDX 1.6 | `cbom.CBOMGenerator.generate`: `bomFormat`, `specVersion "1.6"`, `serialNumber` (`urn:uuid:` from `uuid4`), `version 1`, `metadata.timestamp`, `metadata.tools` (vendor PQBlocks, name pqblocks-scan), `metadata.component` |
| Crypto component | CycloneDX 1.6 `cryptographic-asset` | one component per asset, `bom-ref` `<serial>:crypto-<n>`, `evidence.occurrences[{location, line}]` |
| `cryptoProperties` | CycloneDX 1.6 | `assetType "algorithm"`; `algorithmProperties.primitive` mapped from the name (kem / key-agree / signature / block-cipher / hash / other); `parameterSetIdentifier` = key size; `executionEnvironment "software-plain-ram"`; lower-case `protocolProperties.type` for TLS assets. Validates against the CycloneDX 1.6 schema. |
| NIST security level | FIPS 203/204 categories | table `cbom.NIST_LEVELS`: ML-KEM-512/768/1024 → 1/3/5, ML-DSA-44/65/87 → 2/3/5 (FIPS 203 / FIPS 204); omitted for every other asset. |
| SARIF log | SARIF 2.1.0 | `sarif.SARIFGenerator.generate`: one run; driver `pqblocks-scan`; rules `PQC001` (warning) and `PQC002` (error, for assets mapped as `prohibited`); one result per quantum-vulnerable asset with `physicalLocation.region.startLine` |
| Deadlines | CNSA 2.0, SP 800-131A, SP 800-67, RFC 7465, FIPS 140-3 | `deadlines.DeadlineMapper.DEADLINES`: substring match on the upper-cased name. Unmatched vulnerable assets default to `migration` and the asset's year, or 2033. |
| Quantum vulnerability | IR 8547 (RSA/ECC broken by Shor; symmetric and hash keep strength at larger sizes) | `discovery._quantum_vulnerable_and_deadline`: ML-KEM/ML-DSA, AES-256 and SHA-256/384/512 are not vulnerable; everything else is. `tls_probe._vuln_deadline`: only ML-KEM/ML-DSA prefixes are not vulnerable. |
| CARS score | Costa 2026 | `scorer.CARSScorer`: weights as above. d1 = 100 if any asset is found. d2 = share of non-vulnerable assets, counting X25519/ECDH as compliant when ML-KEM is present and Ed25519/ECDSA-P256 when ML-DSA is present. d3 = share of `abstraction_isolated` assets. d4 = 100 or 40. d5 = 100 or 30. Zero assets give all-zero dimensions. NaN raises. |
| Source discovery | Python `ast` + regular expressions | `discovery.ASTDiscovery`, `discovery.RegexDiscovery`, `discovery.Discovery` |
| TLS discovery | TLS cipher-suite names (IANA / OpenSSL spellings) | `tls_probe.parse_cipher_suite`; `probe_endpoint` via `ssl.create_default_context()` + `socket.create_connection` |

## Independent checks

- The generated SARIF was validated against the official OASIS 2.1.0 schema: 0 errors.
- The CBOM from `CBOMGenerator` was validated against the official CycloneDX 1.6 schema (vendored and sha256-pinned in `tests/schemas/`): 0 errors, checked by `tests/test_cbom_schema.py`.
- Two golden fixtures (`tests/golden/`) pin end-to-end grades. The legacy file grades F (30.5) and the hybrid file grades A (90.0).

## Licence and provenance

- Written for this package and distributed under Apache-2.0.
- No third-party scanner code is included.
- Runtime uses the Python standard library only.
