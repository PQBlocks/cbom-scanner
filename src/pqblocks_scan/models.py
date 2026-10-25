"""
Core data structures for pqblocks-scan.

Data model:
- CryptoAsset: individual cryptographic asset record
- CBOMReport: CycloneDX 1.6 report container
- GradeResult: CARS scoring output
- DeadlineFinding: CNSA/FIPS transition finding
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class AssetType(Enum):
    """Asset types for CycloneDX cryptoProperties.assetType."""
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"


@dataclass
class CryptoAsset:
    """
    Represents a cryptographic asset detected during scanning.

    Fields Crypto Asset Representation.
    """
    asset_id: str
    algorithm: str
    key_size: int
    protocol: Optional[str]
    file_path: str
    line_number: int
    is_quantum_vulnerable: bool
    cnsa2_deadline_year: Optional[int]
    abstraction_isolated: bool

    def __post_init__(self) -> None:
        # Validation: key_size must be positive
        if self.key_size <= 0:
            raise ValueError(
                f"key_size must be positive, got {self.key_size} "
                f"(asset_id={self.asset_id!r}, algorithm={self.algorithm!r})"
            )
        # Validation: line_number must be positive
        if self.line_number <= 0:
            raise ValueError(
                f"line_number must be positive, got {self.line_number} "
                f"(asset_id={self.asset_id!r}, algorithm={self.algorithm!r})"
            )


@dataclass
class CBOMReport:
    """
    CycloneDX 1.6 CBOM report container.

    Serializes to a dict following CycloneDX JSON conventions.
    Components are CryptoAsset instances; each gets a cryptoProperties
    block.
    """
    bom_format: str
    version: str
    components: List[CryptoAsset] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the report to a JSON-compatible dict."""
        serialized_components = []
        for asset in self.components:
            comp: Dict[str, Any] = {
                "type": "application",
                "name": asset.algorithm,
                "version": str(asset.key_size),
                "cryptoProperties": _crypto_properties(asset),
            }
            serialized_components.append(comp)

        return {
            "bomFormat": self.bom_format,
            "specVersion": self.version,
            "version": 1,
            "components": serialized_components,
        }


def _crypto_properties(asset: CryptoAsset) -> Dict[str, Any]:
    """
    Build the cryptoProperties block for a component.

    assetType: algorithm | certificate | protocol
    nistQuantumSecurityLevel: 0 (classical/broken) to 5 (FIPS Level 5)
    """
    asset_type = _determine_asset_type(asset.algorithm)
    nist_level = _nist_quantum_security_level(asset)
    parameter_set_id = _parameter_set_identifier(asset)

    props: Dict[str, Any] = {
        "assetType": asset_type.value,
        "nistQuantumSecurityLevel": nist_level,
        "algorithmProperties": {
            "primitive": asset.algorithm,
            "parameterSetIdentifier": parameter_set_id,
        },
    }
    if asset.protocol is not None:
        props["algorithmProperties"]["executionEnvironment"] = asset.protocol
    if asset.cnsa2_deadline_year is not None:
        props["cnsa2DeadlineYear"] = asset.cnsa2_deadline_year
    if asset.abstraction_isolated:
        props["abstractionIsolated"] = True

    return props


def _determine_asset_type(algorithm: str) -> AssetType:
    """
    Classify an algorithm into an assetType.

    Known PQC / KEM / signature / key-exchange primitives → algorithm.
    Anything else that looks like a protocol name → protocol.
    Hashes and ciphers → algorithm (they are primitives, not certs).
    """
    # Protocol names that appear as 'algorithm' in scan results
    _PROTOCOL_NAMES = {
        "TLS", "DTLS", "IPsec", "SSH", "QUIC", "IKEv2", "SCHANNEL", "GSSAPI"
    }
    upper = algorithm.upper()
    if upper in _PROTOCOL_NAMES:
        return AssetType.PROTOCOL
    # Everything else is a crypto primitive (algorithm)
    return AssetType.ALGORITHM


_PQC_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-SHA2-12F", "SLH-DSA-SHA2-12S",
    "SLH-DSA-SHA2-12L", "SLH-DSA-SHA2-12XL",
    "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128S",
    "SLH-DSA-SHA2-128L", "SLH-DSA-SHA2-128XL",
}

_CLASSICAL_KEY_EXCHANGE = {"X25519", "X448", "ECDH-P256", "ECDH-P384", "ECDH-P521"}
_CLASSICAL_SIGNATURE = {"ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "RSA-PKCS1v15", "RSA-PSS", "DSA"}
_WEAK_HASHES = {"MD5", "SHA-1", "SHA-224"}
_STRONG_HASHES = {"SHA-256", "SHA-384", "SHA-512", "SHA-3"}
_SYMMETRIC = {"AES-128", "AES-256", "AES-192", "CHACHA20", "XSalsa20", "GCM"}


def _nist_quantum_security_level(asset: CryptoAsset) -> int:
    """
    Assign NIST quantum security level 0–5.

    - PQC NIST-approved → level 1+
    - Classical key-exchange / signature / hash → level 0 (broken / insufficient)
    - Symmetric ciphers are not quantum-vulnerable in the key-exchange sense,
      but we assign 0 for simplicity (0 = classical/broken).
    """
    alg = asset.algorithm
    if alg in _PQC_ALGORITHMS:
        # ML-KEM-512/768/1024 → level 1, 2, 3 (approx)
        # ML-DSA-44/65/87 → level 1, 3, 5 (approx)
        if alg == "ML-KEM-512":
            return 1
        if alg == "ML-KEM-768":
            return 3
        if alg == "ML-KEM-1024":
            return 5
        if alg == "ML-DSA-44":
            return 2
        if alg == "ML-DSA-65":
            return 3
        if alg == "ML-DSA-87":
            return 5
        return 1  # default for other PQC
    if alg in _CLASSICAL_KEY_EXCHANGE or alg in _CLASSICAL_SIGNATURE:
        return 0
    if alg in _WEAK_HASHES:
        return 0
    if alg in _STRONG_HASHES or alg in _SYMMETRIC:
        return 0
    # Unknown → 0 (conservative)
    return 0


def _parameter_set_identifier(asset: CryptoAsset) -> str:
    """
    Return a NIST-style parameter set identifier.

    Examples:
      RSA-2048  → "fips-186-rsa-2048"
      ML-KEM-768 → "fips-203-ml-kem-768"
      SHA-256    → "fips-180-sha256"
    """
    alg = asset.algorithm.upper()
    if "ML-KEM" in alg:
        return f"fips-203-{alg.lower()}"
    if "ML-DSA" in alg:
        return f"fips-204-{alg.lower()}"
    if "SLH-DSA" in alg:
        return f"fips-205-{alg.lower()}"
    if alg.startswith("RSA"):
        return f"fips-186-{alg.lower()}"
    if alg.startswith("SHA") or alg in _STRONG_HASHES or alg in _WEAK_HASHES:
        return f"fips-180-{alg.lower()}"
    if alg in _SYMMETRIC:
        return f"fips-197-{alg.lower()}"
    return alg.lower()


@dataclass
class GradeResult:
    """
    CARS maturity scoring output.

    score: composite S in [0, 100]
    letter: "A" | "B" | "C" | "D" | "F"
    dimensions: raw dimension scores d1..d5, each in [0, 1]
    """
    score: float
    letter: str
    dimensions: Dict[str, float]

    def __post_init__(self) -> None:
        # Validation: score must be within [0, 100]
        if self.score < 0.0 or self.score > 100.0:
            raise ValueError(
                f"GradeResult.score must be in [0, 100], got {self.score}"
            )
        # Validation: letter must be a valid grade
        valid = {"A", "B", "C", "D", "F"}
        if self.letter not in valid:
            raise ValueError(
                f"GradeResult.letter must be one of {sorted(valid)}, got {self.letter!r}"
            )
        # Validation: all dimensions must be in [0, 1]
        for name, val in self.dimensions.items():
            if val < 0.0 or val > 1.0:
                raise ValueError(
                    f"dimension {name} must be in [0, 1], got {val}"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "letter": self.letter,
            "dimensions": dict(self.dimensions),
        }


@dataclass
class DeadlineFinding:
    """
    CNSA 2.0 / FIPS 140 transition deadline finding.

    cnsa2_category: "migration" | "deprecated" | "prohibited"
    cnsa2_deadline_year: the year the action must be taken
    """
    asset_id: str
    algorithm: str
    cnsa2_category: str
    cnsa2_deadline_year: int
    action_required: str

    def __post_init__(self) -> None:
        # Validation: cnsa2_category must be one of the valid categories
        valid_categories = {"migration", "deprecated", "prohibited"}
        if self.cnsa2_category not in valid_categories:
            raise ValueError(
                f"DeadlineFinding.cnsa2_category must be one of "
                f"{sorted(valid_categories)}, got {self.cnsa2_category!r}"
            )
        # Validation: cnsa2_deadline_year must be a plausible positive year
        if self.cnsa2_deadline_year <= 0:
            raise ValueError(
                f"cnsa2_deadline_year must be a positive year, got {self.cnsa2_deadline_year}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "algorithm": self.algorithm,
            "cnsa2_category": self.cnsa2_category,
            "cnsa2_deadline_year": self.cnsa2_deadline_year,
            "action_required": self.action_required,
        }
