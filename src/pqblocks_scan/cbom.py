"""
CycloneDX 1.6 CBOM Serializer for pqblocks-scan.
Generates ECMA-424 compliant Bill of Materials with cryptoProperties.
"""

from typing import Dict, List, Any
import json
import uuid
from datetime import datetime, timezone
from .models import CryptoAsset, CBOMReport, AssetType


NIST_LEVELS = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 5,
    "ML-DSA-44": 2,
    "ML-DSA-65": 3,
    "ML-DSA-87": 5,
}


class CBOMGenerator:
    """Generates CycloneDX 1.6 CBOM with cryptographic extensions."""

    SPEC_VERSION = "1.6"
    JSON_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"

    @classmethod
    def asset_to_crypto_properties(cls, asset: CryptoAsset) -> Dict[str, Any]:
        """Convert a CryptoAsset into CycloneDX 1.6 cryptoProperties dictionary."""
        # Map primitive type
        alg_lower = asset.algorithm.lower()
        if any(k in alg_lower for k in ("kem",)):
            primitive = "kem"
        elif any(k in alg_lower for k in ("ecdh", "dh", "x25519", "x448")):
            primitive = "key-agree"
        elif any(k in alg_lower for k in ("rsa", "ecdsa", "dsa", "ml-dsa", "eddsa", "ed25519")):
            primitive = "signature"
        elif any(k in alg_lower for k in ("aes", "chacha", "des")):
            primitive = "block-cipher"
        elif any(k in alg_lower for k in ("sha", "md5")):
            primitive = "hash"
        else:
            primitive = "other"

        algorithm_props: Dict[str, Any] = {
            "primitive": primitive,
            "parameterSetIdentifier": f"{asset.key_size}",
            "executionEnvironment": "software-plain-ram",
        }
        if asset.algorithm in NIST_LEVELS:
            algorithm_props["nistQuantumSecurityLevel"] = NIST_LEVELS[asset.algorithm]

        props: Dict[str, Any] = {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_props,
        }
        if asset.protocol:
            props["protocolProperties"] = {"type": asset.protocol.lower()}
        return props

    @classmethod
    def generate(cls, assets: List[CryptoAsset], component_name: str = "scanned-application") -> Dict[str, Any]:
        """Generate complete CycloneDX 1.6 CBOM document."""
        serial = f"urn:uuid:{uuid.uuid4()}"
        bom_ref_prefix = serial
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        components = []
        for idx, asset in enumerate(assets):
            comp = {
                "type": "cryptographic-asset",
                "bom-ref": f"{bom_ref_prefix}:crypto-{idx}",
                "name": asset.algorithm,
                "version": "1.0",
                "evidence": {
                    "occurrences": [
                        {
                            "location": asset.file_path,
                            "line": asset.line_number,
                        }
                    ]
                },
                "cryptoProperties": cls.asset_to_crypto_properties(asset),
            }
            components.append(comp)

        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": cls.SPEC_VERSION,
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": now,
                "tools": [
                    {
                        "vendor": "PQBlocks",
                        "name": "pqblocks-scan",
                        "version": "0.1.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": component_name,
                },
            },
            "components": components,
        }
        return cbom

    @classmethod
    def to_json(cls, cbom: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(cbom, indent=indent)
