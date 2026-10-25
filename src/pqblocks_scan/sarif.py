"""
SARIF 2.1.0 Output Generator for pqblocks-scan.
Integrates with GitHub Code Scanning Security Tab.
"""

from typing import Dict, List, Any
import json
from .models import CryptoAsset, DeadlineFinding


class SARIFGenerator:
    """Generates OASIS SARIF 2.1.0 JSON reports."""

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"

    @classmethod
    def generate(cls, assets: List[CryptoAsset], deadline_findings: List[DeadlineFinding]) -> Dict[str, Any]:
        """Generate complete SARIF 2.1.0 document."""
        rules = [
            {
                "id": "PQC001",
                "name": "QuantumVulnerableAlgorithm",
                "shortDescription": {"text": "Quantum-vulnerable asymmetric algorithm detected"},
                "fullDescription": {"text": "Legacy classical algorithms (RSA, ECC, ECDSA, ECDH) are vulnerable to Shor's algorithm."},
                "defaultConfiguration": {"level": "warning"},
                "helpUri": "https://csrc.nist.gov/pubs/ir/8547/ipd",
            },
            {
                "id": "PQC002",
                "name": "ClassicallyBrokenPrimitive",
                "shortDescription": {"text": "Classically broken or prohibited cryptographic algorithm"},
                "fullDescription": {"text": "Cryptographic primitives like MD5, SHA-1, DES, and RC4 are prohibited under FIPS 140-3."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://csrc.nist.gov/projects/cryptographic-module-validation-program",
            },
        ]

        results = []
        deadline_by_id = {f.asset_id: f for f in deadline_findings}

        for asset in assets:
            if not asset.is_quantum_vulnerable:
                continue

            deadline = deadline_by_id.get(asset.asset_id)
            is_prohibited = deadline and deadline.cnsa2_category == "prohibited"
            rule_id = "PQC002" if is_prohibited else "PQC001"
            level = "error" if is_prohibited else "warning"

            message_text = f"Cryptographic asset {asset.algorithm} detected at line {asset.line_number}."
            if deadline:
                message_text += f" Action required by year {deadline.cnsa2_deadline_year}: {deadline.action_required}."

            result_entry = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": asset.file_path},
                            "region": {
                                "startLine": max(1, asset.line_number),
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            results.append(result_entry)

        sarif_doc = {
            "$schema": cls.SARIF_SCHEMA,
            "version": cls.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pqblocks-scan",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/PQBlocks/cbom-scanner",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_doc

    @classmethod
    def to_json(cls, sarif_doc: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(sarif_doc, indent=indent)
