"""
CNSA 2.0 and FIPS 140-3 Transition Deadline Mapper for pqblocks-scan.
"""

from typing import List, Dict, Optional
from .models import CryptoAsset, DeadlineFinding


class DeadlineMapper:
    """Maps detected cryptographic assets to binding regulatory sunset deadlines."""

    DEADLINES = {
        # Classically broken / prohibited primitives
        "MD5": ("prohibited", 2026, "FIPS 140-2 sunset September 21, 2026; immediate removal required"),
        "SHA-1": ("prohibited", 2026, "NIST SP 800-131A deprecated; replace with SHA-256 or SHA-3"),
        "DES": ("prohibited", 2026, "Disallowed under FIPS 140-3; replace with AES-256"),
        "3DES": ("prohibited", 2026, "NIST SP 800-67 disallowed after 2023; replace with AES-256"),
        "RC4": ("prohibited", 2026, "RFC 7465 prohibited; immediate removal required"),

        # Quantum-vulnerable asymmetric primitives (CNSA 2.0 timeline)
        "RSA-1024": ("prohibited", 2026, "Legacy broken key size; replace with ML-DSA-65 or ML-KEM-768"),
        "RSA-2048": ("migration", 2031, "CNSA 2.0 deprecation by 2030; transition to ML-KEM-768 / ML-DSA-65 by 2031"),
        "RSA-3072": ("migration", 2033, "CNSA 2.0 deprecation by 2033; transition to ML-KEM-768 / ML-DSA-65"),
        "RSA-4096": ("migration", 2035, "CNSA 2.0 exclusive PQC use required by 2035"),
        "ECDSA-P256": ("migration", 2031, "CNSA 2.0 transition required by 2031; replace with ML-DSA-65"),
        "ECDSA-P384": ("migration", 2033, "CNSA 2.0 transition required by 2033; replace with ML-DSA-87"),
        "ECDH-P256": ("migration", 2031, "CNSA 2.0 transition required by 2031; replace with ML-KEM-768"),
        "ECDH-P384": ("migration", 2033, "CNSA 2.0 transition required by 2033; replace with ML-KEM-1024"),
        "X25519": ("migration", 2031, "CNSA 2.0 transition required by 2031; pair with ML-KEM-768 hybrid"),
        "ED25519": ("migration", 2031, "CNSA 2.0 transition required by 2031; pair with ML-DSA-65 hybrid"),
    }

    @classmethod
    def map_asset(cls, asset: CryptoAsset) -> Optional[DeadlineFinding]:
        """Map a single CryptoAsset to a DeadlineFinding if applicable."""
        alg_upper = asset.algorithm.upper()
        # Direct match or substring match
        matched_rule = None
        for key, rule in cls.DEADLINES.items():
            if key in alg_upper or alg_upper == key:
                matched_rule = rule
                break

        if not matched_rule:
            if asset.is_quantum_vulnerable:
                category = "migration"
                deadline_year = asset.cnsa2_deadline_year or 2033
                action = "Quantum-vulnerable primitive; migrate to FIPS 203/204 approved algorithms"
            else:
                return None
        else:
            category, deadline_year, action = matched_rule

        return DeadlineFinding(
            asset_id=asset.asset_id,
            algorithm=asset.algorithm,
            cnsa2_category=category,
            cnsa2_deadline_year=deadline_year,
            action_required=action,
        )

    @classmethod
    def map_all(cls, assets: List[CryptoAsset]) -> List[DeadlineFinding]:
        """Map list of assets to deadline findings sorted by urgency (earliest deadline first)."""
        findings = []
        for a in assets:
            finding = cls.map_asset(a)
            if finding:
                findings.append(finding)
        findings.sort(key=lambda f: (f.cnsa2_deadline_year, f.algorithm))
        return findings
