"""
CARS Maturity Scoring Engine for pqblocks-scan.
Computes composite Crypto-Agility Readiness Score (Costa et al. 2026).
"""

from typing import List, Dict, Any, Tuple
from .models import CryptoAsset, GradeResult


class CARSScorer:
    """Computes CARS maturity score across five dimensions."""

    # Weights (Costa et al. 2026)
    W_INVENTORY = 0.20
    W_COMPLIANCE = 0.25
    W_DECOUPLING = 0.25
    W_TOOLCHAIN = 0.15
    W_GOVERNANCE = 0.15

    WEIGHTS = (W_INVENTORY, W_COMPLIANCE, W_DECOUPLING, W_TOOLCHAIN, W_GOVERNANCE)

    @classmethod
    def compute_dimensions(
        cls,
        assets: List[CryptoAsset],
        has_ci_workflow: bool = False,
        has_migration_policy: bool = False
    ) -> Tuple[float, float, float, float, float]:
        """Compute the 5 normalized dimension scores [0.0, 100.0]."""
        if not assets:
            # Empty codebase (0 assets) receives 0.0 across all dimensions (Edge case E6 / E1)
            return (0.0, 0.0, 0.0, 0.0, 0.0)

        # d1: Inventory completeness (audited assets ratio)
        d1 = 100.0

        # Check for hybrid pairing: ML-KEM paired with X25519 or ML-DSA paired with Ed25519
        algorithms = {a.algorithm.upper() for a in assets}
        has_pqc_kem = any("ML-KEM" in alg for alg in algorithms)
        has_pqc_sig = any("ML-DSA" in alg for alg in algorithms)

        def is_asset_compliant(a: CryptoAsset) -> bool:
            if not a.is_quantum_vulnerable:
                return True
            if has_pqc_kem and a.algorithm in ("X25519", "ECDH-P256", "ECDH-P384"):
                return True
            if has_pqc_sig and a.algorithm in ("ED25519", "ECDSA-P256"):
                return True
            return False

        # d2: Algorithm compliance (ratio of non-vulnerable / PQC-approved algorithms)
        compliant_count = sum(1 for a in assets if is_asset_compliant(a))
        d2 = (compliant_count / len(assets)) * 100.0

        # d3: Architectural decoupling (ratio of abstraction-isolated assets)
        decoupled_count = sum(1 for a in assets if a.abstraction_isolated)
        d3 = (decoupled_count / len(assets)) * 100.0

        # d4: Toolchain readiness (CI automated scanning)
        d4 = 100.0 if has_ci_workflow else 40.0

        # d5: Governance alignment (migration policy defined)
        d5 = 100.0 if has_migration_policy else 30.0

        return (d1, d2, d3, d4, d5)

    @classmethod
    def calculate_score(cls, dimensions: Tuple[float, float, float, float, float]) -> float:
        """Calculate weighted composite score S in [0.0, 100.0]."""
        import math
        for d in dimensions:
            if math.isnan(d):
                raise ValueError("Dimension score cannot be NaN")
        d1, d2, d3, d4, d5 = dimensions
        s = (
            cls.W_INVENTORY * d1
            + cls.W_COMPLIANCE * d2
            + cls.W_DECOUPLING * d3
            + cls.W_TOOLCHAIN * d4
            + cls.W_GOVERNANCE * d5
        )
        return round(max(0.0, min(100.0, s)), 2)

    @classmethod
    def assign_grade(cls, score: float) -> str:
        """Assign letter grade thresholds."""
        if score >= 85.0:
            return "A"
        elif score >= 70.0:
            return "B"
        elif score >= 55.0:
            return "C"
        elif score >= 40.0:
            return "D"
        else:
            return "F"

    @classmethod
    def evaluate(
        cls,
        assets: List[CryptoAsset],
        has_ci_workflow: bool = False,
        has_migration_policy: bool = False
    ) -> GradeResult:
        """Evaluate complete GradeResult."""
        dims = cls.compute_dimensions(assets, has_ci_workflow, has_migration_policy)
        score = cls.calculate_score(dims)
        grade = cls.assign_grade(score)
        vulnerable_count = sum(1 for a in assets if a.is_quantum_vulnerable)

        dim_dict = {
            "d1": round(dims[0] / 100.0, 4),
            "d2": round(dims[1] / 100.0, 4),
            "d3": round(dims[2] / 100.0, 4),
            "d4": round(dims[3] / 100.0, 4),
            "d5": round(dims[4] / 100.0, 4),
        }

        return GradeResult(
            score=score,
            letter=grade,
            dimensions=dim_dict,
        )
