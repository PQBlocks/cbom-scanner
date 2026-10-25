"""
Command Line Interface and CI Gate Enforcer for pqblocks-scan.
"""

import argparse
import sys
import os
import json
from typing import List, Optional
from .discovery import Discovery
from .cbom import CBOMGenerator
from .scorer import CARSScorer
from .deadlines import DeadlineMapper
from .sarif import SARIFGenerator
from .models import CryptoAsset


GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


def scan_path(target_path: str, errors: Optional[List[tuple]] = None) -> List[CryptoAsset]:
    """Scan directory or file for cryptographic assets."""
    if errors is None:
        errors = []
    assets = []
    discovery = Discovery()
    if not os.path.exists(target_path):
        errors.append((target_path, f"Path does not exist: {target_path}"))
        return assets
    if os.path.isfile(target_path):
        try:
            res = discovery.discover_file(target_path)
            assets.extend(res.assets)
        except SyntaxError as exc:
            errors.append((target_path, f"Syntax error: {exc}"))
        except Exception as exc:
            errors.append((target_path, str(exc)))
    elif os.path.isdir(target_path):
        for root, _, files in sorted(os.walk(target_path)):
            for file in sorted(files):
                if file.endswith((".py", ".go", ".rs", ".js", ".ts", ".java", ".c", ".cpp")):
                    fp = os.path.join(root, file)
                    try:
                        res = discovery.discover_file(fp)
                        assets.extend(res.assets)
                    except SyntaxError as exc:
                        errors.append((fp, f"Syntax error: {exc}"))
                    except Exception as exc:
                        errors.append((fp, str(exc)))
    return assets


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="pqblocks-scan: post-quantum cryptography scanner & cbom generator")
    parser.add_argument("path", nargs="?", default=".", help="Path to source directory or file to scan")
    parser.add_argument("--cbom", help="Output path for CycloneDX 1.6 CBOM JSON")
    parser.add_argument("--sarif", help="Output path for SARIF 2.1.0 JSON report")
    parser.add_argument("--fail-on", choices=["A", "B", "C", "D", "F"], help="Fail CI build (exit code 1) if grade is below threshold")
    parser.add_argument("--json", action="store_true", help="Print evaluation result as JSON to stdout")
    parser.add_argument("--tls-host", help="Probe TLS endpoint for cipher suites")
    parser.add_argument("--tls-port", type=int, default=443, help="Port for TLS endpoint probe (default: 443)")
    parser.add_argument("--has-ci", action="store_true", help="Declare presence of CI automated scanning workflow")
    parser.add_argument("--has-policy", action="store_true", help="Declare presence of migration policy")

    args = parser.parse_args(argv)

    errors: List[tuple] = []
    assets = scan_path(args.path, errors) if not args.tls_host else []
    if args.tls_host:
        from .tls_probe import probe_endpoint
        tls_res = probe_endpoint(args.tls_host, args.tls_port)
        assets.extend(tls_res.assets)

    if errors:
        for p, err in errors:
            print(f"Scan error: {p}: {err}")
        if args.fail_on:
            print(f"\nCI GATE FAILED: Scan errors encountered ({len(errors)} file(s) failed to read)")
        return 2

    result = CARSScorer.evaluate(assets, has_ci_workflow=args.has_ci, has_migration_policy=args.has_policy)
    deadlines = DeadlineMapper.map_all(assets)

    if args.cbom:
        cbom_doc = CBOMGenerator.generate(assets)
        with open(args.cbom, "w", encoding="utf-8") as f:
            f.write(CBOMGenerator.to_json(cbom_doc))
        print(f"CBOM written to {args.cbom}")

    if args.sarif:
        sarif_doc = SARIFGenerator.generate(assets, deadlines)
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(SARIFGenerator.to_json(sarif_doc))
        print(f"SARIF report written to {args.sarif}")

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"\n=== pqblocks-scan Assessment Result ===")
        print(f"Total Assets Detected: {len(assets)}")
        print(f"CARS Readiness Score:  {result.score:.1f}/100.0")
        print(f"Assigned Grade:        {result.letter}")
        if deadlines:
            print(f"\nRegulatory Sunset Deadlines ({len(deadlines)} findings):")
            for d in deadlines[:5]:
                print(f"  [{d.cnsa2_deadline_year}] {d.algorithm} ({d.cnsa2_category}): {d.action_required}")

    # Check CI failure condition
    if args.fail_on:
        if len(assets) == 0:
            print("\nCI GATE PASSED: Zero cryptographic assets detected (clean codebase).")
            return 0
        threshold_val = GRADE_ORDER.get(args.fail_on, 0)
        actual_val = GRADE_ORDER.get(result.letter, 0)
        if actual_val <= threshold_val:
            print(f"\nCI GATE FAILED: Grade {result.letter} fails threshold requirement (--fail-on {args.fail_on})")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
