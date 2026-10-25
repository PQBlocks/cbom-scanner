#!/usr/bin/env python3
"""
Throughput benchmark for pqblocks-scan.
Measures Discovery wall time and lines of code per second on synthetic Python repositories of 5, 25, 100 and 500 files.
Memory is not measured. Writes benchmark_card.json and BENCHMARK-REPORT.md next to this script.
"""
import json
import os
import sys
import time
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pqblocks_scan.discovery import Discovery

SAMPLE_PYTHON_SNIPPET = """
import hashlib
from Crypto.PublicKey import RSA
from pqcrypto.kem import ml_kem_768

def hash_data(data: bytes):
    return hashlib.sha256(data).hexdigest()

def legacy_key():
    return RSA.generate(2048)

def hybrid_key():
    return ml_kem_768.generate_keypair()
"""

def generate_synthetic_repo(dir_path: str, num_files: int):
    os.makedirs(dir_path, exist_ok=True)
    total_loc = 0
    for i in range(num_files):
        fp = os.path.join(dir_path, f"module_{i:04d}.py")
        content = f"# Module {i}\n" + SAMPLE_PYTHON_SNIPPET * 5
        with open(fp, "w") as f:
            f.write(content)
        total_loc += len(content.splitlines())
    return total_loc

def benchmark():
    sizes = [5, 25, 100, 500]  # spanning 2 orders of magnitude (100x)
    results = []
    d = Discovery()

    print("Running pqblocks-scan Discovery Benchmarks...")
    for n in sizes:
        with tempfile.TemporaryDirectory() as tmp:
            loc = generate_synthetic_repo(tmp, n)
            start_t = time.perf_counter()
            total_assets = 0
            for root, _, files in os.walk(tmp):
                for f in files:
                    if f.endswith(".py"):
                        res = d.discover_file(os.path.join(root, f))
                        total_assets += res.asset_count
            duration = time.perf_counter() - start_t
            throughput = loc / duration if duration > 0 else 0
            
            entry = {
                "num_files": n,
                "total_loc": loc,
                "duration_seconds": round(duration, 4),
                "throughput_loc_per_sec": round(throughput, 1),
                "assets_discovered": total_assets
            }
            results.append(entry)
            print(f"  Files: {n:4d} | LOC: {loc:6d} | Time: {duration:6.3f}s | Throughput: {throughput:8.1f} LOC/s | Assets: {total_assets}")

    card = {
        "product": "pqblocks-scan",
        "benchmark_type": "ast_discovery_throughput",
        "sizes_tested": len(sizes),
        "scaling_magnitude": sizes[-1] / sizes[0],
        "results": results,
        "summary": {
            "min_throughput_loc_sec": min(r["throughput_loc_per_sec"] for r in results),
            "max_throughput_loc_sec": max(r["throughput_loc_per_sec"] for r in results),
            "mean_throughput_loc_sec": round(sum(r["throughput_loc_per_sec"] for r in results) / len(results), 1),
        }
    }

    bench_dir = os.path.dirname(os.path.abspath(__file__))
    card_path = os.path.join(bench_dir, "benchmark_card.json")
    with open(card_path, "w") as f:
        json.dump(card, f, indent=2)

    report_path = os.path.join(bench_dir, "BENCHMARK-REPORT.md")
    with open(report_path, "w") as f:
        f.write("# Benchmark Report: pqblocks-scan\n\n")
        f.write("## Scaling Curve across 4 Sizes (>1 order of magnitude)\n\n")
        f.write("| Files | Lines of Code | Duration (s) | Throughput (LOC/s) | Assets Detected |\n")
        f.write("|-------|---------------|--------------|-------------------|-----------------|\n")
        for r in results:
            f.write(f"| {r['num_files']} | {r['total_loc']} | {r['duration_seconds']} | {r['throughput_loc_per_sec']} | {r['assets_discovered']} |\n")
        f.write(f"\n**Mean Scanning Throughput**: {card['summary']['mean_throughput_loc_sec']} LOC/sec\n")

    print(f"Benchmark card saved: {card_path}")
    print(f"Benchmark report saved: {report_path}")

if __name__ == "__main__":
    benchmark()
