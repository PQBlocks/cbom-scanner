# Benchmarks: pqblocks-scan

This page measures one thing: how fast `Discovery` scans synthetic Python files.
**No comparison with other scanners was run, so there is no claim of being faster or more accurate than any other tool.**
Detection accuracy on real repositories was not measured either.

Raw data:
- [benchmarks/benchmark-card-2026-09-13.json](benchmarks/benchmark-card-2026-09-13.json): the original run.
- [benchmarks/benchmark-rerun-2026-10-25.json](benchmarks/benchmark-rerun-2026-10-25.json): three re-runs at release.

Script: [benchmarks/run_bench.py](benchmarks/run_bench.py).

## Setup

| Item | Original run | Release re-run |
|---|---|---|
| Date | 2026-09-13 (card file time, 16:40 UTC) | 2026-10-25 (UTC) |
| Hardware | not recorded in the card | Intel Core i5-10300H @ 2.50 GHz, 8 logical CPUs, no GPU |
| Python | not recorded | 3.14.8 |
| Runs | 1 | 3 |

**Method.**
- Generate 5, 25, 100 and 500 Python files. Each file is a header line plus 5 copies of a 13-line snippet using `hashlib.sha256`, `RSA.generate(2048)` and a `pqcrypto` ML-KEM-768 import, which gives 66 lines and 20 assets per file.
- Time `Discovery.discover_file` over every file with `time.perf_counter`, on a single thread.
- Throughput is lines of code ÷ wall time.
- Memory is not measured.

## Results: original run (verbatim from the card)

| Files | Lines of code | Time (s) | Throughput (LOC/s) | Assets |
|---|---|---|---|---|
| 5 | 330 | 0.0076 | 43,243.2 | 100 |
| 25 | 1,650 | 0.0344 | 47,981.3 | 500 |
| 100 | 6,600 | 0.1416 | 46,599.8 | 2,000 |
| 500 | 33,000 | 0.7481 | 44,109.6 | 10,000 |

Mean throughput in the card is 45,483.5 LOC/s (minimum 43,243.2, maximum 47,981.3).

## Results: release re-run (3 runs, same script)

| Files | Run 1 LOC/s | Run 2 LOC/s | Run 3 LOC/s |
|---|---|---|---|
| 5 | 33,627.2 | 33,348.2 | 45,705.4 |
| 25 | 41,120.7 | 35,553.7 | 59,387.7 |
| 100 | 63,124.3 | 57,331.4 | 59,254.5 |
| 500 | 47,572.3 | 62,923.1 | 63,483.0 |

The asset counts matched the original run in all three re-runs (100, 500, 2,000, 10,000).

## Losing cases and caveats

- **Run-to-run variance is large.** The same size varies by up to about 1.7× between runs (25 files: 35,554 vs 59,388 LOC/s). Small sizes take under 0.05 s and are dominated by timer and file-system noise. Treat the numbers as an order of magnitude: tens of thousands of lines per second on one core.
- **The workload is synthetic.** Every file is the same dense crypto snippet. Real code has fewer hits per line and longer lines, and non-Python files skip the syntax-tree pass.
- **There are no baselines.** No other scanner was run on the same input, so these numbers say nothing about relative speed.
- **Accuracy is not measured.** The benchmark counts assets but checks no ground truth. The research plan to compare grades with the published CARS corpus (43 repositories, Costa 2026) was not carried out.

## Reproducing

From a checkout:

```bash
pip install -e .
python benchmarks/run_bench.py      # writes benchmarks/benchmark_card.json and BENCHMARK-REPORT.md
```
