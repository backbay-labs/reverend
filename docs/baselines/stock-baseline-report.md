# Stock Ghidra Baseline Report

> **Version**: 1.0.0
> **Run Date**: 2026-02-19
> **Addendum**: R1-S4 non-toy slice run on 2026-02-21
> **Commit**: [`68384f98e3`](../../.git) (2026-02-19)
> **Status**: Published

This document captures the baseline metrics for stock Ghidra capabilities, serving as the comparator for all roadmap improvements. All lanes should reference this baseline when measuring feature impact.

---

## Executive Summary

| Feature Area | Metric | Baseline | Target | Gap |
|---|---|---|---|---|
| **Semantic Search** | Recall@1 | 1.00* | 0.70 | - |
| **Semantic Search** | MRR | 1.00* | 0.75 | - |
| **Type Recovery** | Accuracy | 1.00* | 0.25 | - |
| **Diffing** | Match Rate | 0.67* | 0.90 | 0.23 |
| **ML Integration (non-toy)** | Macro F1 (triage) | 0.848677 -> 0.969697 | 0.95 | +0.121020 |

\* Toy dataset results for smoke lanes (REFuSe-Bench, SURE 2025, PatchCorpus still pending).
Non-toy benchmark evidence is now included in Section 4 (curated triage slice `triage-curated-v2026.02.1`).

---

## 1. Semantic Search Baseline

### Method
- **Approach**: Token-based Jaccard similarity (placeholder for BSim)
- **Dataset**: `toy-similarity-v1` (3 queries, 5 functions)
- **Seed**: 0 (deterministic)

### Results

| Metric | Value | Min Threshold | Notes |
|---|---|---|---|
| Recall@1 | 1.000 | 0.95 | Fraction of queries where correct function is top result |
| MRR | 1.000 | 0.95 | Mean reciprocal rank |

### Target Benchmarks (Pending)
- REFuSe-Bench cross-compiler: Recall@1 >= 0.70
- BinCodex cross-platform: Recall@1 >= 0.55
- Query latency p99 < 2s on 1M-function corpus

### Next Steps
1. Run BSim evaluation on BinaryCorp sample
2. Materialize REFuSe-Bench dataset
3. Measure cross-architecture recall

---

## 2. Type Recovery Baseline

### Method
- **Approach**: Heuristic name-pattern matching (placeholder for Ghidra decompiler)
- **Dataset**: `toy-type-v1` (5 cases)
- **Seed**: 0 (deterministic)

### Results

| Metric | Value | Min Threshold | Notes |
|---|---|---|---|
| Accuracy | 1.000 | 0.95 | Fraction of correctly inferred types |

### Target Benchmarks (Pending)
- SURE 2025 (-O2): Accuracy >= 0.25 (60% improvement over ~15% baseline)
- Realtype (UDTs): Field-level F1 >= 0.40
- ExeBench (composition): Accuracy >= 0.55

### Reference: SURE 2025 Paper
> Ghidra baseline: ~14-15% overall accuracy at -O0 and -O2 optimization levels.
> Source: Soni, "Benchmarking Binary Type Inference Techniques in Decompilers" (SURE 2025)

### Next Steps
1. Download SURE 2025 corpus
2. Extract DWARF ground truth from debug builds
3. Run Ghidra headless analysis on stripped binaries
4. Compare inferred types against ground truth

---

## 3. Binary Diffing Baseline

### Method
- **Approach**: Name-based function matching (placeholder for Version Tracking)
- **Dataset**: `toy-diff-v1` (3 function pairs)
- **Seed**: 0 (deterministic)

### Results

| Metric | Value | Min Threshold | Notes |
|---|---|---|---|
| Match Rate | 0.667 | 0.62 | Fraction of functions correctly paired |
| Coverage | 0.667 | 0.62 | Fraction of functions with any match |

### Target Benchmarks (Pending)
- PatchCorpus-v1: Match rate >= 0.90
- Changed-function detection >= 0.95
- False positive rate <= 0.05

### Next Steps
1. Curate PatchCorpus from security patches
2. Run ghidriff baseline evaluation
3. Measure Version Tracking markup transfer accuracy

---

## 4. Non-Toy Benchmark Delta (R1-S4)

### Scope
- **Dataset slice**: `triage-curated-v2026.02.1` (`12` labeled functions)
- **Materialized path**: `datasets/data/triage-curated-v2026.02.1/benchmark.json`
- **Stock baseline profile**: `entrypoint=0.45`, `hotspot=0.30`, `unknown=0.55`
- **Current implementation profile**: `entrypoint=0.30`, `hotspot=0.25`, `unknown=0.65`
- **Run artifact**: `eval/output/soak/non-toy-report.json`

### Reproducible Commands
```bash
# 1) Materialize the pinned non-toy dataset slice
python3 eval/scripts/datasets.py \
  --lockfile datasets/datasets.lock.json \
  materialize \
  --dataset triage-curated-v2026.02.1

# 2) Execute stock-vs-current comparison in soak runner
PYTHONHASHSEED=0 TZ=UTC LC_ALL=C LANG=C EVAL_SEED=0 \
python3 eval/scripts/run_soak.py \
  --iterations 3 \
  --output eval/output/soak/non-toy-report.json \
  --non-toy-benchmark datasets/data/triage-curated-v2026.02.1/benchmark.json
```

### Measured Delta (Stock vs Current)

| Metric | Stock Baseline | Current | Delta | Target |
|---|---:|---:|---:|---:|
| Macro F1 | 0.848677 | 0.969697 | +0.121020 | >= 0.95 |
| Entrypoint Recall | 0.666667 | 1.000000 | +0.333333 | >= 0.95 |
| Hotspot Recall | 0.800000 | 1.000000 | +0.200000 | >= 0.95 |
| Unknown Precision | 0.750000 | 1.000000 | +0.250000 | >= 0.95 |

### Confidence Bounds and Limitations
- **Confidence bounds (95% Wilson intervals, small-sample):**
  - Stock entrypoint recall (`2/3`): `0.208-0.939`; current entrypoint recall (`3/3`): `0.438-1.000`
  - Stock hotspot recall (`4/5`): `0.376-0.964`; current hotspot recall (`5/5`): `0.566-1.000`
  - Stock unknown precision (`3/4`): `0.301-0.954`; current unknown precision (`3/3`): `0.438-1.000`
- **Known limitations:**
  - This is one curated non-toy slice (`12` rows), not a substitute for full REFuSe-Bench/SURE/PatchCorpus coverage.
  - Results reflect deterministic thresholded scoring on labeled fixtures, not headless Ghidra analysis over raw binaries.
  - Small support counts widen uncertainty; delta direction is clear but interval overlap remains non-trivial.
  - First-iteration runtime includes import/warmup effects; stability should be interpreted from repeated runs.

---

## 5. Provenance & Reproducibility

### Dataset Lock
```
datasets_lock_sha256: bdb02a18c04a144ddbbdccff3cc780bbef08efa2afae23664301f4dec8cc66ca
```

### Git Revision
```
commit: 68384f98e307b5c1b1728fd4c1299e35d3d8efd1
branch: wc/1003/20260220T050556Z
date:   2026-02-19T21:48:11-07:00
```

### Determinism Controls
```bash
PYTHONHASHSEED=0
TZ=UTC
LC_ALL=C
LANG=C
EVAL_SEED=0
```

### Reproduction
```bash
# From repo root
bash eval/run_smoke.sh

# Output: eval/output/smoke/metrics.json
```

---

## 6. Regression Policy

| Severity | Condition | Action |
|---|---|---|
| **Critical** | Any metric drops > 10% vs baseline | Block release |
| **Warning** | Any metric drops 5-10% | Flag for review |
| **Info** | Secondary metric changes > 5% | Log for tracking |

### Automated Gate
```bash
python3 eval/scripts/check_regression.py \
  --baseline eval/snapshots/baseline.json \
  --current eval/output/smoke/metrics.json
```

---

## 7. Cross-Lane Access

This baseline is accessible via:
- **File**: `docs/baselines/stock-baseline-report.md`
- **JSON**: `eval/snapshots/baseline.json`
- **CI Artifact**: `eval/output/smoke/metrics.json`

All lanes (Backend, Plugin/UI, ML, Security, Eval/DevOps) should reference these files when:
- Measuring feature impact against stock Ghidra
- Setting acceptance thresholds for new capabilities
- Reporting metric deltas in weekly demos

---

## Appendix: Dataset Details

### toy-similarity-v1
- 5 synthetic functions with pseudo-code descriptions
- 3 queries with ground-truth mappings
- Purpose: Smoke test for similarity infrastructure

### toy-type-v1
- 5 variable naming patterns with expected types
- Purpose: Smoke test for type inference infrastructure

### toy-diff-v1
- 2 synthetic binaries with 3 renamed functions
- Purpose: Smoke test for diffing infrastructure

### triage-curated-v2026.02.1
- 12 curated, labeled function records for triage scoring calibration
- Purpose: non-toy ML-integration slice for stock-vs-current delta checks

See `datasets/datasets.lock.json` for checksums and `docs/research/evaluation-harness.md` for full benchmark specifications.
