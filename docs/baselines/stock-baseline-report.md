# Stock Ghidra Baseline Report

> **Version**: 1.0.0
> **Run Date**: 2026-02-19
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

\* Toy dataset results; real benchmarks pending (REFuSe-Bench, SURE 2025, PatchCorpus)

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

## 4. Provenance & Reproducibility

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

## 5. Regression Policy

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

## 6. Cross-Lane Access

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

See `datasets/datasets.lock.json` for checksums and `docs/research/evaluation-harness.md` for full benchmark specifications.
