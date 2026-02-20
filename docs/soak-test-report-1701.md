# Full Regression and Soak Report (Issue 1701)

Date: 2026-02-20  
Branch: `wc/1701/20260220T230847Z`  
Workcell: `wc-1701-20260220T230847Z`

## Scope

This run validates E8-S1 acceptance criteria:
1. Regression suite completes on the release candidate.
2. Blocking failures are fixed or explicitly waived.
3. Soak output includes performance and stability trends.

## Regression Matrix Results

### Required Quality Gates

| Gate | Command | Result |
|---|---|---|
| test | `bash scripts/cyntra/gates.sh --mode=all` | PASS |
| typecheck | `bash scripts/cyntra/gates.sh --mode=context` | PASS |
| lint | `bash scripts/cyntra/gates.sh --mode=diff` | PASS |
| max-diff-size | diff-check | PASS |
| secret-detection | diff-check | PASS |

### Full Test Suites

| Suite | Command | Result |
|---|---|---|
| ML + backend/python integration tests | `python3 -m unittest discover -s scripts/ml/tests -p 'test_*.py'` | PASS (`66` tests) |
| Security/schema/dashboard tests | `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | PASS (`15` tests) |

## Blocking Failure and Fix

### Failure

- `scripts/tests/test_mvp_gate_dashboard.py` failed with `FileNotFoundError` for `eval/scripts/mvp_gate_dashboard.py`.

### Root Cause

- The evaluation dashboard implementation referenced by tests/docs (`EVAL-534`) was missing from this workcell.

### Fix Applied

- Added `eval/scripts/mvp_gate_dashboard.py`.
  - Builds `dashboard.json`, `alerts.json`, and `dashboard.md` from run artifacts.
  - Computes current gate status and metric trends.
  - Emits reproducibility metadata (`source_artifacts` with `sha256`).
- Added `eval/config/mvp_gate_thresholds.json`.
  - Defines gate operators/thresholds plus severity/action metadata for alerting.

### Waivers

- None.

## Soak Run

### Execution

Ran six sequential MVP benchmark iterations:

```bash
python3 scripts/ml/local_embedding_pipeline.py benchmark-mvp \
  --target-corpus-size 100000 \
  --recall-query-count 16 \
  --latency-sample-count 120 \
  --run-id soak-20260220-runN \
  --output eval/artifacts/mvp-gates/runs/soak-20260220-runN.json
```

Dashboard/alerts build:

```bash
python3 eval/scripts/mvp_gate_dashboard.py \
  --artifacts-dir eval/artifacts/mvp-gates/runs \
  --thresholds eval/config/mvp_gate_thresholds.json \
  --output-dir eval/artifacts/mvp-gates
```

### Per-Run Metrics

| Run | Status | Recall@10 Delta vs Stock | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---:|---:|---:|---:|
| `soak-20260220-run1` | PASS | 1.000 | 9.958 | 10.290 | 10.889 |
| `soak-20260220-run2` | PASS | 1.000 | 9.792 | 10.106 | 10.683 |
| `soak-20260220-run3` | PASS | 1.000 | 10.032 | 10.602 | 11.008 |
| `soak-20260220-run4` | PASS | 1.000 | 10.104 | 10.753 | 10.952 |
| `soak-20260220-run5` | PASS | 1.000 | 10.784 | 29.579 | 66.263 |
| `soak-20260220-run6` | PASS | 1.000 | 9.966 | 10.816 | 11.193 |

### Trend Summary

- Gate pass rate: `6/6` runs (`100%`).
- Recall gate stability: delta metric constant at `1.000` across all runs.
- Latency trend:
  - p95 min/mean/max: `10.106 / 13.691 / 29.579 ms`
  - p99 min/mean/max: `10.683 / 20.165 / 66.263 ms`
  - one transient latency spike appears in run 5, with immediate recovery in run 6.
- Stability gates:
  - `receipt_completeness = 1.0` for all runs
  - `rollback_success_rate = 1.0` for all runs
- Dashboard alerts (`eval/artifacts/mvp-gates/alerts.json`): empty.

## Acceptance Criteria Check

- [x] Regression suite runs to completion on release candidate.
- [x] All blocking failures have fixes or explicit waivers.
- [x] Soak test report includes performance and stability trends.
