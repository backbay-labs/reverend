# Full Regression and Soak Report (Issue 1701)

Date: 2026-02-21 (UTC)
Branch: `wc/1701/20260220T235353Z`
Workcell: `wc-1701-20260220T235353Z`

## Scope

This run validates E8-S1 acceptance criteria:
1. Regression suite includes executable Java/Python gates.
2. JDK 21 is enforced in CI for Gradle test execution on affected modules.
3. Soak output publishes explicit blocking failures with resolutions/waivers.

## Regression Matrix Results

### Required Quality Gates

| Gate | Command | Result |
|---|---|---|
| test | `bash scripts/cyntra/gates.sh --mode=all` | PASS |
| typecheck | `bash scripts/cyntra/gates.sh --mode=context` | PASS |
| lint | `bash scripts/cyntra/gates.sh --mode=diff` | PASS |
| max-diff-size | diff-check | PASS |
| secret-detection | diff-check | PASS |

### Executable Regression Coverage (`--mode=all`)

| Suite | Command | Result |
|---|---|---|
| ML + backend/python tests | `python3 -m unittest discover -s scripts/ml/tests -p 'test_*.py'` | PASS (`66` tests) |
| Security/schema/dashboard tests | `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | PASS (`15` tests) |
| Java threshold-contract gate | `javac ... scripts/tests/java/MvpGateThresholdRegression.java && java ...` | PASS |

## Blocking Failures, Resolution, and Waiver Status

| Blocking Failure | Evidence | Resolution | Waiver |
|---|---|---|---|
| Regression gate was diff/context-only placeholder (no executable suites). | `scripts/cyntra/gates.sh` before fix ran only manifest/diff checks. | Updated `scripts/cyntra/gates.sh --mode=all` to run executable Python (`scripts/ml/tests`, `scripts/tests`) and Java (`MvpGateThresholdRegression`) gates. | None |
| Dashboard regression target missing (`eval/scripts/mvp_gate_dashboard.py`). | `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` failed with `FileNotFoundError` in `test_mvp_gate_dashboard.py`. | Added `eval/scripts/mvp_gate_dashboard.py` and `eval/config/mvp_gate_thresholds.json`; test now passes and dashboard artifacts are generated. | None |
| CI did not enforce JDK 21 for Gradle test execution in smoke lane and had no affected-module Gradle gate. | `.github/workflows/eval.yaml` smoke lane lacked Java setup + Gradle test step. | Added JDK 21 + Gradle setup and blocking `gradle -p eval/java-regression test` in smoke/nightly/release lanes; added `eval/java-regression` module with toolchain set to Java 21. | None |

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
| `soak-20260220-run1` | PASS | 1.000 | 9.791 | 10.398 | 10.697 |
| `soak-20260220-run2` | PASS | 1.000 | 9.866 | 10.599 | 10.972 |
| `soak-20260220-run3` | PASS | 1.000 | 9.839 | 10.618 | 10.848 |
| `soak-20260220-run4` | PASS | 1.000 | 9.851 | 10.327 | 10.627 |
| `soak-20260220-run5` | PASS | 1.000 | 10.010 | 10.743 | 12.806 |
| `soak-20260220-run6` | PASS | 1.000 | 9.939 | 10.400 | 11.147 |

### Trend Summary

- Gate pass rate: `6/6` runs (`100%`).
- Recall gate stability: delta metric constant at `1.000` across all runs.
- Latency trend:
  - p95 min/mean/max: `10.327 / 10.514 / 10.743 ms`
  - p99 min/mean/max: `10.627 / 11.183 / 12.806 ms`
- Stability gates:
  - `receipt_completeness = 1.0` for all runs
  - `rollback_success_rate = 1.0` for all runs
- Dashboard alerts (`eval/artifacts/mvp-gates/alerts.json`): `0`.

## Acceptance Criteria Check

- [x] Regression suite includes executable Java/Python gates (not placeholders).
- [x] JDK21 toolchain is enforced in CI for Gradle test execution on affected modules.
- [x] Soak and regression results are published with explicit blocking failures and resolutions/waivers.
