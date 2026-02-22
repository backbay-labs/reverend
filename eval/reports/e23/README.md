# E23 Real-Target Harness Artifacts

`real_target_manifest.json` pins the real-target corpus slices used by `eval/scripts/run_smoke.py`.

## Reproduce Smoke Metrics

```bash
bash eval/run_smoke.sh --output eval/output/smoke/metrics.json
```

## Promote Baseline Snapshot

```bash
python3 eval/scripts/check_regression.py \
  --current eval/output/smoke/metrics.json \
  --promote-area real_target \
  --promote-baseline eval/reports/e23/real_target_baseline.json
```

## Deterministic Diff Check

```bash
python3 eval/scripts/check_regression.py \
  --current eval/output/smoke/metrics.json \
  --baseline eval/reports/e23/real_target_baseline.json \
  --output eval/output/smoke/real_target_regression.json
```
