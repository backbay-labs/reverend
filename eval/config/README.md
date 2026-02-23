# Eval Threshold Configs

This directory stores versioned threshold contracts that are enforced as blocking gates in local and CI workflows.

## Files

- `mvp_gate_thresholds.json`: MVP dashboard gate definitions used by `eval/scripts/mvp_gate_dashboard.py`.
- `reliability_slo_thresholds.json`: soak reliability SLO thresholds used by `eval/scripts/reliability_slo_report.py`.
- `query_slo_thresholds.json`: query latency/quality SLO thresholds used by `eval/scripts/query_slo_report.py`.

## Query SLO Gate

The query SLO gate evaluates `real_target` smoke metrics against pinned thresholds:

- quality: `mrr`, `recall@1`, `recall@5`
- latency: `latency_p95_ms`

Run locally:

```bash
bash eval/run_smoke.sh --output eval/output/smoke/metrics.json
python3 eval/scripts/query_slo_report.py \
  --metrics eval/output/smoke/metrics.json \
  --thresholds eval/config/query_slo_thresholds.json \
  --output-json eval/output/query-slo/slo-report.json \
  --output-md eval/output/query-slo/slo-report.md \
  --fail-on-breach
```

When thresholds change, update the JSON file in this directory in the same commit as the code/data change and include the regenerated SLO report artifacts in CI.
