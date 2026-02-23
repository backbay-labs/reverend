# E22 Reliability Soak + SLO Artifacts

This directory tracks the artifact contract for reliability soak and SLO gating.

## Artifact Types

- Machine-readable reliability report: `reliability-slo-report.json`
- Human-readable reliability report: `reliability-slo-report.md`

## Generation Commands

Local gate path:

```bash
bash scripts/cyntra/gates.sh --mode=all
```

Manual generation path:

```bash
bash eval/run_soak.sh \
  --iterations 3 \
  --deadlock-threshold-seconds 30 \
  --output eval/output/reliability/soak-report.json

python3 eval/scripts/reliability_slo_report.py \
  --soak-report eval/output/reliability/soak-report.json \
  --thresholds eval/config/reliability_slo_thresholds.json \
  --output-json eval/output/reliability/reliability-slo-report.json \
  --output-md eval/output/reliability/reliability-slo-report.md \
  --fail-on-breach
```

CI publishes the same artifacts from `eval/output/reliability/` in smoke, nightly, and release lanes.
