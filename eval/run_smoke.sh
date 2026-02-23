#!/usr/bin/env bash
set -euo pipefail

export PYTHONHASHSEED="0"
export TZ="UTC"
export LC_ALL="C"
export LANG="C"
export EVAL_SEED="${EVAL_SEED:-0}"
export EVAL_REAL_TARGET_MANIFEST="${EVAL_REAL_TARGET_MANIFEST:-eval/reports/e23/real_target_manifest.json}"

exec python3 eval/scripts/run_smoke.py \
  --real-target-manifest "${EVAL_REAL_TARGET_MANIFEST}" \
  "$@"
