#!/usr/bin/env bash
set -euo pipefail

export PYTHONHASHSEED="0"
export TZ="UTC"
export LC_ALL="C"
export LANG="C"
export EVAL_SEED="${EVAL_SEED:-0}"

exec python3 eval/scripts/run_soak.py "$@"
