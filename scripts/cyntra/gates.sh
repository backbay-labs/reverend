#!/usr/bin/env bash
set -euo pipefail

mode="all"
artifact_root="${CYNTRA_GATE_ARTIFACT_DIR:-.cyntra/artifacts/gates}"
for arg in "$@"; do
  case "$arg" in
    --mode=*)
      mode="${arg#*=}"
      ;;
  esac
done

check_manifest_context() {
  python3 - <<'PY'
import json
import sys
from pathlib import Path

manifest = Path("manifest.json")
if not manifest.exists():
    print("[gates] ERROR: missing manifest.json", file=sys.stderr)
    sys.exit(1)

try:
    data = json.loads(manifest.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[gates] ERROR: invalid manifest.json: {exc}", file=sys.stderr)
    sys.exit(1)

issue = data.get("issue") or {}
context_files = issue.get("context_files") or []
missing = []
for rel in context_files:
    if not isinstance(rel, str) or not rel.strip():
        continue
    if not Path(rel).exists():
        missing.append(rel)

if missing:
    print("[gates] ERROR: manifest context files missing in workcell:", file=sys.stderr)
    for rel in missing:
        print(f"  - {rel}", file=sys.stderr)
    sys.exit(1)

print(f"[gates] context OK ({len(context_files)} files)")
PY
}

check_diff_sanity() {
  git diff --check -- . >/dev/null
  if rg -n "^(<<<<<<<|>>>>>>>)" . >/dev/null 2>&1; then
    echo "[gates] ERROR: unresolved merge conflict markers found" >&2
    rg -n "^(<<<<<<<|>>>>>>>)" . || true
    exit 1
  fi
  echo "[gates] diff sanity OK"
}

run_python_regression() {
  echo "[gates] running python regression: scripts/ml/tests"
  python3 -m unittest discover -s scripts/ml/tests -p 'test_*.py'
  echo "[gates] running python regression: scripts/tests"
  python3 -m unittest discover -s scripts/tests -p 'test_*.py'
  echo "[gates] python regression OK"
}

run_java_regression() {
  local java_gate_src="scripts/tests/java/MvpGateThresholdRegression.java"
  local java_gate_out="${artifact_root}/java"
  local thresholds_path="eval/config/mvp_gate_thresholds.json"

  if [[ ! -f "$java_gate_src" ]]; then
    echo "[gates] ERROR: missing Java gate source: $java_gate_src" >&2
    exit 1
  fi
  if [[ ! -f "$thresholds_path" ]]; then
    echo "[gates] ERROR: missing threshold config: $thresholds_path" >&2
    exit 1
  fi
  if ! command -v javac >/dev/null 2>&1; then
    echo "[gates] ERROR: javac not found; Java regression gate cannot run" >&2
    exit 1
  fi
  if ! command -v java >/dev/null 2>&1; then
    echo "[gates] ERROR: java runtime not found; Java regression gate cannot run" >&2
    exit 1
  fi

  mkdir -p "$java_gate_out"
  rm -f "$java_gate_out"/*.class
  javac -d "$java_gate_out" "$java_gate_src"
  java -cp "$java_gate_out" MvpGateThresholdRegression "$thresholds_path"
  echo "[gates] java regression OK (artifacts: $java_gate_out/*.class)"
}

run_eval_regression() {
  local smoke_runner="eval/run_smoke.sh"
  local regression_checker="eval/scripts/check_regression.py"
  local baseline_path="eval/snapshots/baseline.json"
  local eval_gate_out="${artifact_root}/eval"
  local metrics_out="${eval_gate_out}/smoke-metrics.json"
  local regression_out="${eval_gate_out}/regression.json"

  if [[ ! -f "$smoke_runner" ]]; then
    echo "[gates] ERROR: missing smoke runner: $smoke_runner" >&2
    exit 1
  fi
  if [[ ! -f "$regression_checker" ]]; then
    echo "[gates] ERROR: missing regression checker: $regression_checker" >&2
    exit 1
  fi
  if [[ ! -f "$baseline_path" ]]; then
    echo "[gates] ERROR: missing smoke baseline: $baseline_path" >&2
    exit 1
  fi

  mkdir -p "$eval_gate_out"
  bash "$smoke_runner" --output "$metrics_out"
  python3 "$regression_checker" \
    --current "$metrics_out" \
    --baseline "$baseline_path" \
    --output "$regression_out"
  echo "[gates] eval regression OK (artifacts: $metrics_out, $regression_out)"
}

case "$mode" in
  all)
    check_manifest_context
    check_diff_sanity
    run_python_regression
    run_java_regression
    run_eval_regression
    ;;
  context)
    check_manifest_context
    run_python_regression
    ;;
  diff)
    check_diff_sanity
    run_java_regression
    ;;
  *)
    echo "[gates] ERROR: unknown mode '$mode' (expected all|context|diff)" >&2
    exit 1
    ;;
esac
