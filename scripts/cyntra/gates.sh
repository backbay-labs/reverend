#!/usr/bin/env bash
set -euo pipefail

mode="all"
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

case "$mode" in
  all)
    check_manifest_context
    check_diff_sanity
    ;;
  context)
    check_manifest_context
    ;;
  diff)
    check_diff_sanity
    ;;
  *)
    echo "[gates] ERROR: unknown mode '$mode' (expected all|context|diff)" >&2
    exit 1
    ;;
esac
