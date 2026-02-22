#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock_root="$repo_root/.cyntra/locks"
lock_dir="$lock_root/run-loop.lock"
lock_pid_file="$lock_dir/pid"
deterministic_failure_codes="${CYNTRA_DETERMINISTIC_FAILURE_CODES:-${CYNTRA_DETERMINISTIC_FAILURE_CLASSES:-runtime.prompt_stall_no_output}}"
enable_failure_fallback="${CYNTRA_ENABLE_FAILURE_FALLBACK:-1}"

acquire_kernel_lock() {
  mkdir -p "$lock_root"
  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" >"$lock_pid_file"
    trap 'rm -rf "$lock_dir"' EXIT INT TERM
    return 0
  fi

  if [[ -f "$lock_pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$lock_pid_file" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]] && ! kill -0 "$existing_pid" 2>/dev/null; then
      rm -rf "$lock_dir"
      if mkdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$$" >"$lock_pid_file"
        trap 'rm -rf "$lock_dir"' EXIT INT TERM
        return 0
      fi
    fi
  fi

  echo "[cyntra] runner already active; skipping duplicate run-once launch" >&2
  return 1
}

if ! acquire_kernel_lock; then
  exit 0
fi

cd "$repo_root"

scripts/cyntra/preflight.sh
run_started_epoch="$(date +%s)"
if scripts/cyntra/cyntra.sh run --once "$@"; then
  primary_status=0
else
  primary_status=$?
fi

if [[ "$enable_failure_fallback" != "1" ]]; then
  exit "$primary_status"
fi

classify_latest_deterministic_failure() {
  python3 - "$repo_root" "$deterministic_failure_codes" "$run_started_epoch" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
aliases = {
    "prompt_stall_no_output": "runtime.prompt_stall_no_output",
    "runtime.prompt_stall_no_output": "runtime.prompt_stall_no_output",
    "quality_gate_failed": "gate.quality_gate_failed",
    "gate_failed": "gate.quality_gate_failed",
    "gate.quality_gate_failed": "gate.quality_gate_failed",
    "context_missing_on_main": "gate.context_missing_on_main",
    "gate.context_missing_on_main": "gate.context_missing_on_main",
    "completion_blocked": "policy.completion_blocked",
    "policy_blocked": "policy.completion_blocked",
    "policy.completion_blocked": "policy.completion_blocked",
}
known_codes = {
    aliases[token.strip().lower()]
    for token in sys.argv[2].replace(";", ",").split(",")
    if token.strip() and token.strip().lower() in aliases
}
run_started_epoch = int(sys.argv[3])
if not known_codes:
    raise SystemExit(1)

proof_paths = list(repo_root.glob(".workcells/**/proof.json"))
if not proof_paths:
    raise SystemExit(1)

latest = max(proof_paths, key=lambda p: p.stat().st_mtime)
if int(latest.stat().st_mtime) < run_started_epoch:
    raise SystemExit(1)
try:
    proof = json.loads(latest.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)

status = str(proof.get("status") or "").strip().lower()
metadata = proof.get("metadata") or {}
verification = proof.get("verification") or {}
if not isinstance(metadata, dict):
    metadata = {}
if not isinstance(verification, dict):
    verification = {}

detected_code = ""
candidates: list[str] = []
candidates.append(str(proof.get("failure_code") or "").strip())
candidates.append(str(metadata.get("failure_code") or "").strip())
candidates.append(str(verification.get("failure_code") or "").strip())
timeout_reason = str(metadata.get("timeout_reason") or "").strip()
if status == "timeout":
    candidates.append(timeout_reason)
for code in verification.get("blocking_failures") or []:
    candidates.append(str(code).strip())

for candidate in candidates:
    normalized = aliases.get(candidate.lower())
    if normalized and normalized in known_codes:
        detected_code = normalized
        break

if not detected_code:
    raise SystemExit(1)

proof_changed = False
if str(proof.get("failure_code") or "") != detected_code:
    proof["failure_code"] = detected_code
    proof_changed = True
if str(metadata.get("failure_code") or "") != detected_code:
    metadata["failure_code"] = detected_code
    proof["metadata"] = metadata
    proof_changed = True
if str(verification.get("failure_code") or "") != detected_code:
    verification["failure_code"] = detected_code
    proof["verification"] = verification
    proof_changed = True
if proof_changed:
    latest.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

telemetry_path = latest.parent / "telemetry.jsonl"
telemetry = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "event": "failure_code_classified",
    "failure_code": detected_code,
    "issue_id": str(proof.get("issue_id") or ""),
    "workcell_id": str(proof.get("workcell_id") or latest.parent.name or ""),
    "proof_path": str(latest),
}
with telemetry_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(telemetry, ensure_ascii=False) + "\n")

workcell_id = str(proof.get("workcell_id") or latest.parent.name or "")
issue_id = str(proof.get("issue_id") or "")
print(
    json.dumps(
        {
            "failure_code": detected_code,
            "issue_id": issue_id,
            "workcell_id": workcell_id,
            "proof_path": str(latest),
        }
    )
)
PY
}

if [[ -n "${CYNTRA_FAILURE_CODE:-${CYNTRA_FAILURE_CLASS:-}}" ]]; then
  exit "$primary_status"
fi

classification_json="$(classify_latest_deterministic_failure || true)"
if [[ -z "$classification_json" ]]; then
  exit "$primary_status"
fi

failure_code="$(python3 - "$classification_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("failure_code") or ""))
PY
)"
issue_id="$(python3 - "$classification_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("issue_id") or ""))
PY
)"
workcell_id="$(python3 - "$classification_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("workcell_id") or ""))
PY
)"
proof_path="$(python3 - "$classification_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("proof_path") or ""))
PY
)"

if [[ -z "$failure_code" ]]; then
  exit "$primary_status"
fi

echo "[cyntra] deterministic failure classified as failure_code='$failure_code'; attempting fallback route"

if CYNTRA_FAILURE_CODE="$failure_code" \
  CYNTRA_FAILURE_CLASS="$failure_code" \
  CYNTRA_FALLBACK_ISSUE_ID="$issue_id" \
  CYNTRA_FALLBACK_WORKCELL_ID="$workcell_id" \
  CYNTRA_FALLBACK_PROOF_PATH="$proof_path" \
  scripts/cyntra/cyntra.sh run --once "$@"; then
  fallback_status=0
else
  fallback_status=$?
fi

exit "$fallback_status"
