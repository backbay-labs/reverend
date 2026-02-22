#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock_root="$repo_root/.cyntra/locks"
lock_dir="$lock_root/run-loop.lock"
lock_pid_file="$lock_dir/pid"
watchdog_state_path="${CYNTRA_WATCHDOG_STATE_PATH:-$repo_root/.cyntra/state/watchdog-running.json}"
watchdog_events_path="${CYNTRA_WATCHDOG_EVENTS_PATH:-$repo_root/.cyntra/logs/events.jsonl}"
deterministic_failure_codes="${CYNTRA_DETERMINISTIC_FAILURE_CODES:-${CYNTRA_DETERMINISTIC_FAILURE_CLASSES:-runtime.prompt_stall_no_output}}"
enable_failure_fallback="${CYNTRA_ENABLE_FAILURE_FALLBACK:-1}"
watchdog_registered=0
watchdog_runner="run-once"

watchdog_reconcile_and_register() {
  python3 - "$repo_root" "$watchdog_state_path" "$watchdog_events_path" "$watchdog_runner" "$$" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
state_path = Path(sys.argv[2])
events_path = Path(sys.argv[3])
runner = str(sys.argv[4])
current_pid = int(sys.argv[5])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def pid_alive(raw: object) -> bool:
    try:
        pid = int(raw)
    except Exception:
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def load_state(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = payload.get("entries") if isinstance(payload, dict) else []
    return list(rows) if isinstance(rows, list) else []


def save_state(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at_utc": now_iso(),
                "entries": entries,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def append_event(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def archive_orphaned_workcell(path: str) -> str:
    workcell = Path(path)
    if not workcell.is_dir():
        return ""
    try:
        workcell.relative_to(repo_root / ".workcells")
    except ValueError:
        return ""
    if not workcell.name.startswith("wc-"):
        return ""
    archive_root = repo_root / ".cyntra" / "archives" / "orphaned-workcells"
    archive_root.mkdir(parents=True, exist_ok=True)
    archive_path = archive_root / f"{workcell.name}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    workcell.rename(archive_path)
    return str(archive_path)


entries = load_state(state_path)
active_entries: list[dict] = []
for entry in entries:
    pid = entry.get("pid")
    workcell_path = str(entry.get("workcell_path") or "").strip()
    if not pid_alive(pid):
        reason_code = "stale_running_pid_missing"
    elif workcell_path and not Path(workcell_path).exists():
        reason_code = "stale_running_workcell_missing"
    else:
        active_entries.append(entry)
        continue

    action = "drop_stale_running_entry"
    archived_workcell_path = ""
    if reason_code == "stale_running_pid_missing" and workcell_path:
        archived_workcell_path = archive_orphaned_workcell(workcell_path)
        if archived_workcell_path:
            action = "archive_orphaned_workcell"

    remediation_event = {
        "timestamp_utc": now_iso(),
        "event": "watchdog_remediation",
        "reason_code": reason_code,
        "action": action,
        "runner": str(entry.get("runner") or ""),
        "stale_pid": int(pid) if str(pid).isdigit() else str(pid),
        "workcell_id": str(entry.get("workcell_id") or ""),
        "workcell_path": workcell_path,
    }
    if archived_workcell_path:
        remediation_event["archived_workcell_path"] = archived_workcell_path
    append_event(events_path, remediation_event)
    print(
        "[cyntra] watchdog remediation:"
        f" reason_code={reason_code}"
        f" runner={remediation_event['runner'] or 'unknown'}"
        f" stale_pid={remediation_event['stale_pid']}"
    )

workcell_id = ""
workcell_path = ""
workcell_file = repo_root / ".workcell"
if workcell_file.exists():
    try:
        workcell_doc = json.loads(workcell_file.read_text(encoding="utf-8"))
    except Exception:
        workcell_doc = {}
    workcell_id = str(workcell_doc.get("id") or "")
    workcell_path = str(repo_root)

active_entries.append(
    {
        "runner": runner,
        "pid": current_pid,
        "started_at_utc": now_iso(),
        "workcell_id": workcell_id,
        "workcell_path": workcell_path,
    }
)
save_state(state_path, active_entries)
PY
}

watchdog_unregister() {
  python3 - "$watchdog_state_path" "$watchdog_runner" "$$" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

state_path = Path(sys.argv[1])
runner = str(sys.argv[2])
current_pid = int(sys.argv[3])

if not state_path.exists():
    raise SystemExit(0)

try:
    payload = json.loads(state_path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(0)

entries = payload.get("entries") if isinstance(payload, dict) else []
if not isinstance(entries, list):
    entries = []

retained = []
for entry in entries:
    try:
        entry_pid = int(entry.get("pid") or 0)
    except Exception:
        entry_pid = -1
    if str(entry.get("runner") or "") == runner and entry_pid == current_pid:
        continue
    retained.append(entry)

state_path.parent.mkdir(parents=True, exist_ok=True)
state_path.write_text(
    json.dumps(
        {
            "version": 1,
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "entries": retained,
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
}

cleanup_runtime_state() {
  if [[ "$watchdog_registered" == "1" ]]; then
    watchdog_unregister || true
  fi
  rm -rf "$lock_dir"
}

acquire_kernel_lock() {
  mkdir -p "$lock_root"
  if mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "$$" >"$lock_pid_file"
    trap cleanup_runtime_state EXIT INT TERM
    return 0
  fi

  if [[ -f "$lock_pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$lock_pid_file" 2>/dev/null || true)"
    if [[ -n "$existing_pid" ]] && ! kill -0 "$existing_pid" 2>/dev/null; then
      rm -rf "$lock_dir"
      if mkdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$$" >"$lock_pid_file"
        trap cleanup_runtime_state EXIT INT TERM
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
mkdir -p "$repo_root/.cyntra/state" "$repo_root/.cyntra/logs"
if watchdog_reconcile_and_register; then
  watchdog_registered=1
else
  echo "[cyntra] WARN: watchdog reconciliation failed; continuing without runtime state registration" >&2
fi

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
