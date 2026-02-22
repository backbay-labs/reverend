#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock_root="$repo_root/.cyntra/locks"
lock_dir="$lock_root/run-loop.lock"
lock_pid_file="$lock_dir/pid"
watchdog_state_path="${CYNTRA_WATCHDOG_STATE_PATH:-$repo_root/.cyntra/state/watchdog-running.json}"
watchdog_events_path="${CYNTRA_WATCHDOG_EVENTS_PATH:-$repo_root/.cyntra/logs/events.jsonl}"
watchdog_registered=0
watchdog_runner="run-watch"

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

  echo "[cyntra] runner already active; skipping duplicate run-watch launch" >&2
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
scripts/cyntra/cyntra.sh run --watch "$@"
