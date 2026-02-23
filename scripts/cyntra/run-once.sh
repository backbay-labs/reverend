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
supervised_stall_timeout_seconds="${CYNTRA_SUPERVISED_STALL_TIMEOUT_SECONDS:-300}"
supervised_stall_poll_seconds="${CYNTRA_SUPERVISED_STALL_POLL_SECONDS:-1}"
supervised_activity_paths="${CYNTRA_SUPERVISED_ACTIVITY_PATHS:-$repo_root/.cyntra/logs/events.jsonl,$repo_root/telemetry.jsonl}"
watchdog_registered=0
watchdog_runner="run-once"
primary_failure_code=""
primary_supervision_reason=""
primary_supervision_inactivity_seconds=""
primary_issue_id=""
primary_workcell_id=""

read_workcell_field() {
  local field_name="${1:-}"
  local workcell_path="$repo_root/.workcell"
  [[ -n "$field_name" && -f "$workcell_path" ]] || return 1
  python3 - "$workcell_path" "$field_name" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
field = str(sys.argv[2])
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)
value = payload.get(field)
if value is None:
    raise SystemExit(1)
print(str(value))
PY
}

emit_supervision_failure_telemetry() {
  local failure_code="${1:-}"
  local reason_code="${2:-}"
  local inactivity_seconds="${3:-}"
  local timeout_seconds="${4:-}"
  local issue_id="${5:-}"
  local workcell_id="${6:-}"
  [[ -n "$failure_code" ]] || return 0

  python3 - "$repo_root" "$failure_code" "$reason_code" "$inactivity_seconds" "$timeout_seconds" "$issue_id" "$workcell_id" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

repo_root = Path(sys.argv[1])
failure_code = str(sys.argv[2])
reason_code = str(sys.argv[3])
inactivity_seconds_raw = str(sys.argv[4]).strip()
timeout_seconds_raw = str(sys.argv[5]).strip()
issue_id = str(sys.argv[6])
workcell_id = str(sys.argv[7])


def _to_float(raw: str) -> float | None:
    try:
        return round(float(raw), 3)
    except Exception:
        return None


event = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "event": "failure_code_classified",
    "failure_code": failure_code,
    "reason_code": reason_code,
    "classification_source": "supervision",
    "issue_id": issue_id,
    "workcell_id": workcell_id,
    "proof_path": "",
}
inactivity_seconds = _to_float(inactivity_seconds_raw)
timeout_seconds = _to_float(timeout_seconds_raw)
if inactivity_seconds is not None:
    event["inactivity_seconds"] = inactivity_seconds
if timeout_seconds is not None:
    event["stall_timeout_seconds"] = timeout_seconds

events_path = repo_root / ".cyntra" / "logs" / "events.jsonl"
events_path.parent.mkdir(parents=True, exist_ok=True)
with events_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(event, ensure_ascii=False) + "\n")

if workcell_id:
    workcell_telemetry_path = repo_root / ".workcells" / workcell_id / "telemetry.jsonl"
    workcell_telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    with workcell_telemetry_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
PY
}

run_primary_once_supervised() {
  local supervision_path=""
  local supervision_json=""
  supervision_path="$(mktemp "${TMPDIR:-/tmp}/cyntra-run-once-supervision.XXXXXX.json")"
  python3 - "$repo_root" "$supervised_stall_timeout_seconds" "$supervised_stall_poll_seconds" "$supervised_activity_paths" "$supervision_path" scripts/cyntra/cyntra.sh run --once "$@" <<'PY'
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(sys.argv[1])
try:
    timeout_seconds = float(sys.argv[2])
except Exception:
    timeout_seconds = 0.0
try:
    poll_seconds = float(sys.argv[3])
except Exception:
    poll_seconds = 1.0
activity_paths_raw = str(sys.argv[4])
result_path = Path(sys.argv[5])
command = sys.argv[6:]
if not command:
    result_path.write_text(
        json.dumps({"status": "invalid", "exit_code": 2, "error": "missing command"}),
        encoding="utf-8",
    )
    raise SystemExit(0)

activity_paths = []
for token in activity_paths_raw.replace(";", ",").split(","):
    text = token.strip()
    if text:
        activity_paths.append(Path(text))
poll_seconds = max(0.1, min(poll_seconds, 5.0))
stall_guard_enabled = timeout_seconds > 0


def stat_mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except Exception:
        return None


mtimes = {str(path): stat_mtime(path) for path in activity_paths}
started = time.monotonic()
last_activity = started

proc = subprocess.Popen(command, cwd=repo_root, preexec_fn=os.setsid)
while True:
    now = time.monotonic()
    changed = False
    for path in activity_paths:
        key = str(path)
        current = stat_mtime(path)
        previous = mtimes.get(key)
        if current is not None and (previous is None or current > previous):
            mtimes[key] = current
            changed = True
        elif previous is None and current is None:
            mtimes[key] = None
    if changed:
        last_activity = now

    code = proc.poll()
    inactivity_seconds = max(0.0, now - last_activity)
    if code is not None:
        result_path.write_text(
            json.dumps(
                {
                    "status": "completed",
                    "exit_code": int(code),
                    "elapsed_seconds": round(now - started, 3),
                    "inactivity_seconds": round(inactivity_seconds, 3),
                }
            ),
            encoding="utf-8",
        )
        raise SystemExit(0)

    if stall_guard_enabled and inactivity_seconds >= timeout_seconds:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        stop_deadline = time.monotonic() + 5.0
        while proc.poll() is None and time.monotonic() < stop_deadline:
            time.sleep(0.1)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        code = proc.wait()
        result_path.write_text(
            json.dumps(
                {
                    "status": "stalled",
                    "exit_code": int(code),
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "inactivity_seconds": round(inactivity_seconds, 3),
                    "stall_timeout_seconds": round(timeout_seconds, 3),
                }
            ),
            encoding="utf-8",
        )
        raise SystemExit(0)

    time.sleep(poll_seconds)
PY
  supervision_json="$(cat "$supervision_path")"
  rm -f "$supervision_path"

  local supervision_status
  supervision_status="$(python3 - "$supervision_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("status") or "invalid"))
PY
)"
  primary_status="$(python3 - "$supervision_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
value = payload.get("exit_code")
if isinstance(value, bool):
    print(1 if value else 0)
else:
    try:
        print(int(value))
    except Exception:
        print(1)
PY
)"

  if [[ "$supervision_status" == "stalled" ]]; then
    primary_failure_code="runtime.prompt_stall_no_output"
    primary_supervision_reason="supervision.inactivity_timeout"
    primary_supervision_inactivity_seconds="$(python3 - "$supervision_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
value = payload.get("inactivity_seconds")
try:
    print(f"{float(value):.3f}")
except Exception:
    print("")
PY
)"
    echo "[cyntra] supervision timeout: classified runtime.prompt_stall_no_output (inactivity=${primary_supervision_inactivity_seconds:-unknown}s timeout=${supervised_stall_timeout_seconds}s)"
    emit_supervision_failure_telemetry \
      "$primary_failure_code" \
      "$primary_supervision_reason" \
      "$primary_supervision_inactivity_seconds" \
      "$supervised_stall_timeout_seconds" \
      "$primary_issue_id" \
      "$primary_workcell_id"
    primary_status=124
  fi
}

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
primary_issue_id="$(read_workcell_field issue_id || true)"
primary_workcell_id="$(read_workcell_field id || true)"
run_started_epoch="$(date +%s)"
run_primary_once_supervised "$@"

if [[ "$enable_failure_fallback" != "1" ]]; then
  exit "$primary_status"
fi

classify_latest_deterministic_failure() {
  python3 - "$repo_root" "$deterministic_failure_codes" "$run_started_epoch" <<'PY'
import json
import os
import re
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
known_codes = set()
for token in sys.argv[2].replace(";", ",").split(","):
    raw = token.strip().lower()
    if raw and raw in aliases:
        known_codes.add(aliases[raw])
run_started_epoch = int(sys.argv[3])

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
gate_summary = verification.get("gate_summary") or {}
if not isinstance(gate_summary, dict):
    gate_summary = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_int(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            try:
                return int(text)
            except Exception:
                return None
    return None


def _first_int(*values):
    for value in values:
        parsed = _as_int(value)
        if parsed is not None:
            return parsed
    return None


def _first_text(*values):
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return ""


def _normalized_reason(value: str) -> str:
    text = value.strip().lower()
    return re.sub(r"[\s_\-]+", " ", text)


def _split_tokens(raw: str) -> list[str]:
    tokens = []
    for token in re.split(r"[,;|]", raw):
        text = token.strip()
        if text:
            tokens.append(text)
    return tokens


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def load_manifest(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def manifest_noop_justification(manifest: dict) -> tuple[str, str]:
    if not manifest:
        return "", ""
    issue = manifest.get("issue")
    if isinstance(issue, dict):
        reason = _first_text(issue.get("noop_justification"))
        if reason:
            return reason, "manifest.issue.noop_justification"
    reason = _first_text(manifest.get("noop_justification"))
    if reason:
        return reason, "manifest.noop_justification"
    return "", ""


def parse_skip_entry(raw: object) -> dict[str, str]:
    if isinstance(raw, dict):
        gate = _first_text(raw.get("gate"), raw.get("name"), raw.get("module"), raw.get("id"))
        reason = _first_text(raw.get("reason"), raw.get("skip_reason"), raw.get("status_reason"))
        status = _first_text(raw.get("status"), raw.get("result")) or "skipped"
        return {"gate": gate, "reason": reason, "status": status}
    if isinstance(raw, str):
        text = raw.strip()
        if text:
            return {"gate": text, "reason": "", "status": "skipped"}
    return {"gate": "", "reason": "", "status": ""}


def parse_module_coverage_skip(module: str, value: object) -> dict[str, str]:
    if not isinstance(value, str):
        return {"gate": "", "reason": "", "status": ""}
    text = value.strip()
    if not text.lower().startswith("skipped"):
        return {"gate": "", "reason": "", "status": ""}
    reason = ""
    match = re.match(r"^skipped\s*\((.+)\)\s*$", text, flags=re.IGNORECASE)
    if match:
        reason = match.group(1).strip()
    else:
        match = re.match(r"^skipped\s*:\s*(.+)\s*$", text, flags=re.IGNORECASE)
        if match:
            reason = match.group(1).strip()
    return {"gate": module, "reason": reason, "status": "skipped"}


def dedupe_skip_entries(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = set()
    deduped = []
    for entry in entries:
        gate = _first_text(entry.get("gate"))
        reason = _first_text(entry.get("reason"))
        status = _first_text(entry.get("status")) or "skipped"
        key = (gate, reason, status.lower())
        if not gate and not reason:
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append({"gate": gate, "reason": reason, "status": status})
    deduped.sort(key=lambda item: (item.get("gate", "").lower(), item.get("reason", "").lower()))
    return deduped


def collect_skip_reasons(skips: list[dict[str, str]], *extra_reason_values: object) -> list[str]:
    reasons = []
    for skip in skips:
        reason = _first_text(skip.get("reason"))
        if reason:
            reasons.append(reason)
    for value in extra_reason_values:
        if isinstance(value, str):
            reason = value.strip()
            if reason:
                reasons.append(reason)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.strip():
                    reasons.append(item.strip())
    deduped = []
    seen = set()
    for reason in reasons:
        key = reason.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(reason)
    deduped.sort(key=lambda text: text.lower())
    return deduped


completion_statuses = {
    "completed",
    "complete",
    "done",
    "success",
    "succeeded",
    "passed",
    "ok",
}
is_completion_result = status in completion_statuses

diff_files = _first_int(
    gate_summary.get("diff_files"),
    gate_summary.get("files_changed"),
    verification.get("diff_files"),
    verification.get("files_changed"),
    metadata.get("diff_files"),
    metadata.get("files_changed"),
    proof.get("diff_files"),
    proof.get("files_changed"),
)
diff_lines = _first_int(
    gate_summary.get("diff_lines"),
    gate_summary.get("lines_changed"),
    gate_summary.get("total_lines"),
    verification.get("diff_lines"),
    verification.get("lines_changed"),
    verification.get("total_lines"),
    metadata.get("diff_lines"),
    metadata.get("lines_changed"),
    metadata.get("total_lines"),
    proof.get("diff_lines"),
    proof.get("lines_changed"),
    proof.get("total_lines"),
)
diff_files_value = max(diff_files or 0, 0)
diff_lines_value = max(diff_lines or 0, 0)

manifest = load_manifest(repo_root / "manifest.json")
explicit_noop_justification, explicit_noop_justification_source = manifest_noop_justification(
    manifest
)
has_explicit_noop_justification = bool(explicit_noop_justification)

blocking_skip_allowlist_tokens = _split_tokens(
    os.environ.get("CYNTRA_COMPLETION_BLOCKING_SKIP_REASON_ALLOWLIST", "no scope changes")
)
blocking_skip_allowlist = sorted(
    {
        token
        for token in blocking_skip_allowlist_tokens
        if _normalized_reason(token)
    },
    key=lambda text: text.lower(),
)
blocking_skip_allowlist_normalized = {_normalized_reason(token) for token in blocking_skip_allowlist}

gate_skip_artifact = load_json(repo_root / ".cyntra" / "artifacts" / "gates" / "blocking-gate-summary.json")
artifact_gate_summary = gate_skip_artifact.get("gate_summary") if isinstance(gate_skip_artifact, dict) else {}
if not isinstance(artifact_gate_summary, dict):
    artifact_gate_summary = {}

blocking_skip_entries: list[dict[str, str]] = []
for candidate in (
    gate_summary.get("blocking_gate_skips"),
    gate_summary.get("blocking_skipped_gates"),
    gate_summary.get("skipped_blocking_gates"),
    verification.get("blocking_gate_skips"),
    metadata.get("blocking_gate_skips"),
    proof.get("blocking_gate_skips"),
    artifact_gate_summary.get("blocking_gate_skips"),
    gate_skip_artifact.get("blocking_gate_skips") if isinstance(gate_skip_artifact, dict) else None,
):
    if not isinstance(candidate, list):
        continue
    for item in candidate:
        blocking_skip_entries.append(parse_skip_entry(item))

if not blocking_skip_entries:
    for module_name, key in (
        ("Generic", "module_coverage_generic"),
        ("Reverend", "module_coverage_reverend"),
        ("SoftwareModeling", "module_coverage_softwaremodeling"),
        ("Base", "module_coverage_base"),
    ):
        blocking_skip_entries.append(parse_module_coverage_skip(module_name, gate_summary.get(key)))
        blocking_skip_entries.append(parse_module_coverage_skip(module_name, artifact_gate_summary.get(key)))

normalized_blocking_skips = dedupe_skip_entries(blocking_skip_entries)
blocking_skip_count_hint = _first_int(
    gate_summary.get("blocking_gate_skipped_count"),
    verification.get("blocking_gate_skipped_count"),
    metadata.get("blocking_gate_skipped_count"),
    proof.get("blocking_gate_skipped_count"),
    artifact_gate_summary.get("blocking_gate_skipped_count"),
    gate_skip_artifact.get("blocking_gate_skipped_count") if isinstance(gate_skip_artifact, dict) else None,
)
blocking_gate_skipped_count = max(
    blocking_skip_count_hint if blocking_skip_count_hint is not None else len(normalized_blocking_skips),
    len(normalized_blocking_skips),
    0,
)
blocking_gate_skip_reasons = collect_skip_reasons(
    normalized_blocking_skips,
    gate_summary.get("blocking_gate_skip_reasons"),
    verification.get("blocking_gate_skip_reasons"),
    metadata.get("blocking_gate_skip_reasons"),
    proof.get("blocking_gate_skip_reasons"),
    artifact_gate_summary.get("blocking_gate_skip_reasons"),
    gate_skip_artifact.get("blocking_gate_skip_reasons") if isinstance(gate_skip_artifact, dict) else None,
)
blocking_skip_budget = max(
    _first_int(
        gate_summary.get("blocking_gate_skip_budget"),
        verification.get("blocking_gate_skip_budget"),
        metadata.get("blocking_gate_skip_budget"),
        proof.get("blocking_gate_skip_budget"),
        artifact_gate_summary.get("blocking_gate_skip_budget"),
        gate_skip_artifact.get("blocking_gate_skip_budget") if isinstance(gate_skip_artifact, dict) else None,
        os.environ.get("CYNTRA_COMPLETION_BLOCKING_SKIP_BUDGET"),
    )
    or 0,
    0,
)
blocking_gate_budget_exceeded = blocking_gate_skipped_count > blocking_skip_budget
blocking_gate_skip_reasons_allowlisted = (
    blocking_gate_skipped_count == 0
    or (
        bool(blocking_gate_skip_reasons)
        and all(
            _normalized_reason(reason) in blocking_skip_allowlist_normalized
            for reason in blocking_gate_skip_reasons
        )
    )
)
blocking_gate_skip_evidence_present = (
    blocking_gate_skipped_count == 0
    or (
        bool(blocking_gate_skip_reasons)
        and (bool(normalized_blocking_skips) or blocking_skip_count_hint is not None)
    )
)

if diff_files_value > 0 or diff_lines_value > 0:
    completion_classification = "code_change"
else:
    completion_classification = "noop"

noop_reason = ""
noop_reason_source = ""
policy_result = "allow"
policy_blocked = False
policy_block_reason = ""
if completion_classification == "noop":
    if has_explicit_noop_justification:
        noop_reason = explicit_noop_justification
        noop_reason_source = explicit_noop_justification_source
    else:
        noop_reason = "missing_manifest_noop_justification"
        noop_reason_source = "missing_manifest_noop_justification"
        policy_result = "blocked"
        policy_blocked = True
        policy_block_reason = "missing_manifest_noop_justification"

if blocking_gate_budget_exceeded:
    if not blocking_gate_skip_evidence_present:
        policy_result = "blocked"
        policy_blocked = True
        policy_block_reason = "blocking_gate_skip_evidence_missing"
    elif not blocking_gate_skip_reasons_allowlisted:
        policy_result = "blocked"
        policy_blocked = True
        policy_block_reason = "blocking_gate_skip_reason_not_allowlisted"

completion_gate_summary_payload = {
    "diff_files": diff_files_value,
    "diff_lines": diff_lines_value,
    "completion_classification": completion_classification,
    "noop_reason": noop_reason,
    "noop_reason_source": noop_reason_source,
    "noop_justification_source": noop_reason_source,
    "explicit_noop_justification_present": has_explicit_noop_justification,
    "blocking_gate_skips": normalized_blocking_skips,
    "blocking_gate_skipped_count": blocking_gate_skipped_count,
    "blocking_gate_skip_budget": blocking_skip_budget,
    "blocking_gate_budget_exceeded": blocking_gate_budget_exceeded,
    "blocking_gate_skip_reasons": blocking_gate_skip_reasons,
    "blocking_gate_skip_reasons_allowlisted": blocking_gate_skip_reasons_allowlisted,
    "blocking_gate_skip_evidence_present": blocking_gate_skip_evidence_present,
    "blocking_gate_skip_reason_allowlist": blocking_skip_allowlist,
    "policy_result": policy_result,
    "policy_blocked": policy_blocked,
    "policy_block_reason": policy_block_reason,
}

gate_summary.update(completion_gate_summary_payload)
verification["gate_summary"] = gate_summary
proof["verification"] = verification

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

if policy_blocked and is_completion_result:
    detected_code = "policy.completion_blocked"

proof_changed = False
if detected_code and str(proof.get("failure_code") or "") != detected_code:
    proof["failure_code"] = detected_code
    proof_changed = True
if detected_code and str(metadata.get("failure_code") or "") != detected_code:
    metadata["failure_code"] = detected_code
    proof["metadata"] = metadata
    proof_changed = True
if detected_code and str(verification.get("failure_code") or "") != detected_code:
    verification["failure_code"] = detected_code
    proof["verification"] = verification
    proof_changed = True
blocking_failures = verification.get("blocking_failures")
if not isinstance(blocking_failures, list):
    blocking_failures = []
if detected_code and detected_code.startswith("policy.") and detected_code not in blocking_failures:
    verification["blocking_failures"] = [*blocking_failures, detected_code]
    proof["verification"] = verification
    proof_changed = True

telemetry_path = latest.parent / "telemetry.jsonl"
global_events_path = repo_root / ".cyntra" / "logs" / "events.jsonl"
workcell_id = str(proof.get("workcell_id") or latest.parent.name or "")
issue_id = str(proof.get("issue_id") or "")

completion_summary_event = {
    "timestamp_utc": now_iso(),
    "event": "completion_policy_gate_summary",
    "issue_id": issue_id,
    "workcell_id": workcell_id,
    "proof_path": str(latest),
    "gate_summary": completion_gate_summary_payload,
}
if is_completion_result:
    with telemetry_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(completion_summary_event, ensure_ascii=False) + "\n")
    global_events_path.parent.mkdir(parents=True, exist_ok=True)
    with global_events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(completion_summary_event, ensure_ascii=False) + "\n")
    proof_changed = True

if detected_code:
    telemetry = {
        "timestamp_utc": now_iso(),
        "event": "failure_code_classified",
        "failure_code": detected_code,
        "issue_id": issue_id,
        "workcell_id": workcell_id,
        "proof_path": str(latest),
    }
    with telemetry_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(telemetry, ensure_ascii=False) + "\n")
    global_events_path.parent.mkdir(parents=True, exist_ok=True)
    with global_events_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(telemetry, ensure_ascii=False) + "\n")

if proof_changed:
    latest.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

if not detected_code and not is_completion_result:
    raise SystemExit(1)

print(
    json.dumps(
        {
            "failure_code": detected_code,
            "issue_id": issue_id,
            "workcell_id": workcell_id,
            "proof_path": str(latest),
            "completion_classification": completion_classification,
            "noop_reason": noop_reason,
            "policy_result": policy_result,
            "policy_block_reason": policy_block_reason,
        }
    )
)
PY
}

if [[ -n "${CYNTRA_FAILURE_CODE:-${CYNTRA_FAILURE_CLASS:-}}" ]]; then
  exit "$primary_status"
fi

classification_json="$(classify_latest_deterministic_failure || true)"
if [[ -z "$classification_json" && -n "$primary_failure_code" ]]; then
  classification_json="$(python3 - "$primary_failure_code" "$primary_issue_id" "$primary_workcell_id" <<'PY'
import json
import sys
payload = {
    "failure_code": str(sys.argv[1]),
    "issue_id": str(sys.argv[2]),
    "workcell_id": str(sys.argv[3]),
    "proof_path": "",
    "completion_classification": "",
    "noop_reason": "",
    "policy_result": "",
    "policy_block_reason": "",
}
print(json.dumps(payload))
PY
)"
fi
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
policy_block_reason="$(python3 - "$classification_json" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
print(str(payload.get("policy_block_reason") or ""))
PY
)"

if [[ -z "$failure_code" ]]; then
  exit "$primary_status"
fi

if [[ "$failure_code" == "policy.completion_blocked" ]]; then
  case "$policy_block_reason" in
    missing_manifest_noop_justification)
      echo "[cyntra] completion policy blocked zero-diff closure (missing manifest no-op justification)"
      ;;
    blocking_gate_skip_reason_not_allowlisted)
      echo "[cyntra] completion policy blocked closure (blocking gates skipped beyond budget without allowlisted reason)"
      ;;
    blocking_gate_skip_evidence_missing)
      echo "[cyntra] completion policy blocked closure (blocking gate skip evidence missing from gate summary telemetry)"
      ;;
    *)
      if [[ -n "$policy_block_reason" ]]; then
        echo "[cyntra] completion policy blocked closure (${policy_block_reason})"
      else
        echo "[cyntra] completion policy blocked closure"
      fi
      ;;
  esac
  exit 1
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
