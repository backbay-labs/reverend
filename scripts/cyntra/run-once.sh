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
mission_checkpoint_path="${CYNTRA_MISSION_CHECKPOINT_PATH:-$repo_root/.cyntra/state/run-once-mission-checkpoint.json}"
mission_primary_max_attempts_raw="${CYNTRA_MISSION_PRIMARY_MAX_ATTEMPTS:-1}"
mission_classify_max_attempts_raw="${CYNTRA_MISSION_CLASSIFY_MAX_ATTEMPTS:-1}"
mission_fallback_max_attempts_raw="${CYNTRA_MISSION_FALLBACK_MAX_ATTEMPTS:-1}"
mission_primary_retryable_codes_raw="${CYNTRA_MISSION_PRIMARY_RETRYABLE_EXIT_CODES:-}"
mission_classify_retryable_codes_raw="${CYNTRA_MISSION_CLASSIFY_RETRYABLE_EXIT_CODES:-}"
mission_fallback_retryable_codes_raw="${CYNTRA_MISSION_FALLBACK_RETRYABLE_EXIT_CODES:-}"
watchdog_registered=0
watchdog_runner="run-once"
primary_status=1
primary_failure_code=""
primary_supervision_reason=""
primary_supervision_inactivity_seconds=""
primary_issue_id=""
primary_workcell_id=""
classification_json=""
failure_code=""
issue_id=""
workcell_id=""
proof_path=""
policy_block_reason=""
fallback_status=1
completion_policy_blocked=0

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
  supervision_path="$(mktemp "${TMPDIR:-/tmp}/cyntra-run-once-supervision.XXXXXX")"
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

normalize_positive_int() {
  local raw="${1:-1}"
  if [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 )); then
    printf '%s\n' "$raw"
    return 0
  fi
  printf '%s\n' "1"
}

normalize_retryable_codes() {
  local raw="${1:-}"
  python3 - "$raw" <<'PY'
import re
import sys

raw = str(sys.argv[1])
codes = []
seen = set()
for token in re.split(r"[\s,;|]+", raw):
    text = token.strip()
    if not text:
        continue
    if not re.fullmatch(r"-?\d+", text):
        continue
    value = int(text)
    if value in seen:
        continue
    seen.add(value)
    codes.append(value)
print(",".join(str(code) for code in sorted(codes)))
PY
}

mission_stage_dependencies_json='{"primary_supervised":[],"classify_failure":["primary_supervised"],"fallback_route":["classify_failure"]}'
mission_stage_order_csv=""
mission_input_signature=""
mission_input_payload_b64=""
mission_checkpoint_resumed=0
mission_terminal_exit_code=""
mission_primary_stage_state="pending"
mission_primary_stage_attempts=0
mission_primary_stage_last_exit=""
mission_classify_stage_state="pending"
mission_classify_stage_attempts=0
mission_classify_stage_last_exit=""
mission_fallback_stage_state="pending"
mission_fallback_stage_attempts=0
mission_fallback_stage_last_exit=""

mission_primary_max_attempts="$(normalize_positive_int "$mission_primary_max_attempts_raw")"
mission_classify_max_attempts="$(normalize_positive_int "$mission_classify_max_attempts_raw")"
mission_fallback_max_attempts="$(normalize_positive_int "$mission_fallback_max_attempts_raw")"
mission_primary_retryable_codes="$(normalize_retryable_codes "$mission_primary_retryable_codes_raw")"
mission_classify_retryable_codes="$(normalize_retryable_codes "$mission_classify_retryable_codes_raw")"
mission_fallback_retryable_codes="$(normalize_retryable_codes "$mission_fallback_retryable_codes_raw")"
mission_retry_policy_json="$(python3 - \
  "$mission_primary_max_attempts" \
  "$mission_primary_retryable_codes" \
  "$mission_classify_max_attempts" \
  "$mission_classify_retryable_codes" \
  "$mission_fallback_max_attempts" \
  "$mission_fallback_retryable_codes" <<'PY'
import json
import sys

payload = {
    "primary_supervised": {
        "max_attempts": int(sys.argv[1]),
        "retryable_exit_codes": [int(token) for token in sys.argv[2].split(",") if token],
    },
    "classify_failure": {
        "max_attempts": int(sys.argv[3]),
        "retryable_exit_codes": [int(token) for token in sys.argv[4].split(",") if token],
    },
    "fallback_route": {
        "max_attempts": int(sys.argv[5]),
        "retryable_exit_codes": [int(token) for token in sys.argv[6].split(",") if token],
    },
}
print(json.dumps(payload, sort_keys=True))
PY
)"

resolve_mission_stage_order_csv() {
  python3 - "$mission_stage_dependencies_json" <<'PY'
import heapq
import json
import sys

deps = json.loads(sys.argv[1])
stages = sorted(deps.keys())
incoming = {stage: set() for stage in stages}
outgoing = {stage: set() for stage in stages}
for stage, requirements in deps.items():
    for requirement in requirements:
        if requirement not in incoming:
            raise SystemExit(2)
        incoming[stage].add(requirement)
        outgoing[requirement].add(stage)

ready = [stage for stage in stages if not incoming[stage]]
heapq.heapify(ready)
order = []
while ready:
    current = heapq.heappop(ready)
    order.append(current)
    for neighbor in sorted(outgoing[current]):
        incoming[neighbor].discard(current)
        if not incoming[neighbor]:
            heapq.heappush(ready, neighbor)

if len(order) != len(stages):
    raise SystemExit(3)
print(",".join(order))
PY
}

mission_get_stage_state() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised) printf '%s\n' "$mission_primary_stage_state" ;;
    classify_failure) printf '%s\n' "$mission_classify_stage_state" ;;
    fallback_route) printf '%s\n' "$mission_fallback_stage_state" ;;
    *) return 1 ;;
  esac
}

mission_set_stage_state() {
  local stage_id="${1:-}"
  local value="${2:-pending}"
  case "$stage_id" in
    primary_supervised) mission_primary_stage_state="$value" ;;
    classify_failure) mission_classify_stage_state="$value" ;;
    fallback_route) mission_fallback_stage_state="$value" ;;
    *) return 1 ;;
  esac
}

mission_get_stage_attempts() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised) printf '%s\n' "$mission_primary_stage_attempts" ;;
    classify_failure) printf '%s\n' "$mission_classify_stage_attempts" ;;
    fallback_route) printf '%s\n' "$mission_fallback_stage_attempts" ;;
    *) return 1 ;;
  esac
}

mission_set_stage_attempts() {
  local stage_id="${1:-}"
  local value="${2:-0}"
  case "$stage_id" in
    primary_supervised) mission_primary_stage_attempts="$value" ;;
    classify_failure) mission_classify_stage_attempts="$value" ;;
    fallback_route) mission_fallback_stage_attempts="$value" ;;
    *) return 1 ;;
  esac
}

mission_get_stage_last_exit() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised) printf '%s\n' "$mission_primary_stage_last_exit" ;;
    classify_failure) printf '%s\n' "$mission_classify_stage_last_exit" ;;
    fallback_route) printf '%s\n' "$mission_fallback_stage_last_exit" ;;
    *) return 1 ;;
  esac
}

mission_set_stage_last_exit() {
  local stage_id="${1:-}"
  local value="${2:-}"
  case "$stage_id" in
    primary_supervised) mission_primary_stage_last_exit="$value" ;;
    classify_failure) mission_classify_stage_last_exit="$value" ;;
    fallback_route) mission_fallback_stage_last_exit="$value" ;;
    *) return 1 ;;
  esac
}

mission_stage_max_attempts() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised) printf '%s\n' "$mission_primary_max_attempts" ;;
    classify_failure) printf '%s\n' "$mission_classify_max_attempts" ;;
    fallback_route) printf '%s\n' "$mission_fallback_max_attempts" ;;
    *) return 1 ;;
  esac
}

mission_stage_retryable_codes() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised) printf '%s\n' "$mission_primary_retryable_codes" ;;
    classify_failure) printf '%s\n' "$mission_classify_retryable_codes" ;;
    fallback_route) printf '%s\n' "$mission_fallback_retryable_codes" ;;
    *) return 1 ;;
  esac
}

mission_exit_code_retryable() {
  local retryable_codes="${1:-}"
  local exit_code="${2:-}"
  if [[ -z "$retryable_codes" || -z "$exit_code" ]]; then
    printf '%s\n' "0"
    return 0
  fi
  python3 - "$retryable_codes" "$exit_code" <<'PY'
import sys

codes = {token for token in sys.argv[1].split(",") if token}
print("1" if sys.argv[2] in codes else "0")
PY
}

mission_checkpoint_load_or_init() {
  local cli_args=("$@")
  local state_env
  state_env="$(python3 - \
    "$mission_checkpoint_path" \
    "$mission_stage_order_csv" \
    "$mission_stage_dependencies_json" \
    "$mission_retry_policy_json" \
    "$deterministic_failure_codes" \
    "$enable_failure_fallback" \
    "$supervised_stall_timeout_seconds" \
    "$supervised_stall_poll_seconds" \
    "$supervised_activity_paths" \
    "$run_started_epoch" \
    "${cli_args[@]-}" <<'PY'
import base64
import hashlib
import json
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

checkpoint_path = Path(sys.argv[1])
stage_order = [token for token in str(sys.argv[2]).split(",") if token]
stage_dependencies = json.loads(sys.argv[3])
retry_policy = json.loads(sys.argv[4])
deterministic_failure_codes = str(sys.argv[5])
enable_failure_fallback = str(sys.argv[6])
supervised_stall_timeout_seconds = str(sys.argv[7])
supervised_stall_poll_seconds = str(sys.argv[8])
supervised_activity_paths = str(sys.argv[9])
current_run_started_epoch = int(sys.argv[10])
cli_args = list(sys.argv[11:])


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def shell_assign(name: str, value: object) -> str:
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "1" if value else "0"
    else:
        text = str(value)
    return f"{name}={shlex.quote(text)}"


def normalize_stage(stage_payload: object) -> dict:
    payload = stage_payload if isinstance(stage_payload, dict) else {}
    status = str(payload.get("status") or "pending")
    try:
        attempts = int(payload.get("attempts") or 0)
    except Exception:
        attempts = 0
    last_exit = payload.get("last_exit_code")
    if last_exit is None:
        last_exit_text = ""
    else:
        last_exit_text = str(last_exit)
    return {
        "status": status,
        "attempts": max(attempts, 0),
        "last_exit_code": last_exit_text,
    }


signature_payload = {
    "runner": "run-once",
    "cli_args": cli_args,
    "deterministic_failure_codes": deterministic_failure_codes,
    "enable_failure_fallback": enable_failure_fallback,
    "supervised_stall_timeout_seconds": supervised_stall_timeout_seconds,
    "supervised_stall_poll_seconds": supervised_stall_poll_seconds,
    "supervised_activity_paths": supervised_activity_paths,
    "failure_override": str(os.environ.get("CYNTRA_FAILURE_CODE") or os.environ.get("CYNTRA_FAILURE_CLASS") or ""),
    "mission_retry_policy": retry_policy,
    "mission_stage_order": stage_order,
    "mission_stage_dependencies": stage_dependencies,
}
signature_payload_json = json.dumps(signature_payload, sort_keys=True, separators=(",", ":"))
input_signature = hashlib.sha256(signature_payload_json.encode("utf-8")).hexdigest()

doc = {}
resume = False
if checkpoint_path.exists():
    try:
        loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except Exception:
        loaded = {}
    if isinstance(loaded, dict):
        doc = loaded
        if (
            str(doc.get("runner") or "") == "run-once"
            and str(doc.get("input_signature") or "") == input_signature
            and doc.get("completed") is not True
        ):
            resume = True

run_started_epoch_value = current_run_started_epoch
if resume:
    prior_inputs = doc.get("inputs") if isinstance(doc.get("inputs"), dict) else {}
    try:
        run_started_epoch_value = int(prior_inputs.get("run_started_epoch") or current_run_started_epoch)
    except Exception:
        run_started_epoch_value = current_run_started_epoch

input_payload = dict(signature_payload)
input_payload["run_started_epoch"] = run_started_epoch_value
input_payload_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"))
input_payload_b64 = base64.b64encode(input_payload_json.encode("utf-8")).decode("ascii")

if not resume:
    doc = {
        "version": 1,
        "runner": "run-once",
        "created_at_utc": now_iso(),
        "updated_at_utc": now_iso(),
        "completed": False,
        "terminal_exit_code": None,
        "checkpoint_path": str(checkpoint_path),
        "input_signature": input_signature,
        "inputs": input_payload,
        "stage_dependencies": stage_dependencies,
        "execution_order": stage_order,
        "retry_policy": retry_policy,
        "stages": {},
        "outputs": {},
    }
else:
    doc["updated_at_utc"] = now_iso()
    doc["checkpoint_path"] = str(checkpoint_path)
    doc["execution_order"] = stage_order
    doc["stage_dependencies"] = stage_dependencies
    doc["retry_policy"] = retry_policy
    doc["inputs"] = input_payload
    doc["input_signature"] = input_signature

stages = doc.get("stages")
if not isinstance(stages, dict):
    stages = {}
normalized_stages: dict[str, dict] = {}
for stage_id in stage_order:
    normalized_stages[stage_id] = normalize_stage(stages.get(stage_id))
doc["stages"] = normalized_stages

outputs = doc.get("outputs")
if not isinstance(outputs, dict):
    outputs = {}
doc["outputs"] = {
    "primary_status": str(outputs.get("primary_status") or "1"),
    "primary_failure_code": str(outputs.get("primary_failure_code") or ""),
    "primary_supervision_reason": str(outputs.get("primary_supervision_reason") or ""),
    "primary_supervision_inactivity_seconds": str(outputs.get("primary_supervision_inactivity_seconds") or ""),
    "classification_json": str(outputs.get("classification_json") or ""),
    "failure_code": str(outputs.get("failure_code") or ""),
    "issue_id": str(outputs.get("issue_id") or ""),
    "workcell_id": str(outputs.get("workcell_id") or ""),
    "proof_path": str(outputs.get("proof_path") or ""),
    "policy_block_reason": str(outputs.get("policy_block_reason") or ""),
    "completion_policy_blocked": "1" if str(outputs.get("completion_policy_blocked") or "") in {"1", "true", "True"} else "0",
    "fallback_status": str(outputs.get("fallback_status") or "1"),
}

checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
tmp_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
tmp_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp_path.replace(checkpoint_path)

primary_stage = normalized_stages["primary_supervised"]
classify_stage = normalized_stages["classify_failure"]
fallback_stage = normalized_stages["fallback_route"]
lines = [
    shell_assign("mission_input_signature", input_signature),
    shell_assign("mission_input_payload_b64", input_payload_b64),
    shell_assign("mission_checkpoint_resumed", "1" if resume else "0"),
    shell_assign("run_started_epoch", input_payload.get("run_started_epoch")),
    shell_assign("mission_primary_stage_state", primary_stage.get("status")),
    shell_assign("mission_primary_stage_attempts", primary_stage.get("attempts")),
    shell_assign("mission_primary_stage_last_exit", primary_stage.get("last_exit_code")),
    shell_assign("mission_classify_stage_state", classify_stage.get("status")),
    shell_assign("mission_classify_stage_attempts", classify_stage.get("attempts")),
    shell_assign("mission_classify_stage_last_exit", classify_stage.get("last_exit_code")),
    shell_assign("mission_fallback_stage_state", fallback_stage.get("status")),
    shell_assign("mission_fallback_stage_attempts", fallback_stage.get("attempts")),
    shell_assign("mission_fallback_stage_last_exit", fallback_stage.get("last_exit_code")),
    shell_assign("primary_status", doc["outputs"].get("primary_status")),
    shell_assign("primary_failure_code", doc["outputs"].get("primary_failure_code")),
    shell_assign("primary_supervision_reason", doc["outputs"].get("primary_supervision_reason")),
    shell_assign(
        "primary_supervision_inactivity_seconds",
        doc["outputs"].get("primary_supervision_inactivity_seconds"),
    ),
    shell_assign("classification_json", doc["outputs"].get("classification_json")),
    shell_assign("failure_code", doc["outputs"].get("failure_code")),
    shell_assign("issue_id", doc["outputs"].get("issue_id")),
    shell_assign("workcell_id", doc["outputs"].get("workcell_id")),
    shell_assign("proof_path", doc["outputs"].get("proof_path")),
    shell_assign("policy_block_reason", doc["outputs"].get("policy_block_reason")),
    shell_assign("completion_policy_blocked", doc["outputs"].get("completion_policy_blocked")),
    shell_assign("fallback_status", doc["outputs"].get("fallback_status")),
]
print("\n".join(lines))
PY
)"
  eval "$state_env"
}

mission_checkpoint_persist() {
  local mark_completed="${1:-0}"
  local terminal_exit_code="${2:-}"
  MISSION_CHECKPOINT_PATH="$mission_checkpoint_path" \
    MISSION_INPUT_SIGNATURE="$mission_input_signature" \
    MISSION_INPUT_PAYLOAD_B64="$mission_input_payload_b64" \
    MISSION_STAGE_ORDER_CSV="$mission_stage_order_csv" \
    MISSION_STAGE_DEPENDENCIES_JSON="$mission_stage_dependencies_json" \
    MISSION_RETRY_POLICY_JSON="$mission_retry_policy_json" \
    MISSION_PRIMARY_STAGE_STATE="$mission_primary_stage_state" \
    MISSION_PRIMARY_STAGE_ATTEMPTS="$mission_primary_stage_attempts" \
    MISSION_PRIMARY_STAGE_LAST_EXIT="$mission_primary_stage_last_exit" \
    MISSION_CLASSIFY_STAGE_STATE="$mission_classify_stage_state" \
    MISSION_CLASSIFY_STAGE_ATTEMPTS="$mission_classify_stage_attempts" \
    MISSION_CLASSIFY_STAGE_LAST_EXIT="$mission_classify_stage_last_exit" \
    MISSION_FALLBACK_STAGE_STATE="$mission_fallback_stage_state" \
    MISSION_FALLBACK_STAGE_ATTEMPTS="$mission_fallback_stage_attempts" \
    MISSION_FALLBACK_STAGE_LAST_EXIT="$mission_fallback_stage_last_exit" \
    MISSION_PRIMARY_STATUS="$primary_status" \
    MISSION_PRIMARY_FAILURE_CODE="$primary_failure_code" \
    MISSION_PRIMARY_SUPERVISION_REASON="$primary_supervision_reason" \
    MISSION_PRIMARY_SUPERVISION_INACTIVITY_SECONDS="$primary_supervision_inactivity_seconds" \
    MISSION_CLASSIFICATION_JSON="$classification_json" \
    MISSION_FAILURE_CODE="$failure_code" \
    MISSION_ISSUE_ID="$issue_id" \
    MISSION_WORKCELL_ID="$workcell_id" \
    MISSION_PROOF_PATH="$proof_path" \
    MISSION_POLICY_BLOCK_REASON="$policy_block_reason" \
    MISSION_COMPLETION_POLICY_BLOCKED="$completion_policy_blocked" \
    MISSION_FALLBACK_STATUS="$fallback_status" \
    MISSION_MARK_COMPLETED="$mark_completed" \
    MISSION_TERMINAL_EXIT_CODE="$terminal_exit_code" \
    python3 - <<'PY'
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_int(value: str, *, default: int | None = None) -> int | None:
    text = str(value or "").strip()
    if not text:
        return default
    try:
        return int(text)
    except Exception:
        return default


def _as_stage(status_key: str, attempts_key: str, exit_key: str) -> dict:
    return {
        "status": str(os.environ.get(status_key, "pending") or "pending"),
        "attempts": max(_as_int(os.environ.get(attempts_key, "0"), default=0) or 0, 0),
        "last_exit_code": str(os.environ.get(exit_key, "") or ""),
    }


checkpoint_path = Path(os.environ["MISSION_CHECKPOINT_PATH"])
stage_order = [token for token in os.environ.get("MISSION_STAGE_ORDER_CSV", "").split(",") if token]
stage_dependencies = json.loads(os.environ.get("MISSION_STAGE_DEPENDENCIES_JSON", "{}"))
retry_policy = json.loads(os.environ.get("MISSION_RETRY_POLICY_JSON", "{}"))
input_payload_b64 = str(os.environ.get("MISSION_INPUT_PAYLOAD_B64", "") or "")
inputs = {}
if input_payload_b64:
    try:
        inputs = json.loads(base64.b64decode(input_payload_b64.encode("ascii")).decode("utf-8"))
    except Exception:
        inputs = {}

doc = {}
if checkpoint_path.exists():
    try:
        loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except Exception:
        loaded = {}
    if isinstance(loaded, dict):
        doc = loaded

doc["version"] = 1
doc["runner"] = "run-once"
doc["checkpoint_path"] = str(checkpoint_path)
doc["input_signature"] = str(os.environ.get("MISSION_INPUT_SIGNATURE", "") or "")
doc["inputs"] = inputs
doc["execution_order"] = stage_order
doc["stage_dependencies"] = stage_dependencies
doc["retry_policy"] = retry_policy
doc["updated_at_utc"] = now_iso()
if not str(doc.get("created_at_utc") or "").strip():
    doc["created_at_utc"] = now_iso()

doc["stages"] = {
    "primary_supervised": _as_stage(
        "MISSION_PRIMARY_STAGE_STATE",
        "MISSION_PRIMARY_STAGE_ATTEMPTS",
        "MISSION_PRIMARY_STAGE_LAST_EXIT",
    ),
    "classify_failure": _as_stage(
        "MISSION_CLASSIFY_STAGE_STATE",
        "MISSION_CLASSIFY_STAGE_ATTEMPTS",
        "MISSION_CLASSIFY_STAGE_LAST_EXIT",
    ),
    "fallback_route": _as_stage(
        "MISSION_FALLBACK_STAGE_STATE",
        "MISSION_FALLBACK_STAGE_ATTEMPTS",
        "MISSION_FALLBACK_STAGE_LAST_EXIT",
    ),
}

doc["outputs"] = {
    "primary_status": str(os.environ.get("MISSION_PRIMARY_STATUS", "") or ""),
    "primary_failure_code": str(os.environ.get("MISSION_PRIMARY_FAILURE_CODE", "") or ""),
    "primary_supervision_reason": str(os.environ.get("MISSION_PRIMARY_SUPERVISION_REASON", "") or ""),
    "primary_supervision_inactivity_seconds": str(
        os.environ.get("MISSION_PRIMARY_SUPERVISION_INACTIVITY_SECONDS", "") or ""
    ),
    "classification_json": str(os.environ.get("MISSION_CLASSIFICATION_JSON", "") or ""),
    "failure_code": str(os.environ.get("MISSION_FAILURE_CODE", "") or ""),
    "issue_id": str(os.environ.get("MISSION_ISSUE_ID", "") or ""),
    "workcell_id": str(os.environ.get("MISSION_WORKCELL_ID", "") or ""),
    "proof_path": str(os.environ.get("MISSION_PROOF_PATH", "") or ""),
    "policy_block_reason": str(os.environ.get("MISSION_POLICY_BLOCK_REASON", "") or ""),
    "completion_policy_blocked": "1"
    if str(os.environ.get("MISSION_COMPLETION_POLICY_BLOCKED", "0") or "").strip().lower() in {"1", "true"}
    else "0",
    "fallback_status": str(os.environ.get("MISSION_FALLBACK_STATUS", "") or ""),
}

mark_completed = str(os.environ.get("MISSION_MARK_COMPLETED", "0") or "").strip()
if mark_completed in {"1", "true", "True"}:
    doc["completed"] = True
    doc["terminal_exit_code"] = _as_int(os.environ.get("MISSION_TERMINAL_EXIT_CODE", ""), default=0)
else:
    doc["completed"] = False
    doc["terminal_exit_code"] = None

checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
tmp_path = checkpoint_path.with_suffix(checkpoint_path.suffix + ".tmp")
tmp_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp_path.replace(checkpoint_path)
PY
}

mission_stage_should_run() {
  local stage_id="${1:-}"
  case "$stage_id" in
    primary_supervised)
      return 0
      ;;
    classify_failure)
      [[ "$enable_failure_fallback" == "1" ]]
      return $?
      ;;
    fallback_route)
      [[ "$enable_failure_fallback" == "1" ]] || return 1
      [[ -n "${CYNTRA_FAILURE_CODE:-${CYNTRA_FAILURE_CLASS:-}}" ]] && return 1
      [[ "$completion_policy_blocked" == "1" ]] && return 1
      [[ -n "$failure_code" ]]
      return $?
      ;;
    *)
      return 1
      ;;
  esac
}

decode_classification_json() {
  local payload="${1:-}"
  [[ -n "$payload" ]] || return 1
  eval "$(python3 - "$payload" <<'PY'
import json
import shlex
import sys

payload = json.loads(sys.argv[1])
fields = {
    "failure_code": str(payload.get("failure_code") or ""),
    "issue_id": str(payload.get("issue_id") or ""),
    "workcell_id": str(payload.get("workcell_id") or ""),
    "proof_path": str(payload.get("proof_path") or ""),
    "policy_block_reason": str(payload.get("policy_block_reason") or ""),
}
for key, value in fields.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"
}

run_mission_stage_primary_supervised() {
  run_primary_once_supervised "$@"
}

run_mission_stage_classify_failure() {
  if [[ -n "${CYNTRA_FAILURE_CODE:-${CYNTRA_FAILURE_CLASS:-}}" ]]; then
    classification_json=""
    failure_code=""
    issue_id=""
    workcell_id=""
    proof_path=""
    policy_block_reason=""
    completion_policy_blocked=0
    return 0
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
    failure_code=""
    issue_id=""
    workcell_id=""
    proof_path=""
    policy_block_reason=""
    completion_policy_blocked=0
    return 0
  fi

  decode_classification_json "$classification_json"
  completion_policy_blocked=0
  if [[ "$failure_code" == "policy.completion_blocked" ]]; then
    completion_policy_blocked=1
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
  fi
}

run_mission_stage_fallback_route() {
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
  return "$fallback_status"
}

run_mission_stage_handler() {
  local stage_id="${1:-}"
  shift || true
  case "$stage_id" in
    primary_supervised)
      run_mission_stage_primary_supervised "$@"
      ;;
    classify_failure)
      run_mission_stage_classify_failure
      ;;
    fallback_route)
      run_mission_stage_fallback_route "$@"
      ;;
    *)
      echo "[cyntra] ERROR: unknown mission stage '$stage_id'" >&2
      return 2
      ;;
  esac
}

execute_mission_stage() {
  local stage_id="${1:-}"
  shift || true
  local stage_state
  stage_state="$(mission_get_stage_state "$stage_id")"
  local stage_attempts
  stage_attempts="$(mission_get_stage_attempts "$stage_id")"
  local max_attempts
  max_attempts="$(mission_stage_max_attempts "$stage_id")"
  local retryable_codes
  retryable_codes="$(mission_stage_retryable_codes "$stage_id")"

  if [[ "$stage_state" == "succeeded" || "$stage_state" == "skipped" ]]; then
    echo "[cyntra] mission DAG resume: stage '$stage_id' already ${stage_state} (attempts=$stage_attempts)"
    return 0
  fi

  if [[ "$stage_state" == "running" ]]; then
    if (( stage_attempts > 0 )); then
      stage_attempts=$((stage_attempts - 1))
      mission_set_stage_attempts "$stage_id" "$stage_attempts"
    fi
    mission_set_stage_state "$stage_id" "pending"
    mission_set_stage_last_exit "$stage_id" ""
    mission_checkpoint_persist 0 ""
    echo "[cyntra] mission DAG resume: stage '$stage_id' was interrupted while running; replaying attempt"
  fi

  if ! mission_stage_should_run "$stage_id"; then
    mission_set_stage_state "$stage_id" "skipped"
    mission_set_stage_last_exit "$stage_id" ""
    mission_checkpoint_persist 0 ""
    echo "[cyntra] mission DAG stage '$stage_id' skipped by policy"
    return 0
  fi

  while (( stage_attempts < max_attempts )); do
    local next_attempt=$((stage_attempts + 1))
    mission_set_stage_state "$stage_id" "running"
    mission_set_stage_attempts "$stage_id" "$next_attempt"
    mission_checkpoint_persist 0 ""

    local stage_rc=0
    if run_mission_stage_handler "$stage_id" "$@"; then
      stage_rc=0
    else
      stage_rc=$?
    fi

    stage_attempts="$next_attempt"
    if (( stage_rc == 0 )); then
      mission_set_stage_state "$stage_id" "succeeded"
      mission_set_stage_last_exit "$stage_id" "0"
      mission_checkpoint_persist 0 ""
      return 0
    fi

    mission_set_stage_last_exit "$stage_id" "$stage_rc"
    local retryable=0
    if [[ "$(mission_exit_code_retryable "$retryable_codes" "$stage_rc")" == "1" ]]; then
      retryable=1
    fi

    if (( stage_attempts < max_attempts )) && [[ "$retryable" == "1" ]]; then
      mission_set_stage_state "$stage_id" "pending"
      mission_checkpoint_persist 0 ""
      echo "[cyntra] mission DAG stage '$stage_id' attempt ${stage_attempts}/${max_attempts} failed with exit=${stage_rc}; retrying"
      continue
    fi

    mission_set_stage_state "$stage_id" "failed"
    mission_checkpoint_persist 0 ""
    echo "[cyntra] mission DAG stage '$stage_id' failed with exit=${stage_rc} (attempt ${stage_attempts}/${max_attempts})"
    return "$stage_rc"
  done

  mission_set_stage_state "$stage_id" "failed"
  mission_checkpoint_persist 0 ""
  return 1
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

mission_stage_order_csv="$(resolve_mission_stage_order_csv)"
if [[ -z "$mission_stage_order_csv" ]]; then
  echo "[cyntra] ERROR: mission DAG order resolution failed" >&2
  exit 2
fi

mission_checkpoint_load_or_init "$@"
if [[ "$mission_checkpoint_resumed" == "1" ]]; then
  echo "[cyntra] mission DAG resume from checkpoint '$mission_checkpoint_path'"
else
  echo "[cyntra] mission DAG start checkpoint='$mission_checkpoint_path'"
fi
echo "[cyntra] mission DAG order=$mission_stage_order_csv retries=primary(max=${mission_primary_max_attempts},codes=${mission_primary_retryable_codes:-none}) classify(max=${mission_classify_max_attempts},codes=${mission_classify_retryable_codes:-none}) fallback(max=${mission_fallback_max_attempts},codes=${mission_fallback_retryable_codes:-none})"

mission_terminal_exit_code=""
IFS=',' read -r -a mission_stage_order <<<"$mission_stage_order_csv"
for stage_id in "${mission_stage_order[@]}"; do
  [[ -n "$stage_id" ]] || continue
  if execute_mission_stage "$stage_id" "$@"; then
    continue
  else
    mission_terminal_exit_code="$?"
    break
  fi
done

if [[ -n "$mission_terminal_exit_code" ]]; then
  mission_checkpoint_persist 1 "$mission_terminal_exit_code"
  rm -f "$mission_checkpoint_path" || true
  exit "$mission_terminal_exit_code"
fi

if [[ "$completion_policy_blocked" == "1" ]]; then
  mission_terminal_exit_code="1"
elif [[ "$enable_failure_fallback" != "1" ]]; then
  mission_terminal_exit_code="$primary_status"
elif [[ -n "${CYNTRA_FAILURE_CODE:-${CYNTRA_FAILURE_CLASS:-}}" ]]; then
  mission_terminal_exit_code="$primary_status"
elif [[ -z "$failure_code" ]]; then
  mission_terminal_exit_code="$primary_status"
else
  mission_terminal_exit_code="$fallback_status"
fi

mission_checkpoint_persist 1 "$mission_terminal_exit_code"
rm -f "$mission_checkpoint_path" || true
exit "$mission_terminal_exit_code"
