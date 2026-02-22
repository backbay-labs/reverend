#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_path="${CYNTRA_KERNEL_PATH:-/Users/connor/Medica/backbay/platform/kernel}"
config_path="${CYNTRA_CONFIG_PATH:-$repo_root/.cyntra/config.yaml}"
issues_path="${CYNTRA_ISSUES_PATH:-$repo_root/.beads/issues.jsonl}"
merge_guards="${CYNTRA_MERGE_GUARDS:-1}"
uv_refresh_kernel="${CYNTRA_UV_REFRESH_KERNEL:-1}"
fallback_policy="${CYNTRA_FALLBACK_POLICY:-prompt_stall_no_output=claude}"
fallback_max_hops="${CYNTRA_FALLBACK_MAX_HOPS:-1}"
fallback_record_path="${CYNTRA_FALLBACK_RECORD_PATH:-$repo_root/.cyntra/state/fallback-routing.json}"

cleanup_paths=()

cleanup_temp_files() {
  local path
  for path in "${cleanup_paths[@]-}"; do
    [[ -n "$path" ]] || continue
    rm -f "$path"
  done
}

trap cleanup_temp_files EXIT

normalize_merge_conflict_beads() {
  [[ -f "$issues_path" ]] || return 0
  python3 - "$issues_path" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
original_text = path.read_text(encoding="utf-8")
lines = [line for line in original_text.splitlines() if line.strip()]
issues = [json.loads(line) for line in lines]
by_id = {str(issue.get("id")): issue for issue in issues}
orig_re = re.compile(r"-\s*Original issue:\s*#(\d+)")


def is_merge_conflict(issue):
    if not isinstance(issue, dict):
        return False
    title = str(issue.get("title") or "")
    desc = str(issue.get("description") or "")
    tags = issue.get("tags") or []
    return (
        title.startswith("[MERGE CONFLICT]")
        or "MERGE_CONFLICT_AUTOGEN" in desc
        or "merge-conflict" in tags
    )


def original_issue_id(issue):
    match = orig_re.search(str(issue.get("description") or ""))
    return match.group(1) if match else None


def resolve_canonical(issue_id):
    depth = 0
    seen = set()
    current_id = issue_id
    while True:
        current = by_id.get(current_id)
        if not current or not is_merge_conflict(current):
            return current_id, depth, False
        if current_id in seen:
            return current_id, depth, True
        seen.add(current_id)
        nxt = original_issue_id(current)
        if not nxt:
            return current_id, depth, False
        depth += 1
        current_id = nxt


retire_ids = set()
kept_by_canonical = {}
retired_shadow = 0
retired_duplicate = 0
retired_cycle = 0
retired_active = 0

for issue in issues:
    issue_id = str(issue.get("id"))
    if not is_merge_conflict(issue):
        continue

    canonical_id, depth, cycle = resolve_canonical(issue_id)
    if cycle:
        retire_ids.add(issue_id)
        retired_cycle += 1
        continue
    if depth > 1:
        retire_ids.add(issue_id)
        retired_shadow += 1
        continue

    prior = kept_by_canonical.get(canonical_id)
    if prior and prior != issue_id:
        retire_ids.add(issue_id)
        retired_duplicate += 1
        continue
    kept_by_canonical[canonical_id] = issue_id

for issue in issues:
    issue_id = str(issue.get("id"))
    if issue_id in retire_ids:
        continue
    if not is_merge_conflict(issue):
        continue
    status = str(issue.get("status") or "").lower()
    if status in {"open", "ready", "in_progress"}:
        issue["status"] = "done"
        retired_active += 1

output = [issue for issue in issues if str(issue.get("id")) not in retire_ids]
new_text = "\n".join(json.dumps(issue, ensure_ascii=False) for issue in output)
if new_text:
    new_text += "\n"

if new_text != original_text:
    path.write_text(new_text, encoding="utf-8")
    changed = 1
else:
    changed = 0

print(
    "[cyntra] merge-conflict cleanup:"
    f" changed={changed}"
    f" retired_shadow={retired_shadow}"
    f" retired_duplicate={retired_duplicate}"
    f" retired_cycle={retired_cycle}"
    f" retired_active={retired_active}"
)
PY
}

resolve_canonical_issue_id() {
  local issue_id="${1:-}"
  [[ -n "$issue_id" ]] || return 1
  [[ -f "$issues_path" ]] || {
    echo "$issue_id"
    return 0
  }

  python3 - "$issues_path" "$issue_id" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = sys.argv[2]
lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
issues = [json.loads(line) for line in lines]
by_id = {str(issue.get("id")): issue for issue in issues}
orig_re = re.compile(r"-\s*Original issue:\s*#(\d+)")


def is_merge_conflict(issue):
    if not isinstance(issue, dict):
        return False
    title = str(issue.get("title") or "")
    desc = str(issue.get("description") or "")
    tags = issue.get("tags") or []
    return (
        title.startswith("[MERGE CONFLICT]")
        or "MERGE_CONFLICT_AUTOGEN" in desc
        or "merge-conflict" in tags
    )


def original_issue_id(issue):
    match = orig_re.search(str(issue.get("description") or ""))
    return match.group(1) if match else None


seen = set()
current = str(target)
while True:
    issue = by_id.get(current)
    if not issue or not is_merge_conflict(issue):
        print(current)
        break
    if current in seen:
        print(current)
        break
    seen.add(current)
    nxt = original_issue_id(issue)
    if not nxt:
        print(current)
        break
    current = nxt
PY
}

rewrite_issue_arg_to_canonical() {
  local issue_value=""
  local issue_index="-1"
  local issue_inline="0"
  local i
  local canonical_issue

  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      --issue=*)
        issue_value="${args[$i]#--issue=}"
        issue_index="$i"
        issue_inline="1"
        ;;
      --issue)
        if (( i + 1 < ${#args[@]} )); then
          issue_value="${args[$((i + 1))]}"
          issue_index="$((i + 1))"
          issue_inline="0"
        fi
        ;;
    esac
  done

  [[ -n "$issue_value" ]] || return 0
  canonical_issue="$(resolve_canonical_issue_id "$issue_value")"
  [[ -n "$canonical_issue" ]] || return 0
  [[ "$canonical_issue" == "$issue_value" ]] && return 0

  if [[ "$issue_inline" == "1" ]]; then
    args[$issue_index]="--issue=$canonical_issue"
  else
    args[$issue_index]="$canonical_issue"
  fi
  echo "[cyntra] remapped --issue $issue_value -> $canonical_issue"
}

extract_issue_arg() {
  local i
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
      --issue=*)
        printf '%s\n' "${args[$i]#--issue=}"
        return 0
        ;;
      --issue)
        if (( i + 1 < ${#args[@]} )); then
          printf '%s\n' "${args[$((i + 1))]}"
          return 0
        fi
        ;;
    esac
  done
  return 1
}

read_workcell_field() {
  local field_name="$1"
  local workcell_path="$repo_root/.workcell"
  [[ -f "$workcell_path" ]] || return 1
  python3 - "$workcell_path" "$field_name" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
field = sys.argv[2]
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)
value = data.get(field)
if value is None:
    raise SystemExit(1)
print(str(value))
PY
}

resolve_fallback_toolchain() {
  local failure_class="${1:-}"
  local normalized_class
  normalized_class="$(printf '%s' "$failure_class" | tr '[:upper:]' '[:lower:]')"
  [[ -n "$normalized_class" ]] || return 1

  local old_ifs="$IFS"
  IFS=',;'
  read -r -a entries <<<"$fallback_policy"
  IFS="$old_ifs"

  local entry=""
  local lhs=""
  local rhs=""
  for entry in "${entries[@]}"; do
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    [[ -n "$entry" ]] || continue
    if [[ "$entry" == *"="* ]]; then
      lhs="${entry%%=*}"
      rhs="${entry#*=}"
    elif [[ "$entry" == *":"* ]]; then
      lhs="${entry%%:*}"
      rhs="${entry#*:}"
    else
      continue
    fi
    lhs="${lhs#"${lhs%%[![:space:]]*}"}"
    lhs="${lhs%"${lhs##*[![:space:]]}"}"
    rhs="${rhs#"${rhs%%[![:space:]]*}"}"
    rhs="${rhs%"${rhs##*[![:space:]]}"}"
    [[ -n "$lhs" && -n "$rhs" ]] || continue
    if [[ "$(printf '%s' "$lhs" | tr '[:upper:]' '[:lower:]')" == "$normalized_class" ]]; then
      printf '%s\n' "$rhs"
      return 0
    fi
  done
  return 1
}

toolchain_in_chain() {
  local chain="${1:-}"
  local candidate="${2:-}"
  [[ -n "$chain" && -n "$candidate" ]] || return 1
  local normalized_candidate
  normalized_candidate="$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')"
  local old_ifs="$IFS"
  IFS=',:;>'
  read -r -a parts <<<"$chain"
  IFS="$old_ifs"
  local item
  for item in "${parts[@]}"; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -n "$item" ]] || continue
    if [[ "$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')" == "$normalized_candidate" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_active_toolchain() {
  local toolchain="${CYNTRA_PRIMARY_TOOLCHAIN:-}"
  if [[ -n "$toolchain" ]]; then
    printf '%s\n' "$toolchain"
    return 0
  fi

  local manifest_path="$repo_root/manifest.json"
  [[ -f "$manifest_path" ]] || return 1
  python3 - "$manifest_path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    manifest = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    raise SystemExit(1)
toolchain = manifest.get("toolchain")
if not toolchain:
    raise SystemExit(1)
print(str(toolchain))
PY
}

apply_issue_toolchain_override() {
  local issue_id="${1:-}"
  local fallback_toolchain="${2:-}"
  [[ -n "$issue_id" && -n "$fallback_toolchain" ]] || return 1
  [[ -f "$issues_path" ]] || return 1

  local tmp_issues
  tmp_issues="$(mktemp "${TMPDIR:-/tmp}/cyntra-fallback-beads.XXXXXX.jsonl")"

  python3 - "$issues_path" "$tmp_issues" "$issue_id" "$fallback_toolchain" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
issue_id = str(sys.argv[3])
fallback_toolchain = str(sys.argv[4])

updated = False
rows = []
for line in src.read_text(encoding="utf-8").splitlines():
    raw = line.strip()
    if not raw:
        continue
    issue = json.loads(raw)
    if str(issue.get("id")) == issue_id:
        issue["dk_tool_hint"] = fallback_toolchain
        updated = True
    rows.append(issue)

if not updated:
    raise SystemExit(2)

dst.write_text(
    "".join(json.dumps(issue, ensure_ascii=False) + "\n" for issue in rows),
    encoding="utf-8",
)
PY
  local override_status=$?
  if (( override_status != 0 )); then
    rm -f "$tmp_issues"
    return 1
  fi

  cleanup_paths+=("$tmp_issues")
  export CYNTRA_BEADS_PATH="$tmp_issues"
  return 0
}

write_fallback_provenance() {
  local issue_id="${1:-}"
  local source_toolchain="${2:-}"
  local fallback_toolchain="${3:-}"
  local failure_class="${4:-}"
  local workcell_id="${5:-}"
  local proof_path="${6:-}"

  mkdir -p "$(dirname "$fallback_record_path")"
  python3 - "$fallback_record_path" <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(__import__("sys").argv[1])
record = {
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "issue_id": os.environ.get("CYNTRA_FALLBACK_ISSUE_ID"),
    "workcell_id": os.environ.get("CYNTRA_FALLBACK_WORKCELL_ID"),
    "failure_class": os.environ.get("CYNTRA_FALLBACK_CLASS"),
    "source_toolchain": os.environ.get("CYNTRA_FALLBACK_SOURCE_TOOLCHAIN"),
    "target_toolchain": os.environ.get("CYNTRA_FALLBACK_TARGET_TOOLCHAIN"),
    "proof_path": os.environ.get("CYNTRA_FALLBACK_PROOF_PATH"),
}
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY
}

configure_fallback_routing_if_requested() {
  [[ "${args[0]:-}" == "run" ]] || return 0
  local failure_class="${CYNTRA_FAILURE_CLASS:-}"
  [[ -n "$failure_class" ]] || return 0

  local fallback_toolchain=""
  if ! fallback_toolchain="$(resolve_fallback_toolchain "$failure_class")"; then
    echo "[cyntra] no fallback route configured for failure class '$failure_class'"
    return 0
  fi

  local source_toolchain=""
  source_toolchain="$(resolve_active_toolchain || true)"
  local source_normalized
  source_normalized="$(printf '%s' "$source_toolchain" | tr '[:upper:]' '[:lower:]')"
  local fallback_normalized
  fallback_normalized="$(printf '%s' "$fallback_toolchain" | tr '[:upper:]' '[:lower:]')"
  if [[ -n "$source_normalized" && "$source_normalized" == "$fallback_normalized" ]]; then
    echo "[cyntra] fallback route resolved to same toolchain '$fallback_toolchain'; skipping"
    return 0
  fi

  local fallback_chain="${CYNTRA_FALLBACK_CHAIN:-}"
  if [[ -n "$fallback_chain" ]] && toolchain_in_chain "$fallback_chain" "$fallback_toolchain"; then
    echo "[cyntra] fallback loop guard: '$fallback_toolchain' already in chain '$fallback_chain'; skipping"
    return 0
  fi

  local fallback_hops=0
  if [[ -n "$fallback_chain" ]]; then
    fallback_hops="$(python3 - "$fallback_chain" <<'PY'
import sys
parts = [p.strip() for p in sys.argv[1].replace(">", ",").replace(";", ",").split(",")]
print(sum(1 for p in parts if p))
PY
)"
  fi
  if [[ "$fallback_max_hops" =~ ^[0-9]+$ ]] && (( fallback_hops >= fallback_max_hops )); then
    echo "[cyntra] fallback max hops reached ($fallback_hops/$fallback_max_hops); skipping"
    return 0
  fi

  local issue_id=""
  issue_id="$(extract_issue_arg || true)"
  if [[ -z "$issue_id" ]]; then
    issue_id="$(read_workcell_field issue_id || true)"
  fi
  local workcell_id=""
  workcell_id="$(read_workcell_field id || true)"
  local proof_path="${CYNTRA_FALLBACK_PROOF_PATH:-}"

  if [[ -n "$issue_id" ]]; then
    if ! apply_issue_toolchain_override "$issue_id" "$fallback_toolchain"; then
      echo "[cyntra] failed to apply fallback toolchain override for issue '$issue_id'; continuing without override"
      return 0
    fi
  fi

  if [[ -n "$fallback_chain" ]]; then
    export CYNTRA_FALLBACK_CHAIN="${fallback_chain},${fallback_toolchain}"
  elif [[ -n "$source_toolchain" ]]; then
    export CYNTRA_FALLBACK_CHAIN="${source_toolchain},${fallback_toolchain}"
  else
    export CYNTRA_FALLBACK_CHAIN="${fallback_toolchain}"
  fi
  export CYNTRA_FALLBACK_CLASS="$failure_class"
  export CYNTRA_FALLBACK_SOURCE_TOOLCHAIN="$source_toolchain"
  export CYNTRA_FALLBACK_TARGET_TOOLCHAIN="$fallback_toolchain"
  export CYNTRA_FALLBACK_ISSUE_ID="$issue_id"
  export CYNTRA_FALLBACK_WORKCELL_ID="$workcell_id"
  export CYNTRA_FALLBACK_PROOF_PATH="$proof_path"
  export CYNTRA_FALLBACK_APPLIED=1

  write_fallback_provenance "$issue_id" "$source_toolchain" "$fallback_toolchain" "$failure_class" "$workcell_id" "$proof_path"
  echo "[cyntra] fallback routing: class='$failure_class' source='${source_toolchain:-unknown}' target='$fallback_toolchain' issue='${issue_id:-unknown}'"
}

invoke_kernel() {
  local uv_args=()
  if [[ "$uv_refresh_kernel" == "1" ]]; then
    uv_args+=(--refresh-package cyntra)
  fi
  uv tool run "${uv_args[@]}" --from "$kernel_path" cyntra --config "$config_path" "${args[@]}"
}

args=("$@")

if [[ "${args[0]:-}" == "repair-merge-conflicts" ]]; then
  normalize_merge_conflict_beads
  exit 0
fi

if [[ ! -d "$kernel_path" ]]; then
  echo "Kernel path not found: $kernel_path" >&2
  exit 1
fi

if [[ ! -f "$config_path" ]]; then
  echo "Config file not found: $config_path" >&2
  exit 1
fi

if [[ "$merge_guards" == "1" && "${args[0]:-}" == "run" ]]; then
  # Canonicalize an explicit issue id before cleanup can retire stale shadow beads.
  rewrite_issue_arg_to_canonical
  normalize_merge_conflict_beads
fi

configure_fallback_routing_if_requested

invoke_kernel
