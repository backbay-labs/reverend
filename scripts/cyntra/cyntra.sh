#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_path="${CYNTRA_KERNEL_PATH:-/Users/connor/Medica/backbay/platform/kernel}"
config_path="${CYNTRA_CONFIG_PATH:-$repo_root/.cyntra/config.yaml}"
issues_path="${CYNTRA_ISSUES_PATH:-$repo_root/.beads/issues.jsonl}"
merge_guards="${CYNTRA_MERGE_GUARDS:-1}"
uv_refresh_kernel="${CYNTRA_UV_REFRESH_KERNEL:-1}"

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

uv_args=()
if [[ "$uv_refresh_kernel" == "1" ]]; then
  uv_args+=(--refresh-package cyntra)
fi

exec uv tool run "${uv_args[@]}" --from "$kernel_path" cyntra --config "$config_path" "${args[@]}"
