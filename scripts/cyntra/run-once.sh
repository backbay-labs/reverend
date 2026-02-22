#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lock_root="$repo_root/.cyntra/locks"
lock_dir="$lock_root/run-loop.lock"
lock_pid_file="$lock_dir/pid"

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
scripts/cyntra/cyntra.sh run --once "$@"
