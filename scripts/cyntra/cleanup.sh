#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

older_than_days="${1:-2}"
archive_retention_days="${CYNTRA_ARCHIVE_RETENTION_DAYS:-7}"
keep_logs_flag="${CYNTRA_KEEP_LOG_ARCHIVES:-0}"

args=(cleanup --older-than "$older_than_days")
if [[ "$keep_logs_flag" == "1" ]]; then
  args+=(--keep-logs)
fi

scripts/cyntra/cyntra.sh "${args[@]}"

if [[ -d .cyntra/archives ]]; then
  find .cyntra/archives -mindepth 1 -maxdepth 1 -type d -mtime +"$archive_retention_days" -print -exec rm -rf {} +
fi

scripts/cyntra/disk-report.sh

