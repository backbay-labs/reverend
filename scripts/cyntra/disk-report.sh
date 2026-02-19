#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

echo "[disk] filesystem headroom"
df -h "$repo_root" | sed -n '1,2p'
echo
echo "[disk] cyntra runtime footprint"
for path in .workcells .cyntra/archives .cyntra/logs .cyntra/runs .cyntra/state; do
  if [[ -e "$path" ]]; then
    du -sh "$path"
  fi
done

