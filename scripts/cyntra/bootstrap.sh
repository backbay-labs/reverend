#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

echo "[bootstrap] repo: $repo_root"

mkdir -p .cyntra/logs .cyntra/archives .cyntra/state .cyntra/runs .cyntra/dynamics
mkdir -p .workcells

if [[ ! -f .workcells/.gitignore ]]; then
  cat > .workcells/.gitignore <<'EOF'
# Ignore all ephemeral workcells.
*
!.gitignore
EOF
  echo "[bootstrap] wrote .workcells/.gitignore"
fi

if [[ ! -f .cyntra/config.yaml ]]; then
  echo "[bootstrap] missing .cyntra/config.yaml; expected committed config file" >&2
  exit 1
fi

if ! git show-ref --verify --quiet refs/heads/main; then
  git branch main HEAD
  echo "[bootstrap] created local branch 'main' at $(git rev-parse --short HEAD)"
else
  echo "[bootstrap] branch 'main' already exists"
fi

echo "[bootstrap] complete"
echo "[bootstrap] next: scripts/cyntra/preflight.sh"

