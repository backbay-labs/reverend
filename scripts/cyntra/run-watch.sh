#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

scripts/cyntra/preflight.sh
scripts/cyntra/cyntra.sh run --watch "$@"

