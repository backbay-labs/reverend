#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
kernel_path="${CYNTRA_KERNEL_PATH:-/Users/connor/Medica/backbay/platform/kernel}"
config_path="${CYNTRA_CONFIG_PATH:-$repo_root/.cyntra/config.yaml}"

if [[ ! -d "$kernel_path" ]]; then
  echo "Kernel path not found: $kernel_path" >&2
  exit 1
fi

if [[ ! -f "$config_path" ]]; then
  echo "Config file not found: $config_path" >&2
  exit 1
fi

exec uv tool run --from "$kernel_path" cyntra --config "$config_path" "$@"

