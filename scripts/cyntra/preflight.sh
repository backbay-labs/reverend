#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

kernel_path="${CYNTRA_KERNEL_PATH:-/Users/connor/Medica/backbay/platform/kernel}"
min_free_gb="${CYNTRA_MIN_FREE_GB:-35}"
max_active_workcells="${CYNTRA_MAX_ACTIVE_WORKCELLS:-}"
auto_fix_main="${CYNTRA_AUTO_FIX_MAIN:-1}"
run_status_check="${CYNTRA_PREFLIGHT_STATUS_CHECK:-1}"
strict_context_main="${CYNTRA_STRICT_CONTEXT_MAIN:-1}"
required_python_minor="${CYNTRA_REQUIRED_PYTHON_MINOR:-11}"
required_java_major="${CYNTRA_REQUIRED_JAVA_MAJOR:-21}"

fail() {
  echo "[preflight] ERROR: $*" >&2
  exit 1
}

info() {
  echo "[preflight] $*"
}

parse_java_major() {
  local java_version_line java_version java_major
  java_version_line="$(java -version 2>&1 | head -n 1)"
  java_version="$(sed -n 's/.*version "\(.*\)".*/\1/p' <<<"$java_version_line")"
  [[ -n "$java_version" ]] || return 1
  java_major="${java_version%%.*}"
  if [[ "$java_major" == "1" ]]; then
    java_major="$(cut -d. -f2 <<<"$java_version")"
  fi
  [[ "$java_major" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$java_major"
}

parse_javac_major() {
  local javac_version_line javac_version javac_major
  javac_version_line="$(javac -version 2>&1 | head -n 1)"
  javac_version="$(awk '{print $2}' <<<"$javac_version_line")"
  [[ -n "$javac_version" ]] || return 1
  javac_major="${javac_version%%.*}"
  if [[ "$javac_major" == "1" ]]; then
    javac_major="$(cut -d. -f2 <<<"$javac_version")"
  fi
  [[ "$javac_major" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$javac_major"
}

command -v uv >/dev/null 2>&1 || fail "uv is required but not found in PATH"
command -v python3 >/dev/null 2>&1 || fail "python3 is required but not found in PATH (install Python 3.${required_python_minor}+)"
read -r python_major python_minor python_patch < <(
  python3 - <<'PY'
import sys
print(sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
PY
)
if (( python_major != 3 || python_minor < required_python_minor )); then
  fail "Python 3.${required_python_minor}+ is required; found ${python_major}.${python_minor}.${python_patch}. Install/select a compatible interpreter and verify with: python3 --version"
fi
info "python toolchain OK: ${python_major}.${python_minor}.${python_patch} (require >=3.${required_python_minor})"

command -v java >/dev/null 2>&1 || fail "java is required but not found in PATH (install Temurin JDK ${required_java_major} and set JAVA_HOME)"
command -v javac >/dev/null 2>&1 || fail "javac is required but not found in PATH (install full JDK ${required_java_major}, not JRE-only)"
java_major="$(parse_java_major || true)"
if [[ -z "$java_major" ]]; then
  fail "unable to parse Java version from 'java -version'. Verify installation with: java -version && javac -version"
fi
if (( java_major != required_java_major )); then
  fail "JDK ${required_java_major} is required for reproducible runs; found Java ${java_major}. Install/select Temurin ${required_java_major} and verify with: java -version && javac -version"
fi
javac_major="$(parse_javac_major || true)"
if [[ -z "$javac_major" ]]; then
  fail "unable to parse Java compiler version from 'javac -version'. Verify installation with: java -version && javac -version"
fi
if (( javac_major != required_java_major )); then
  fail "JDK ${required_java_major} is required for reproducible runs; found javac ${javac_major}. Install/select Temurin ${required_java_major} and verify with: java -version && javac -version"
fi
if (( java_major != javac_major )); then
  fail "java/javac mismatch detected (java ${java_major}, javac ${javac_major}). Align JAVA_HOME (${JAVA_HOME:-<unset>}) and PATH so both resolve to Temurin ${required_java_major}. Verify with: which java && which javac && java -version && javac -version"
fi
info "java toolchain OK: $(java -version 2>&1 | head -n 1) | $(javac -version 2>&1 | head -n 1)"

[[ -d "$kernel_path" ]] || fail "kernel path not found: $kernel_path"
[[ -f .beads/issues.jsonl ]] || fail "missing .beads/issues.jsonl"
[[ -f .beads/deps.jsonl ]] || fail "missing .beads/deps.jsonl"
[[ -f .cyntra/config.yaml ]] || fail "missing .cyntra/config.yaml"

if [[ -z "$max_active_workcells" ]]; then
  max_active_workcells="$(
    python3 - <<'PY'
import sys
from pathlib import Path
try:
    import yaml
except Exception:
    print(3)
    sys.exit(0)
path = Path(".cyntra/config.yaml")
if not path.exists():
    print(3)
    sys.exit(0)
try:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
except Exception:
    print(3)
    sys.exit(0)
val = ((data.get("scheduling") or {}).get("max_concurrent_workcells"))
try:
    print(int(val))
except Exception:
    print(3)
PY
  )"
fi

mkdir -p .cyntra/logs .cyntra/archives .cyntra/state .cyntra/runs .cyntra/dynamics
mkdir -p .workcells
if [[ ! -f .workcells/.gitignore ]]; then
  cat > .workcells/.gitignore <<'EOF'
*
!.gitignore
EOF
fi

if ! git show-ref --verify --quiet refs/heads/main; then
  if [[ "$auto_fix_main" == "1" ]]; then
    git branch main HEAD
    info "created missing local branch 'main' at $(git rev-parse --short HEAD)"
  else
    fail "missing branch 'main' (set CYNTRA_AUTO_FIX_MAIN=1 to auto-create)"
  fi
fi

free_kb="$(df -Pk "$repo_root" | awk 'NR==2{print $4}')"
free_gb="$((free_kb / 1024 / 1024))"
if (( free_gb < min_free_gb )); then
  fail "low disk headroom: ${free_gb}GiB free, require >= ${min_free_gb}GiB"
fi
info "disk headroom OK: ${free_gb}GiB free"

active_wc_count="$(find .workcells -mindepth 1 -maxdepth 1 -type d -name 'wc-*' 2>/dev/null | wc -l | tr -d ' ')"
if (( active_wc_count > max_active_workcells )); then
  fail "active workcells ${active_wc_count} exceed limit ${max_active_workcells}; run scripts/cyntra/cleanup.sh"
fi
info "active workcells: ${active_wc_count} (limit ${max_active_workcells})"

export CYNTRA_STRICT_CONTEXT_MAIN="$strict_context_main"

python3 - <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

issues_path = Path(".beads/issues.jsonl")
deps_path = Path(".beads/deps.jsonl")

try:
    issues = [json.loads(line) for line in issues_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    deps = [json.loads(line) for line in deps_path.read_text(encoding="utf-8").splitlines() if line.strip()]
except Exception as exc:
    print(f"[preflight] ERROR: failed to parse beads files: {exc}", file=sys.stderr)
    sys.exit(1)

issue_ids = {str(i.get("id")) for i in issues}
invalid_deps = []
for dep in deps:
    f = str(dep.get("from", dep.get("from_id", "")))
    t = str(dep.get("to", dep.get("to_id", "")))
    if f not in issue_ids or t not in issue_ids:
        invalid_deps.append((f, t))

if invalid_deps:
    print("[preflight] ERROR: dependency references unknown issue ids:", file=sys.stderr)
    for f, t in invalid_deps[:10]:
        print(f"  - {f} -> {t}", file=sys.stderr)
    sys.exit(1)

context_files = sorted(
    {
        str(path)
        for issue in issues
        for path in (issue.get("context_files") or [])
        if isinstance(path, str) and path.strip()
    }
)

missing = []
not_on_main = []
for rel in context_files:
    p = Path(rel)
    if not p.exists():
        missing.append(rel)
        continue
    check = subprocess.run(
        ["git", "cat-file", "-e", f"main:{rel}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode != 0:
        not_on_main.append(rel)

if missing:
    print("[preflight] ERROR: context files missing in working tree:", file=sys.stderr)
    for item in missing:
        print(f"  - {item}", file=sys.stderr)
    sys.exit(1)

if not_on_main:
    strict = os.environ.get("CYNTRA_STRICT_CONTEXT_MAIN", "1") != "0"
    level = "ERROR" if strict else "WARN"
    stream = sys.stderr if strict else sys.stdout
    print(f"[preflight] {level}: context files are not committed on branch 'main':", file=stream)
    for item in not_on_main:
        print(f"  - {item}", file=stream)
    if strict:
        print("[preflight] Commit required context docs before dispatch for reproducible workcells.", file=stream)
        sys.exit(1)
    else:
        print("[preflight] WARN: continuing with non-reproducible context (strict mode disabled).", file=stream)

ready = sum(1 for issue in issues if issue.get("status") == "ready")
print(f"[preflight] beads graph OK: issues={len(issues)} deps={len(deps)} ready={ready} context_files={len(context_files)}")
PY

if [[ "$run_status_check" == "1" ]]; then
  scripts/cyntra/cyntra.sh status >/dev/null
  info "kernel status check OK"
fi

info "preflight checks passed"
