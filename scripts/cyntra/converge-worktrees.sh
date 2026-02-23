#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

integrated_branch="${CYNTRA_CONVERGENCE_INTEGRATED_BRANCH:-main}"
configured_integrated_path="${CYNTRA_INTEGRATED_WORKTREE_PATH:-}"
require_integrated="${CYNTRA_CONVERGENCE_REQUIRE_INTEGRATED_WORKTREE:-1}"
run_compile="${CYNTRA_CONVERGENCE_RUN_COMPILE:-1}"
run_gates="${CYNTRA_CONVERGENCE_RUN_GATES:-1}"
gate_modes="${CYNTRA_CONVERGENCE_GATE_MODES:-context diff java}"
gate_context_strict="${CYNTRA_CONVERGENCE_GATE_CONTEXT_STRICT:-0}"
report_dir="${CYNTRA_CONVERGENCE_REPORT_DIR:-$repo_root/.cyntra/reports/convergence}"
active_gradle_user_home="${CYNTRA_CONVERGENCE_ACTIVE_GRADLE_USER_HOME:-$repo_root/.gradle-user-home}"
integrated_gradle_user_home="${CYNTRA_CONVERGENCE_INTEGRATED_GRADLE_USER_HOME:-}"

fail() {
  echo "[converge] ERROR: $*" >&2
  exit 1
}

info() {
  echo "[converge] $*"
}

is_enabled() {
  local value="${1:-}"
  case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_integrated_worktree_path() {
  local requested_branch="$1"
  local current_path
  local worktree_path=""
  local worktree_branch=""
  local line

  current_path="$(cd "$repo_root" && pwd -P)"

  if [[ -n "$configured_integrated_path" ]]; then
    [[ -d "$configured_integrated_path" ]] || fail "configured integrated worktree path does not exist: $configured_integrated_path"
    (cd "$configured_integrated_path" && pwd -P)
    return 0
  fi

  while IFS= read -r line; do
    case "$line" in
      worktree\ *)
        worktree_path="${line#worktree }"
        worktree_branch=""
        ;;
      branch\ refs/heads/*)
        worktree_branch="${line#branch refs/heads/}"
        if [[ "$worktree_branch" == "$requested_branch" && -n "$worktree_path" && -d "$worktree_path" ]]; then
          local canonical_path
          canonical_path="$(cd "$worktree_path" && pwd -P)"
          if [[ "$canonical_path" != "$current_path" ]]; then
            printf '%s\n' "$canonical_path"
            return 0
          fi
        fi
        ;;
    esac
  done < <(git worktree list --porcelain)

  return 1
}

append_report() {
  printf '%s\n' "$*" >>"$report_path"
}

mark_step() {
  local step_label="$1"
  local step_status="$2"
  local step_log="$3"
  append_report "- ${step_label}: ${step_status}"
  append_report "  log: ${step_log}"
}

while (($# > 0)); do
  case "$1" in
    --checklist-only)
      run_compile=0
      run_gates=0
      ;;
    --no-compile)
      run_compile=0
      ;;
    --no-gates)
      run_gates=0
      ;;
    --integrated-branch=*)
      integrated_branch="${1#*=}"
      ;;
    --integrated-path=*)
      configured_integrated_path="${1#*=}"
      ;;
    --require-integrated=*)
      require_integrated="${1#*=}"
      ;;
    --report-dir=*)
      report_dir="${1#*=}"
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

mkdir -p "$report_dir"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
report_path="$report_dir/convergence-${timestamp}.txt"
latest_report="$report_dir/latest.txt"
logs_dir="$report_dir/logs"
mkdir -p "$logs_dir"

append_report "# Cyntra Convergence Report"
append_report ""
append_report "timestamp_utc: ${timestamp}"
append_report "repo_root: ${repo_root}"

active_path="$(cd "$repo_root" && pwd -P)"
active_branch="$(git -C "$active_path" rev-parse --abbrev-ref HEAD)"
active_head="$(git -C "$active_path" rev-parse HEAD)"
append_report "active_path: ${active_path}"
append_report "active_branch: ${active_branch}"
append_report "active_head: ${active_head}"

integrated_path="$(resolve_integrated_worktree_path "$integrated_branch" || true)"
if [[ -z "$integrated_path" ]]; then
  if is_enabled "$require_integrated"; then
    fail "unable to resolve integrated worktree for branch '${integrated_branch}' (set CYNTRA_INTEGRATED_WORKTREE_PATH or --integrated-path=...)"
  fi
  append_report "integrated_path: <missing>"
  append_report "integrated_branch: ${integrated_branch}"
  append_report "integrated_head: <missing>"
  append_report "ahead_behind: <skipped>"
  append_report "conflict_status: <skipped>"
  append_report ""
  append_report "## Checklist"
  append_report "- compile(active): cd ${active_path} && GRADLE_USER_HOME=${active_gradle_user_home} ./gradlew --no-daemon :Framework-TraceModeling:compileJava :Reverend:compileJava :Reverend:test --tests ghidra.reverend.cockpit.*"
  append_report "- integrated worktree missing; configure CYNTRA_INTEGRATED_WORKTREE_PATH for branch '${integrated_branch}'"
  cp "$report_path" "$latest_report"
  info "integrated worktree not found; wrote checklist-only report: $report_path"
  exit 0
fi

integrated_path="$(cd "$integrated_path" && pwd -P)"
integrated_branch_actual="$(git -C "$integrated_path" rev-parse --abbrev-ref HEAD)"
integrated_head="$(git -C "$integrated_path" rev-parse HEAD)"
integrated_gradle_user_home="${integrated_gradle_user_home:-$integrated_path/.gradle-user-home}"
append_report "integrated_path: ${integrated_path}"
append_report "integrated_branch: ${integrated_branch_actual}"
append_report "integrated_head: ${integrated_head}"

read -r ahead_count behind_count < <(git rev-list --left-right --count "${active_head}...${integrated_head}")
append_report "ahead_behind(active_vs_integrated): ahead=${ahead_count} behind=${behind_count}"

merge_base="$(git merge-base "$active_head" "$integrated_head")"
if git merge-tree "$merge_base" "$active_head" "$integrated_head" | grep -q '^<<<<<<< '; then
  conflict_status="conflict-risk-detected"
else
  conflict_status="clean-merge-prediction"
fi
append_report "conflict_status: ${conflict_status}"
append_report ""
append_report "## Checklist"
append_report "- compile(active): cd ${active_path} && GRADLE_USER_HOME=${active_gradle_user_home} ./gradlew --no-daemon :Framework-TraceModeling:compileJava :Reverend:compileJava :Reverend:test --tests ghidra.reverend.cockpit.*"
append_report "- compile(integrated): cd ${integrated_path} && GRADLE_USER_HOME=${integrated_gradle_user_home} ./gradlew --no-daemon :Framework-TraceModeling:compileJava :Reverend:compileJava :Reverend:test --tests ghidra.reverend.cockpit.*"
for mode in $gate_modes; do
  append_report "- gates(${mode},active): cd ${active_path} && CYNTRA_GATE_CONTEXT_STRICT=${gate_context_strict} bash scripts/cyntra/gates.sh --mode=${mode}"
  append_report "- gates(${mode},integrated): cd ${integrated_path} && CYNTRA_GATE_CONTEXT_STRICT=${gate_context_strict} bash scripts/cyntra/gates.sh --mode=${mode}"
done

failures=0
append_report ""
append_report "## Evidence"

if is_enabled "$run_compile"; then
  active_compile_log="${logs_dir}/${timestamp}-active-compile.log"
  if (
    cd "$active_path"
    GRADLE_USER_HOME="$active_gradle_user_home" ./gradlew --no-daemon \
      :Framework-TraceModeling:compileJava \
      :Reverend:compileJava \
      :Reverend:test --tests "ghidra.reverend.cockpit.*"
  ) >"$active_compile_log" 2>&1; then
    mark_step "compile(active)" "pass" "$active_compile_log"
  else
    mark_step "compile(active)" "fail" "$active_compile_log"
    failures=$((failures + 1))
  fi

  integrated_compile_log="${logs_dir}/${timestamp}-integrated-compile.log"
  if (
    cd "$integrated_path"
    GRADLE_USER_HOME="$integrated_gradle_user_home" ./gradlew --no-daemon \
      :Framework-TraceModeling:compileJava \
      :Reverend:compileJava \
      :Reverend:test --tests "ghidra.reverend.cockpit.*"
  ) >"$integrated_compile_log" 2>&1; then
    mark_step "compile(integrated)" "pass" "$integrated_compile_log"
  else
    mark_step "compile(integrated)" "fail" "$integrated_compile_log"
    failures=$((failures + 1))
  fi
else
  append_report "- compile(active): skipped"
  append_report "- compile(integrated): skipped"
fi

if is_enabled "$run_gates"; then
  for mode in $gate_modes; do
    active_gate_log="${logs_dir}/${timestamp}-active-gates-${mode}.log"
    if (
      cd "$active_path"
      CYNTRA_GATE_CONTEXT_STRICT="$gate_context_strict" bash scripts/cyntra/gates.sh "--mode=${mode}"
    ) >"$active_gate_log" 2>&1; then
      mark_step "gates(${mode},active)" "pass" "$active_gate_log"
    else
      mark_step "gates(${mode},active)" "fail" "$active_gate_log"
      failures=$((failures + 1))
    fi

    integrated_gate_log="${logs_dir}/${timestamp}-integrated-gates-${mode}.log"
    if (
      cd "$integrated_path"
      CYNTRA_GATE_CONTEXT_STRICT="$gate_context_strict" bash scripts/cyntra/gates.sh "--mode=${mode}"
    ) >"$integrated_gate_log" 2>&1; then
      mark_step "gates(${mode},integrated)" "pass" "$integrated_gate_log"
    else
      mark_step "gates(${mode},integrated)" "fail" "$integrated_gate_log"
      failures=$((failures + 1))
    fi
  done
else
  append_report "- gates(active): skipped"
  append_report "- gates(integrated): skipped"
fi

cp "$report_path" "$latest_report"
info "wrote convergence report: $report_path"
info "updated latest report: $latest_report"

if (( failures > 0 )); then
  fail "convergence verification failed (${failures} step(s)); see report ${report_path}"
fi

info "convergence verification passed"
