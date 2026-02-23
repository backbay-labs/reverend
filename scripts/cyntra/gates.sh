#!/usr/bin/env bash
set -euo pipefail

mode="all"
artifact_root="${CYNTRA_GATE_ARTIFACT_DIR:-.cyntra/artifacts/gates}"
# Use a repo-local Gradle user home by default so workcells stay hermetic.
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-.gradle-user-home}"
for arg in "$@"; do
  case "$arg" in
    --mode=*)
      mode="${arg#*=}"
      ;;
  esac
done

module_coverage_generic="not-run"
module_coverage_reverend="not-run"
module_coverage_softwaremodeling="not-run"
module_coverage_base="not-run"

set_module_coverage() {
  local module="$1"
  local status="$2"
  local reason="${3:-}"
  local value="$status"
  if [[ -n "$reason" ]]; then
    value="${value} (${reason})"
  fi

  case "$module" in
    Generic)
      module_coverage_generic="$value"
      ;;
    Reverend)
      module_coverage_reverend="$value"
      ;;
    SoftwareModeling)
      module_coverage_softwaremodeling="$value"
      ;;
    Base)
      module_coverage_base="$value"
      ;;
    *)
      echo "[gates] WARN: unknown module coverage key '${module}'"
      ;;
  esac

  echo "[gates] MODULE_COVERAGE: ${module}=${value}"
}

join_by_comma() {
  local IFS=","
  echo "$*"
}

write_blocking_gate_summary_artifact() {
  local summary_path="${artifact_root}/blocking-gate-summary.json"
  mkdir -p "$artifact_root"
  CYNTRA_MODULE_COVERAGE_GENERIC="$module_coverage_generic" \
    CYNTRA_MODULE_COVERAGE_REVEREND="$module_coverage_reverend" \
    CYNTRA_MODULE_COVERAGE_SOFTWAREMODELING="$module_coverage_softwaremodeling" \
    CYNTRA_MODULE_COVERAGE_BASE="$module_coverage_base" \
    CYNTRA_BLOCKING_SKIP_BUDGET="${CYNTRA_COMPLETION_BLOCKING_SKIP_BUDGET:-0}" \
    python3 - "$summary_path" <<'PY'
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

summary_path = Path(__import__("sys").argv[1])


def _as_int(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            try:
                return int(text)
            except Exception:
                return None
    return None


def parse_coverage(module: str, value: str) -> dict:
    text = (value or "").strip()
    lowered = text.lower()
    if lowered.startswith("executed"):
        return {"module": module, "status": "executed", "reason": ""}
    if lowered.startswith("skipped"):
        reason = ""
        match = re.match(r"^skipped\s*\((.+)\)\s*$", text, flags=re.IGNORECASE)
        if match:
            reason = match.group(1).strip()
        else:
            match = re.match(r"^skipped\s*:\s*(.+)\s*$", text, flags=re.IGNORECASE)
            if match:
                reason = match.group(1).strip()
        return {"module": module, "status": "skipped", "reason": reason}
    return {"module": module, "status": text or "not-run", "reason": ""}


coverages = [
    parse_coverage("Generic", os.environ.get("CYNTRA_MODULE_COVERAGE_GENERIC", "")),
    parse_coverage("Reverend", os.environ.get("CYNTRA_MODULE_COVERAGE_REVEREND", "")),
    parse_coverage("SoftwareModeling", os.environ.get("CYNTRA_MODULE_COVERAGE_SOFTWAREMODELING", "")),
    parse_coverage("Base", os.environ.get("CYNTRA_MODULE_COVERAGE_BASE", "")),
]
blocking_gate_skips = [
    {"gate": item["module"], "reason": item["reason"], "status": "skipped"}
    for item in coverages
    if item["status"] == "skipped"
]
blocking_gate_skip_reasons = sorted(
    {
        str(item.get("reason") or "").strip()
        for item in blocking_gate_skips
        if str(item.get("reason") or "").strip()
    },
    key=lambda text: text.lower(),
)
blocking_gate_skip_budget = max(_as_int(os.environ.get("CYNTRA_BLOCKING_SKIP_BUDGET")) or 0, 0)
blocking_gate_skipped_count = len(blocking_gate_skips)

gate_summary = {
    "module_coverage_generic": os.environ.get("CYNTRA_MODULE_COVERAGE_GENERIC", ""),
    "module_coverage_reverend": os.environ.get("CYNTRA_MODULE_COVERAGE_REVEREND", ""),
    "module_coverage_softwaremodeling": os.environ.get("CYNTRA_MODULE_COVERAGE_SOFTWAREMODELING", ""),
    "module_coverage_base": os.environ.get("CYNTRA_MODULE_COVERAGE_BASE", ""),
    "blocking_gate_skips": blocking_gate_skips,
    "blocking_gate_skipped_count": blocking_gate_skipped_count,
    "blocking_gate_skip_reasons": blocking_gate_skip_reasons,
    "blocking_gate_skip_budget": blocking_gate_skip_budget,
}
payload = {
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "source": "scripts/cyntra/gates.sh",
    "gate_summary": gate_summary,
    **gate_summary,
}
summary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
  echo "[gates] blocking gate skip summary artifact: $summary_path"
}

check_manifest_context() {
  python3 - <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

issues_ref = (os.environ.get("CYNTRA_ISSUES_REF") or "HEAD").strip() or "HEAD"
strict = os.environ.get("CYNTRA_GATE_CONTEXT_STRICT", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
    "",
}


def fail(message: str) -> None:
    print(f"[gates] ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def warn(message: str) -> None:
    print(f"[gates] WARN: {message}")


def load_manifest():
    path = Path("manifest.json")
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid manifest.json: {exc}")


def parse_context_files(values):
    if not isinstance(values, list):
        return []
    output = []
    for value in values:
        if isinstance(value, str) and value.strip():
            output.append(value.strip())
    return output


def load_issues():
    local = Path(".beads/issues.jsonl")
    if local.exists():
        text = local.read_text(encoding="utf-8")
        source = str(local)
    else:
        source = f"{issues_ref}:.beads/issues.jsonl"
        try:
            text = subprocess.check_output(
                ["git", "show", source],
                text=True,
                stderr=subprocess.STDOUT,
            )
        except Exception as exc:
            return {}, f"{source} (unavailable: {exc})"

    issues = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            issue = json.loads(line)
        except Exception:
            continue
        issue_id = str(issue.get("id") or "").strip()
        if issue_id:
            issues[issue_id] = issue
    return issues, source


def infer_issue_from_branch():
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "", ""

    patterns = (
        r"^wc/(\d+)(?:/|$)",
        r"^wc-(\d+)(?:-|$)",
        r"^workcell/(\d+)(?:/|$)",
    )
    for pattern in patterns:
        match = re.match(pattern, branch)
        if match:
            return match.group(1), branch
    return "", branch


issue_id = ""
context_files = []
source = ""
manifest = load_manifest()
if manifest is not None:
    issue_block = manifest.get("issue") if isinstance(manifest, dict) else {}
    if isinstance(issue_block, dict):
        issue_id = str(issue_block.get("id") or issue_block.get("issue_id") or "").strip()
        context_files = parse_context_files(issue_block.get("context_files"))
    if not context_files and isinstance(manifest, dict):
        context_files = parse_context_files(manifest.get("context_files"))
    source = "manifest.json"

if not issue_id:
    issue_id = str(os.environ.get("CYNTRA_GATE_ISSUE_ID") or "").strip()
    if issue_id:
        source = source or "CYNTRA_GATE_ISSUE_ID"

branch_name = ""
if not issue_id:
    inferred_issue_id, branch_name = infer_issue_from_branch()
    if inferred_issue_id:
        issue_id = inferred_issue_id
        source = source or f"branch:{branch_name}"

if issue_id and not context_files:
    issues, issues_source = load_issues()
    issue = issues.get(issue_id)
    if issue:
        context_files = parse_context_files(issue.get("context_files"))
        if source and source != "manifest.json":
            source = f"{source}+{issues_source}"
        else:
            source = issues_source
    else:
        warn(f"issue #{issue_id} not found in {issues_source}; cannot derive context_files")

if not context_files:
    message = "unable to resolve context files from manifest, issue id, or branch"
    if strict:
        fail(message)
    warn(f"{message}; skipping context-file existence checks")
    fallback = "repo-root"
    if branch_name:
        fallback = f"{fallback} (branch={branch_name})"
    print(f"[gates] context fallback active: {fallback}")
    raise SystemExit(0)

missing = []
skipped = []
for rel in context_files:
    if rel.startswith(".beads/"):
        skipped.append(rel)
        continue
    if not Path(rel).exists():
        missing.append(rel)

if missing:
    print("[gates] ERROR: context files missing in worktree:", file=sys.stderr)
    for rel in missing:
        print(f"  - {rel}", file=sys.stderr)
    raise SystemExit(1)

issue_suffix = f", issue={issue_id}" if issue_id else ""
print(f"[gates] context OK ({len(context_files)} files) via {source or 'unknown'}{issue_suffix}")
if skipped:
    print(f"[gates] context skipped ({len(skipped)} kernel-owned files)")
PY
}

check_diff_sanity() {
  git diff --check -- . >/dev/null
  if rg -n "^(<<<<<<<|>>>>>>>)" . >/dev/null 2>&1; then
    echo "[gates] ERROR: unresolved merge conflict markers found" >&2
    rg -n "^(<<<<<<<|>>>>>>>)" . || true
    exit 1
  fi
  echo "[gates] diff sanity OK"
}

enforce_nonzero_diff_or_noop() {
  python3 - <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path


def changed_stats() -> tuple[int, int]:
    ignored_prefixes = (
        ".beads/",
        ".cyntra/",
        ".gradle/",
        ".gradle-user-home/",
        ".idea/",
        ".vscode/",
        "build/",
        "dist/",
        "logs/",
        "tmp/",
    )
    ignored_exact = {
        ".DS_Store",
        ".mise.toml",
        ".workcell",
        "manifest.json",
        "prompt.md",
        "proof.json",
        "rollout.json",
        "telemetry.jsonl",
    }

    def should_ignore(path: str) -> bool:
        normalized = path.replace("\\", "/").lstrip("./")
        if not normalized:
            return True
        if normalized in ignored_exact:
            return True
        return any(normalized.startswith(prefix) for prefix in ignored_prefixes)

    def collect_diff_stats(*diff_args: str) -> tuple[set[str], int]:
        files_out = subprocess.check_output(
            ["git", "diff", "--name-only", *diff_args, "--", "."],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        files = {
            line.strip()
            for line in files_out.splitlines()
            if line.strip() and not should_ignore(line.strip())
        }
        lines_out = subprocess.check_output(
            ["git", "diff", "--numstat", *diff_args, "--", "."],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        line_count = 0
        for row in lines_out.splitlines():
            parts = row.split("\t")
            if len(parts) < 2:
                continue
            try:
                added = 0 if parts[0] == "-" else int(parts[0])
                deleted = 0 if parts[1] == "-" else int(parts[1])
            except ValueError:
                continue
            line_count += added + deleted
        return files, line_count

    def resolve_workcell_commit_diff_range() -> str:
        if not Path(".workcell").exists():
            return ""
        candidates: list[str] = []
        env_base = os.environ.get("CYNTRA_NONZERO_DIFF_BASE", "").strip()
        if env_base:
            candidates.append(env_base)
        try:
            upstream = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            upstream = ""
        if upstream:
            candidates.append(upstream)
        try:
            origin_head = subprocess.check_output(
                ["git", "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            origin_head = ""
        if origin_head:
            candidates.append(origin_head)
        candidates.extend(["origin/master", "origin/main", "master", "main"])

        try:
            head_commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            head_commit = ""
        if not head_commit:
            return ""

        seen: set[str] = set()
        for ref in candidates:
            if not ref or ref in seen:
                continue
            seen.add(ref)
            verified = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if verified.returncode != 0:
                continue
            try:
                merge_base = subprocess.check_output(
                    ["git", "merge-base", "HEAD", ref],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
            except Exception:
                continue
            if merge_base and merge_base != head_commit:
                return f"{merge_base}...HEAD"

        prior = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", "HEAD~1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if prior.returncode == 0:
            return "HEAD~1...HEAD"
        return ""

    files, line_count = collect_diff_stats()
    status_out = subprocess.check_output(
        ["git", "status", "--porcelain", "--", "."],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    untracked = []
    for row in status_out.splitlines():
        if not row:
            continue
        code = row[:2]
        path = row[3:].strip()
        if not path:
            continue
        if code == "??" and not should_ignore(path):
            untracked.append(path)
    all_files = set(files)
    all_files.update(untracked)
    # Preserve non-zero diff semantics for untracked-only changes.
    if line_count == 0 and untracked:
        line_count = len(untracked)

    # Workcells can gate after committing changes; account for committed branch delta too.
    if not all_files and line_count == 0:
        commit_range = resolve_workcell_commit_diff_range()
        if commit_range:
            committed_files, committed_lines = collect_diff_stats(commit_range)
            all_files.update(committed_files)
            line_count += committed_lines
    return len(all_files), line_count


def load_manifest() -> dict:
    path = Path("manifest.json")
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def manifest_noop_reason(manifest: dict) -> str:
    if not manifest:
        return ""
    issue = manifest.get("issue")
    if isinstance(issue, dict):
        reason = str(issue.get("noop_justification") or "").strip()
        if reason:
            return reason
        tags = issue.get("tags")
        if isinstance(tags, list) and "allow-zero-diff" in {str(tag).strip() for tag in tags}:
            return "issue.tags includes allow-zero-diff"
    top_reason = str(manifest.get("noop_justification") or "").strip()
    if top_reason:
        return top_reason
    top_tags = manifest.get("tags")
    if isinstance(top_tags, list) and "allow-zero-diff" in {str(tag).strip() for tag in top_tags}:
        return "manifest.tags includes allow-zero-diff"
    return ""


files_changed, total_lines = changed_stats()
if files_changed > 0 or total_lines > 0:
    print(f"[gates] nonzero diff OK (files={files_changed}, lines={total_lines})")
    raise SystemExit(0)

if os.environ.get("CYNTRA_ALLOW_ZERO_DIFF", "").strip().lower() in {"1", "true", "yes", "on"}:
    print("[gates] WARN: zero diff accepted via CYNTRA_ALLOW_ZERO_DIFF")
    raise SystemExit(0)

reason = manifest_noop_reason(load_manifest())
if reason:
    print(f"[gates] WARN: zero diff accepted with explicit no-op justification: {reason}")
    raise SystemExit(0)

print(
    "[gates] ERROR: zero-diff workcell rejected; require code/doc changes or explicit no-op justification",
    file=sys.stderr,
)
print(
    "[gates] hint: add manifest issue.noop_justification or set CYNTRA_ALLOW_ZERO_DIFF=1 for intentional no-op",
    file=sys.stderr,
)
raise SystemExit(1)
PY
}

run_tracked_python_unittests() {
  local test_dir="$1"
  local -a test_files=()
  local test_file module_name
  while IFS= read -r test_file; do
    [[ -n "$test_file" ]] || continue
    test_files+=("$test_file")
  done < <(git ls-files "${test_dir}"/test_*.py)

  if [[ ${#test_files[@]} -eq 0 ]]; then
    echo "[gates] python regression skipped: no tracked tests under ${test_dir}"
    return 0
  fi

  echo "[gates] running python regression (tracked): ${test_dir} (${#test_files[@]} files)"
  for test_file in "${test_files[@]}"; do
    module_name="${test_file%.py}"
    module_name="${module_name//\//.}"
    python3 -m unittest "$module_name"
  done
}

run_python_regression() {
  run_tracked_python_unittests "scripts/ml/tests"
  run_tracked_python_unittests "scripts/tests"
  echo "[gates] python regression OK"
}

run_java_regression() {
  local java_gate_src="scripts/tests/java/MvpGateThresholdRegression.java"
  local java_gate_out="${artifact_root}/java"
  local thresholds_path="eval/config/mvp_gate_thresholds.json"

  if [[ ! -f "$java_gate_src" ]]; then
    echo "[gates] ERROR: missing Java gate source: $java_gate_src" >&2
    exit 1
  fi
  if [[ ! -f "$thresholds_path" ]]; then
    echo "[gates] ERROR: missing threshold config: $thresholds_path" >&2
    exit 1
  fi
  if ! command -v javac >/dev/null 2>&1; then
    echo "[gates] ERROR: javac not found; Java regression gate cannot run" >&2
    exit 1
  fi
  if ! command -v java >/dev/null 2>&1; then
    echo "[gates] ERROR: java runtime not found; Java regression gate cannot run" >&2
    exit 1
  fi

  mkdir -p "$java_gate_out"
  rm -f "$java_gate_out"/*.class
  javac -d "$java_gate_out" "$java_gate_src"
  java -cp "$java_gate_out" MvpGateThresholdRegression "$thresholds_path"
  echo "[gates] java regression OK (artifacts: $java_gate_out/*.class)"
}

require_gradle_build_prereqs() {
  if [[ -d "dependencies/flatRepo" || -f "ghidra.repos.config" ]]; then
    return 0
  fi

  echo "[gates] build dependency configuration missing; bootstrapping via fetchDependencies.gradle"

  local -a bootstrap_cmd=()
  if [[ -x "./gradlew" ]]; then
    bootstrap_cmd=("./gradlew" "-I" "gradle/support/fetchDependencies.gradle" "--no-daemon")
  elif command -v gradle >/dev/null 2>&1; then
    bootstrap_cmd=("gradle" "-I" "gradle/support/fetchDependencies.gradle" "--no-daemon")
  else
    echo "[gates] ERROR: cannot bootstrap dependencies (missing ./gradlew and gradle command)" >&2
    exit 1
  fi

  "${bootstrap_cmd[@]}"

  if [[ ! -d "dependencies/flatRepo" && ! -f "ghidra.repos.config" ]]; then
    echo "[gates] ERROR: missing build dependency configuration after bootstrap (need dependencies/flatRepo or ghidra.repos.config)" >&2
    echo "[gates] hint: run 'gradle -I gradle/support/fetchDependencies.gradle' manually and check network/proxy config" >&2
    exit 1
  fi
}

has_java_scope_changes() {
  git diff --name-only -- . | rg -q '^(Ghidra/|GPL/|GhidraBuild/|gradle/|build\.gradle$|settings\.gradle$|gradle\.properties$)'
}

run_security_compile_regression() {
  if ! has_java_scope_changes; then
    echo "[gates] security compile gate skipped (no Java/Ghidra scope changes)"
    set_module_coverage "Generic" "skipped" "no scope changes"
    return 0
  fi

  require_gradle_build_prereqs

  local gradle_cmd=("./gradlew")
  if [[ ! -x "./gradlew" ]]; then
    if command -v gradle >/dev/null 2>&1; then
      gradle_cmd=("gradle")
    else
      echo "[gates] ERROR: neither ./gradlew nor gradle command is available" >&2
      exit 1
    fi
  fi

  echo "[gates] compiling security-bearing Generic module (blocking)"
  "${gradle_cmd[@]}" --no-daemon :Generic:compileJava
  echo "[gates] running Generic security tests (blocking)"
  "${gradle_cmd[@]}" --no-daemon :Generic:test --tests "ghidra.security.*"
  python3 scripts/cyntra/check-junit-failures.py \
    --results-dir Ghidra/Framework/Generic/build/test-results/test
  echo "[gates] Generic security compile/test regression OK"
  set_module_coverage "Generic" "executed"
}

run_reverend_compile_regression() {
  if ! has_java_scope_changes; then
    echo "[gates] Reverend compile gate skipped (no Java/Ghidra scope changes)"
    set_module_coverage "Reverend" "skipped" "no scope changes"
    return 0
  fi

  require_gradle_build_prereqs

  local gradle_cmd=("./gradlew")
  if [[ ! -x "./gradlew" ]]; then
    if command -v gradle >/dev/null 2>&1; then
      gradle_cmd=("gradle")
    else
      echo "[gates] ERROR: neither ./gradlew nor gradle command is available" >&2
      exit 1
    fi
  fi

  echo "[gates] compiling Reverend module (blocking)"
  "${gradle_cmd[@]}" --no-daemon :Reverend:compileJava
  echo "[gates] running Reverend unit tests (blocking)"
  "${gradle_cmd[@]}" --no-daemon :Reverend:test --tests "ghidra.reverend.*"
  python3 scripts/cyntra/check-junit-failures.py \
    --results-dir Ghidra/Features/Reverend/build/test-results/test
  echo "[gates] Reverend compile/test regression OK"
  set_module_coverage "Reverend" "executed"
}

run_frontier_compile_regression() {
  if ! has_java_scope_changes; then
    echo "[gates] frontier compile gate skipped (no Java/Ghidra scope changes)"
    set_module_coverage "SoftwareModeling" "skipped" "no scope changes"
    set_module_coverage "Base" "skipped" "no scope changes"
    return 0
  fi

  require_gradle_build_prereqs

  local gradle_cmd=("./gradlew")
  if [[ ! -x "./gradlew" ]]; then
    if command -v gradle >/dev/null 2>&1; then
      gradle_cmd=("gradle")
    else
      echo "[gates] ERROR: neither ./gradlew nor gradle command is available" >&2
      exit 1
    fi
  fi

  # Compile key frontier modules that form the dependency backbone
  echo "[gates] compiling frontier modules: SoftwareModeling, Base (blocking)"
  "${gradle_cmd[@]}" --no-daemon :SoftwareModeling:compileJava :Base:compileJava
  echo "[gates] frontier module compile OK"
  set_module_coverage "SoftwareModeling" "executed"
  set_module_coverage "Base" "executed"
}

run_security_evidence_integrity() {
  local bundle_1702="docs/security/evidence/abuse-scenario-suite-1702"
  local bundle_1806="docs/security/evidence/abuse-scenario-suite-1806"

  python3 - "$bundle_1702" "$bundle_1806" <<'PY'
import hashlib
import sys
from pathlib import Path

bundles = [Path(arg) for arg in sys.argv[1:]]
errors: list[str] = []
checked = 0

for bundle in bundles:
    manifest = bundle / "checksums.sha256"
    if not manifest.exists():
        errors.append(f"missing checksum manifest: {manifest}")
        continue
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append(f"failed to read manifest {manifest}: {exc}")
        continue

    if not lines:
        errors.append(f"empty checksum manifest: {manifest}")
        continue

    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line:
            continue
        if "  " not in line:
            errors.append(f"{manifest}:{lineno}: invalid checksum entry (expected '<sha256>  <path>')")
            continue
        digest, rel = line.split("  ", 1)
        rel = rel.strip()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            errors.append(f"{manifest}:{lineno}: invalid sha256 digest '{digest}'")
            continue
        target = bundle / rel
        if not target.exists():
            errors.append(f"{manifest}:{lineno}: missing referenced file '{rel}'")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest.lower():
            errors.append(
                f"{manifest}:{lineno}: checksum mismatch for '{rel}' (expected {digest.lower()}, got {actual})"
            )
            continue
        checked += 1

if errors:
    print("[gates] ERROR: security evidence integrity failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"[gates] security evidence integrity OK ({checked} checksum entries verified)")
PY
}

run_eval_regression() {
  local smoke_runner="eval/run_smoke.sh"
  local regression_checker="eval/scripts/check_regression.py"
  local baseline_path="eval/snapshots/baseline.json"
  local eval_gate_out="${artifact_root}/eval"
  local metrics_out="${eval_gate_out}/smoke-metrics.json"
  local regression_out="${eval_gate_out}/regression.json"

  if [[ ! -f "$smoke_runner" ]]; then
    echo "[gates] ERROR: missing smoke runner: $smoke_runner" >&2
    exit 1
  fi
  if [[ ! -f "$regression_checker" ]]; then
    echo "[gates] ERROR: missing regression checker: $regression_checker" >&2
    exit 1
  fi
  if [[ ! -f "$baseline_path" ]]; then
    echo "[gates] ERROR: missing smoke baseline: $baseline_path" >&2
    exit 1
  fi

  mkdir -p "$eval_gate_out"
  bash "$smoke_runner" --output "$metrics_out"
  python3 "$regression_checker" \
    --current "$metrics_out" \
    --baseline "$baseline_path" \
    --output "$regression_out"
  echo "[gates] eval regression OK (artifacts: $metrics_out, $regression_out)"
}

run_query_slo_gate() {
  local query_slo_reporter="eval/scripts/query_slo_report.py"
  local thresholds_path="eval/config/query_slo_thresholds.json"
  local smoke_runner="eval/run_smoke.sh"
  local eval_gate_out="${artifact_root}/eval"
  local metrics_out="${eval_gate_out}/smoke-metrics.json"
  local query_slo_json="${eval_gate_out}/query-slo-report.json"
  local query_slo_md="${eval_gate_out}/query-slo-report.md"

  if [[ ! -f "$query_slo_reporter" ]]; then
    echo "[gates] ERROR: missing query SLO reporter: $query_slo_reporter" >&2
    exit 1
  fi
  if [[ ! -f "$thresholds_path" ]]; then
    echo "[gates] ERROR: missing query SLO thresholds: $thresholds_path" >&2
    exit 1
  fi
  if [[ ! -f "$smoke_runner" ]]; then
    echo "[gates] ERROR: missing smoke runner: $smoke_runner" >&2
    exit 1
  fi

  mkdir -p "$eval_gate_out"
  if [[ ! -f "$metrics_out" ]]; then
    bash "$smoke_runner" --output "$metrics_out"
  fi

  python3 "$query_slo_reporter" \
    --metrics "$metrics_out" \
    --thresholds "$thresholds_path" \
    --output-json "$query_slo_json" \
    --output-md "$query_slo_md" \
    --fail-on-breach
  echo "[gates] query SLO OK (artifacts: $query_slo_json, $query_slo_md)"
}

run_operational_claim_gate() {
  local smoke_runner="eval/run_smoke.sh"
  local regression_checker="eval/scripts/check_regression.py"
  local operational_baseline="${CYNTRA_OPERATIONAL_CLAIM_BASELINE:-eval/snapshots/operational_claim_baseline.json}"
  local eval_gate_out="${artifact_root}/eval"
  local metrics_out="${eval_gate_out}/smoke-metrics.json"
  local regression_out="${eval_gate_out}/operational-claim-regression.json"
  local delta_out="${eval_gate_out}/operational-claim-delta.json"
  local manifest_out="${eval_gate_out}/operational-claim-manifest.json"
  local regression_status=0

  if [[ ! -f "$smoke_runner" ]]; then
    echo "[gates] ERROR: missing smoke runner: $smoke_runner" >&2
    exit 1
  fi
  if [[ ! -f "$regression_checker" ]]; then
    echo "[gates] ERROR: missing regression checker: $regression_checker" >&2
    exit 1
  fi
  if [[ ! -f "$operational_baseline" ]]; then
    echo "[gates] ERROR: missing operational claim baseline: $operational_baseline" >&2
    exit 1
  fi

  mkdir -p "$eval_gate_out"
  if [[ ! -f "$metrics_out" ]]; then
    bash "$smoke_runner" --output "$metrics_out"
  fi

  set +e
  python3 "$regression_checker" \
    --current "$metrics_out" \
    --baseline "$operational_baseline" \
    --require-area real_target \
    --require-area spec_review \
    --output "$regression_out"
  regression_status=$?
  set -e

  python3 - "$metrics_out" "$operational_baseline" "$regression_out" "$delta_out" "$manifest_out" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def fail(message: str) -> None:
    print(f"[gates] ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_doc(path: Path, label: str) -> dict:
    if not path.exists():
        fail(f"{label} missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"failed to parse {label} {path}: {exc}")
    if not isinstance(payload, dict):
        fail(f"{label} must be a JSON object: {path}")
    return payload


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


metrics_path = Path(sys.argv[1])
baseline_path = Path(sys.argv[2])
regression_path = Path(sys.argv[3])
delta_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])

metrics_doc = load_doc(metrics_path, "smoke metrics")
baseline_doc = load_doc(baseline_path, "operational baseline")
regression_doc = load_doc(regression_path, "operational regression")

results = regression_doc.get("results")
if not isinstance(results, list):
    fail("operational regression artifact missing 'results' list")

operational_areas = {"real_target", "spec_review"}
operational_results = []
for row in results:
    if not isinstance(row, dict):
        continue
    if str(row.get("area", "")).strip() in operational_areas:
        operational_results.append(row)

if not operational_results:
    fail("operational regression artifact did not evaluate real_target/spec_review metrics")

failures = [row for row in operational_results if not bool(row.get("passed"))]
benchmark_slices = metrics_doc.get("benchmark_slices")
if not isinstance(benchmark_slices, list):
    benchmark_slices = []
selected_slices = []
for slice_row in benchmark_slices:
    if not isinstance(slice_row, dict):
        continue
    kind = str(slice_row.get("kind", "")).strip()
    slice_id = str(slice_row.get("slice_id", "")).strip()
    if kind in {"real_target", "fixture", "operator_workflow"} or slice_id == "spec-review-v1":
        selected_slices.append(slice_row)

if not selected_slices:
    selected_slices = benchmark_slices

per_area: dict[str, list[dict]] = {}
for row in sorted(
    operational_results,
    key=lambda item: (str(item.get("area", "")), str(item.get("name", ""))),
):
    area = str(row.get("area", "")).strip() or "unknown"
    per_area.setdefault(area, []).append(
        {
            "metric": row.get("name"),
            "baseline": row.get("baseline"),
            "current": row.get("current"),
            "delta": row.get("delta"),
            "operator": row.get("operator"),
            "threshold": row.get("threshold"),
            "passed": bool(row.get("passed")),
        }
    )

delta_payload = {
    "schema_version": 1,
    "kind": "operational_claim_baseline_vs_current",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "source": {
        "metrics_path": str(metrics_path),
        "metrics_sha256": file_sha256(metrics_path),
        "baseline_path": str(baseline_path),
        "baseline_sha256": file_sha256(baseline_path),
        "regression_path": str(regression_path),
        "regression_sha256": file_sha256(regression_path),
    },
    "reproducibility": {
        "seed": metrics_doc.get("seed"),
        "datasets_lock_sha256": metrics_doc.get("datasets_lock_sha256"),
        "real_target_harness": metrics_doc.get("real_target_harness", {}),
        "benchmark_slice_count": len(selected_slices),
    },
    "benchmark_slices": selected_slices,
    "evaluation": {
        "passed": len(failures) == 0,
        "total_metrics": len(operational_results),
        "failed_metrics": len(failures),
    },
    "threshold_band_breaches": [
        f"{row.get('area')}/{row.get('name')}" for row in failures
    ],
    "areas": per_area,
}

delta_path.write_text(
    json.dumps(delta_payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

manifest_payload = {
    "schema_version": 1,
    "kind": "operational_claim_reproducible_manifest",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "inputs": [
        {"path": str(metrics_path), "sha256": file_sha256(metrics_path)},
        {"path": str(baseline_path), "sha256": file_sha256(baseline_path)},
        {"path": str(regression_path), "sha256": file_sha256(regression_path)},
    ],
    "outputs": [
        {"path": str(delta_path), "sha256": file_sha256(delta_path)},
    ],
    "baseline_contract": {
        "schema_version": baseline_doc.get("schema_version"),
        "kind": baseline_doc.get("kind"),
    },
}
manifest_path.write_text(
    json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

  if (( regression_status != 0 )); then
    echo "[gates] ERROR: operational claim regression breached (artifacts: $regression_out, $delta_out, $manifest_out)" >&2
    exit "$regression_status"
  fi

  echo "[gates] operational claim gate OK (artifacts: $regression_out, $delta_out, $manifest_out)"
}

run_reliability_soak_slo() {
  local soak_runner="eval/run_soak.sh"
  local slo_reporter="eval/scripts/reliability_slo_report.py"
  local thresholds_path="eval/config/reliability_slo_thresholds.json"
  local eval_gate_out="${artifact_root}/eval"
  local soak_out="${eval_gate_out}/soak-report.json"
  local slo_json="${eval_gate_out}/reliability-slo-report.json"
  local slo_md="${eval_gate_out}/reliability-slo-report.md"
  local soak_iterations="${CYNTRA_RELIABILITY_SOAK_ITERATIONS:-3}"
  local deadlock_threshold_seconds="${CYNTRA_RELIABILITY_DEADLOCK_THRESHOLD_SECONDS:-30}"
  local soak_status=0

  if [[ ! "$soak_iterations" =~ ^[0-9]+$ ]] || (( soak_iterations <= 0 )); then
    echo "[gates] ERROR: CYNTRA_RELIABILITY_SOAK_ITERATIONS must be a positive integer (got '$soak_iterations')" >&2
    exit 1
  fi
  if [[ ! -f "$soak_runner" ]]; then
    echo "[gates] ERROR: missing soak runner: $soak_runner" >&2
    exit 1
  fi
  if [[ ! -f "$slo_reporter" ]]; then
    echo "[gates] ERROR: missing reliability SLO reporter: $slo_reporter" >&2
    exit 1
  fi
  if [[ ! -f "$thresholds_path" ]]; then
    echo "[gates] ERROR: missing reliability threshold config: $thresholds_path" >&2
    exit 1
  fi

  mkdir -p "$eval_gate_out"
  if ! bash "$soak_runner" \
    --iterations "$soak_iterations" \
    --deadlock-threshold-seconds "$deadlock_threshold_seconds" \
    --output "$soak_out"; then
    soak_status=$?
  fi

  python3 "$slo_reporter" \
    --soak-report "$soak_out" \
    --thresholds "$thresholds_path" \
    --output-json "$slo_json" \
    --output-md "$slo_md" \
    --fail-on-breach

  if (( soak_status != 0 )); then
    echo "[gates] ERROR: soak runner failed with exit code ${soak_status}" >&2
    exit "$soak_status"
  fi

  echo "[gates] reliability soak SLO OK (artifacts: $soak_out, $slo_json, $slo_md)"
}

run_roadmap_consistency_validation() {
  echo "[gates] validating roadmap source-of-truth consistency (blocking)"
  bash scripts/cyntra/validate-roadmap-completion.sh
  echo "[gates] roadmap source-of-truth consistency OK"
}

print_module_coverage_summary() {
  local -a executed_modules=()
  local -a skipped_modules=()
  local -a unresolved_modules=()
  local module value

  for module in "Generic" "Reverend" "SoftwareModeling" "Base"; do
    case "$module" in
      Generic)
        value="$module_coverage_generic"
        ;;
      Reverend)
        value="$module_coverage_reverend"
        ;;
      SoftwareModeling)
        value="$module_coverage_softwaremodeling"
        ;;
      Base)
        value="$module_coverage_base"
        ;;
    esac

    case "$value" in
      executed*)
        executed_modules+=("$module")
        ;;
      skipped*)
        skipped_modules+=("$module")
        ;;
      *)
        unresolved_modules+=("${module}=${value}")
        ;;
    esac
  done

  echo "[gates] ====== MODULE COVERAGE SUMMARY ======"
  if [[ ${#executed_modules[@]} -gt 0 ]]; then
    echo "[gates] Executed: $(join_by_comma "${executed_modules[@]}")"
  else
    echo "[gates] Executed: none"
  fi
  if [[ ${#skipped_modules[@]} -gt 0 ]]; then
    echo "[gates] Skipped: $(join_by_comma "${skipped_modules[@]}")"
  else
    echo "[gates] Skipped: none"
  fi
  if [[ ${#unresolved_modules[@]} -gt 0 ]]; then
    echo "[gates] Unresolved: $(join_by_comma "${unresolved_modules[@]}")"
  fi
  echo "[gates] Detailed: Generic=${module_coverage_generic}; Reverend=${module_coverage_reverend}; SoftwareModeling=${module_coverage_softwaremodeling}; Base=${module_coverage_base}"
  echo "[gates] ======================================="
}

case "$mode" in
  all)
    check_manifest_context
    check_diff_sanity
    enforce_nonzero_diff_or_noop
    run_python_regression
    run_java_regression
    run_security_compile_regression
    run_reverend_compile_regression
    run_frontier_compile_regression
    run_eval_regression
    run_query_slo_gate
    run_operational_claim_gate
    run_reliability_soak_slo
    run_security_evidence_integrity
    run_roadmap_consistency_validation
    print_module_coverage_summary
    write_blocking_gate_summary_artifact
    ;;
  context)
    check_manifest_context
    run_python_regression
    ;;
  diff)
    check_diff_sanity
    run_java_regression
    ;;
  java)
    run_java_regression
    run_security_compile_regression
    run_reverend_compile_regression
    run_frontier_compile_regression
    print_module_coverage_summary
    write_blocking_gate_summary_artifact
    ;;
  evidence)
    run_security_evidence_integrity
    ;;
  *)
    echo "[gates] ERROR: unknown mode '$mode' (expected all|context|diff|java|evidence)" >&2
    exit 1
    ;;
esac
