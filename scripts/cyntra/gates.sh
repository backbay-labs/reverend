#!/usr/bin/env bash
set -euo pipefail

mode="all"
artifact_root="${CYNTRA_GATE_ARTIFACT_DIR:-.cyntra/artifacts/gates}"
for arg in "$@"; do
  case "$arg" in
    --mode=*)
      mode="${arg#*=}"
      ;;
  esac
done

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

run_python_regression() {
  echo "[gates] running python regression: scripts/ml/tests"
  python3 -m unittest discover -s scripts/ml/tests -p 'test_*.py'
  echo "[gates] running python regression: scripts/tests"
  python3 -m unittest discover -s scripts/tests -p 'test_*.py'
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
  if [[ ! -d "dependencies/flatRepo" && ! -f "ghidra.repos.config" ]]; then
    echo "[gates] ERROR: missing build dependency configuration (need dependencies/flatRepo or ghidra.repos.config)" >&2
    echo "[gates] hint: run 'gradle -I gradle/support/fetchDependencies.gradle' before strict Java module gates" >&2
    exit 1
  fi
}

run_security_compile_regression() {
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

case "$mode" in
  all)
    check_manifest_context
    check_diff_sanity
    run_python_regression
    run_java_regression
    run_security_compile_regression
    run_eval_regression
    run_security_evidence_integrity
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
    ;;
  evidence)
    run_security_evidence_integrity
    ;;
  *)
    echo "[gates] ERROR: unknown mode '$mode' (expected all|context|diff|java|evidence)" >&2
    exit 1
    ;;
esac
