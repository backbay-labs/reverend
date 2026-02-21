# Quality Gate Evidence (Issue 1800)

**Date:** 2026-02-21 (UTC)  
**Branch:** `wc/1800/20260221T020242Z`  
**Workcell:** `wc-1800-20260221T020242Z`

## Commands

```bash
bash scripts/cyntra/gates.sh --mode=all
bash scripts/cyntra/gates.sh --mode=context
bash scripts/cyntra/gates.sh --mode=diff
python3 - <<'PY'
import subprocess, re
from pathlib import Path
cfg = Path(".cyntra/config.yaml").read_text(encoding="utf-8")
max_lines = int(re.search(r"^\s*max_diff_lines:\s*(\d+)", cfg, flags=re.M).group(1))
max_files = int(re.search(r"^\s*max_diff_files:\s*(\d+)", cfg, flags=re.M).group(1))
numstat = subprocess.check_output(["git", "diff", "--numstat", "--", "."], text=True)
tracked_files = tracked_lines = 0
for line in numstat.splitlines():
    add, delete, _ = line.split("\t", 2)
    tracked_files += 1
    tracked_lines += int(add) if add.isdigit() else 0
    tracked_lines += int(delete) if delete.isdigit() else 0
untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], text=True)
untracked_text_files = untracked_lines = 0
for rel in [p for p in untracked.splitlines() if p.strip()]:
    path = Path(rel)
    if not path.is_file():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        continue
    untracked_text_files += 1
    untracked_lines += len(text.splitlines())
diff_files = tracked_files + untracked_text_files
diff_lines = tracked_lines + untracked_lines
print(f"max_files={max_files} max_lines={max_lines}")
print(f"diff_files={diff_files} diff_lines={diff_lines}")
raise SystemExit(0 if diff_files <= max_files and diff_lines <= max_lines else 1)
PY

python3 - <<'PY'
import re, subprocess
from pathlib import Path
patterns = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?i)-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
]
added = []
diff = subprocess.check_output(["git", "diff", "--unified=0", "--", "."], text=True, errors="ignore")
for line in diff.splitlines():
    if line.startswith("+++") or line.startswith("@@"):
        continue
    if line.startswith("+"):
        added.append(line[1:])
untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], text=True)
for rel in [p for p in untracked.splitlines() if p.strip()]:
    path = Path(rel)
    if not path.is_file():
        continue
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            added.append(line)
    except Exception:
        continue
matches = [line for line in added if any(p.search(line) for p in patterns)]
print(f"scanned_lines={len(added)} matched_patterns={len(matches)}")
raise SystemExit(0 if not matches else 1)
PY
```

## Results

| Gate | Result | Evidence summary |
|---|---|---|
| `test` | PASS | Context check passed (`4` files; `1` kernel-owned skipped); Python suites passed (`68` + `17` tests); Java threshold-contract gate passed; eval regression passed (`5/5`). |
| `typecheck` | PASS | Context check passed (`4` files; `1` kernel-owned skipped); Python suites passed (`68` + `17` tests). |
| `lint` | PASS | Diff sanity check passed; Java threshold-contract gate passed. |
| `max-diff-size` | PASS | Manifest thresholds: `max_files=200`, `max_lines=4000`; measured `diff_files=6`, `diff_lines=167`. |
| `secret-detection` | PASS | Diff/untracked scan completed with `matched_patterns=0` on `149` scanned lines. |

## Reopened Escalation Story Closure Mapping

| Story | Result | Commit evidence | Key artifact files |
|---|---|---|---|
| `14` | done | `39f9d585ff` | `scripts/cyntra/preflight.sh`, `.github/workflows/eval.yaml`, `docs/research/python-integration-ops-matrix.md`, `docs/cyntra-kernel-runbook.md` |
| `15` | done | `a2b0f6a3a9`, `d12d4d1ae4` | `scripts/cyntra/sync-backlog-csv.sh`, `docs/backlog-jira-linear.csv`, `docs/cyntra-kernel-runbook.md` |
| `16` | done | `714b440f7c`, `e8941eac4d` | `scripts/cyntra/cyntra.sh`, `scripts/tests/test_cyntra_merge_path.py`, `docs/cyntra-kernel-runbook.md` |
