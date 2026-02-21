# Cyntra Kernel Runbook (for `reverend`)

This repository is pre-wired for Cyntra with:
- Backlog graph: `.beads/issues.jsonl`, `.beads/deps.jsonl`
- Runtime config: `.cyntra/config.yaml`
- Repeatable wrappers: `scripts/cyntra/*.sh`

## 1. Why this setup

Ghidra is large. Cyntra workcells are git worktrees (not full `.git` clones), but each workcell still checks out files and can consume substantial disk.

Defaults in this repo intentionally reduce footprint:
- `max_concurrent_workcells: 3`
- speculation disabled
- preflight disk guard + branch/context checks before dispatch

## 2. Bootstrap once

```bash
scripts/cyntra/bootstrap.sh
```

This creates runtime dirs and ensures a local `main` branch exists (required by Cyntra workcell creation).

## 3. Preflight before dispatch

```bash
scripts/cyntra/preflight.sh
```

Preflight validates:
- disk headroom (`CYNTRA_MIN_FREE_GB`, default `35`)
- active workcell count limit (`CYNTRA_MAX_ACTIVE_WORKCELLS`, defaults to configured `max_concurrent_workcells`)
- `.beads` integrity
- `context_files` exist and are committed on `main`
- kernel status command succeeds via `uv tool run`

If you need to bypass the `main`-commit requirement temporarily:

```bash
CYNTRA_STRICT_CONTEXT_MAIN=0 scripts/cyntra/preflight.sh
```

## 4. Run the kernel

```bash
# single cycle (recommended while ramping up)
scripts/cyntra/run-once.sh

# continuous loop
scripts/cyntra/run-watch.sh
```

Pass through extra flags, for example:

```bash
scripts/cyntra/run-once.sh --dry-run
scripts/cyntra/run-once.sh --issue 1001
```

Direct passthrough command:

```bash
scripts/cyntra/cyntra.sh status
scripts/cyntra/cyntra.sh workcells
scripts/cyntra/cyntra.sh history
```

When running `scripts/cyntra/cyntra.sh run ...`, merge guards are enabled by default:
- recursive `[MERGE CONFLICT]` shadow beads are retired from `.beads/issues.jsonl`
- `--issue` values that point at a merge-conflict bead are remapped to the canonical issue id

Disable this only for debugging:

```bash
CYNTRA_MERGE_GUARDS=0 scripts/cyntra/cyntra.sh run --once --issue <id>
```

## 5. Cleanup and disk management

```bash
# remove workcells older than 2 days, prune old archives, print footprint
scripts/cyntra/cleanup.sh 2

# show current footprint without cleanup
scripts/cyntra/disk-report.sh
```

Use `CYNTRA_ARCHIVE_RETENTION_DAYS` to tune archive pruning.

## 6. Backlog notes

- `.beads/issues.jsonl` is the source of truth for backlog statuses.
- Canonical statuses for epic/story backlog items are `open`, `done`, and `blocked`.
- Snapshot as of `2026-02-21`: epics `1000`-`1700` are `done`; remediation epic `1800` is `blocked`; remediation stories `1802`-`1809` are `open` (`1801` is `done`).
- Dependency ordering is in `.beads/deps.jsonl`.

Sync `docs/backlog-jira-linear.csv` status values from bead truth:

```bash
python3 - <<'PY'
import csv
import json
import subprocess
from pathlib import Path

issues_path = Path(".beads/issues.jsonl")
if issues_path.exists():
    lines = issues_path.read_text(encoding="utf-8").splitlines()
else:
    lines = subprocess.check_output(
        ["git", "show", "HEAD:.beads/issues.jsonl"],
        text=True,
    ).splitlines()

status_by_id = {}
for line in lines:
    if not line.strip():
        continue
    issue = json.loads(line)
    status_by_id[str(issue["id"])] = str(issue.get("status", "")).lower()

csv_path = Path("docs/backlog-jira-linear.csv")
rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
for row in rows:
    status = status_by_id.get(row["id"])
    if status:
        row["status"] = status

with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"synced {len(rows)} backlog rows from bead status")
PY
```

## 7. Deterministic merge-failure recovery

When merge-to-`main` fails and Cyntra emits `[MERGE CONFLICT]` beads:

1. Retire stale merge-conflict shadows and make sure no recursive chain is schedulable:

```bash
scripts/cyntra/cyntra.sh repair-merge-conflicts
python3 - <<'PY'
import json, re
from pathlib import Path
issues = [json.loads(l) for l in Path(".beads/issues.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
by = {str(i.get("id")): i for i in issues}
orig_re = re.compile(r"-\s*Original issue:\s*#(\d+)")
def is_mc(i):
    t = str(i.get("title") or "")
    d = str(i.get("description") or "")
    tags = i.get("tags") or []
    return t.startswith("[MERGE CONFLICT]") or "MERGE_CONFLICT_AUTOGEN" in d or "merge-conflict" in tags
def orig(i):
    m = orig_re.search(str(i.get("description") or ""))
    return m.group(1) if m else None
bad = []
for i in issues:
    if not is_mc(i) or str(i.get("status") or "").lower() not in {"open", "ready", "in_progress"}:
        continue
    seen = set()
    cur = str(i.get("id"))
    depth = 0
    while True:
        node = by.get(cur)
        if not node or not is_mc(node):
            break
        if cur in seen:
            bad.append(str(i.get("id")))
            break
        seen.add(cur)
        nxt = orig(node)
        if not nxt:
            break
        depth += 1
        cur = nxt
    if depth > 1:
        bad.append(str(i.get("id")))
if bad:
    raise SystemExit(f"recursive schedulable merge conflicts remain: {sorted(set(bad))}")
print("merge-conflict schedulability check OK")
PY
```

2. Re-run by issue id. `scripts/cyntra/cyntra.sh run ...` canonicalizes `--issue` before cleanup, so merge-conflict ids are remapped safely:

```bash
scripts/cyntra/cyntra.sh run --once --issue <merge-conflict-or-canonical-id>
```

3. If merge still fails, run a deterministic patch-apply + merge cycle from the recorded workcell branch:

```bash
issue_id=<canonical-issue-id>
workcell_branch=wc/<issue-id>/<timestamp>
patch_file=.cyntra/state/merge-recovery-${issue_id}.patch

git switch main
mkdir -p .cyntra/state
git format-patch --stdout "main..${workcell_branch}" > "${patch_file}"
git apply --check "${patch_file}"
git apply "${patch_file}"
git add -A
git commit -m "Apply workcell patch for issue ${issue_id}"
git merge --no-ff --no-edit "${workcell_branch}"
bash scripts/cyntra/gates.sh --mode=all
```

Reference regression: `scripts/tests/test_cyntra_merge_path.py`.
