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
- `docs/backlog-jira-linear.csv` is the deterministic export of canonical roadmap entries only:
  - include entries tagged `roadmap12w` with `type:epic` or `type:story`
  - exclude synthetic operational beads tagged `merge-conflict` or `escalation` (for example `[MERGE CONFLICT]`/`[ESCALATION]` records)
- Canonical statuses for exported epic/story backlog entries are `open`, `done`, and `blocked`.
- Escalation/merge-conflict beads track operational incidents and are not exported to Jira/Linear CSV.
- Dependency ordering is in `.beads/deps.jsonl`.

Sync (or rebuild) `docs/backlog-jira-linear.csv` from bead truth:

```bash
scripts/cyntra/sync-backlog-csv.sh
```

Notes:
- The sync command reads `.beads/issues.jsonl` from the worktree when present.
- In sparse workcells where `.beads` is not checked out, it falls back to `git show HEAD:.beads/issues.jsonl`.

Verification (status parity for exported rows):

```bash
python3 - <<'PY'
import csv
import json
import subprocess
import sys
from pathlib import Path

def issue_type(tags):
    for tag in tags:
        if tag.startswith("type:"):
            return tag.split(":", 1)[1].lower()
    return ""

issues = [
    json.loads(line)
    for line in subprocess.check_output(
        ["git", "show", "HEAD:.beads/issues.jsonl"],
        text=True,
    ).splitlines()
    if line.strip()
]

bead_status = {}
for issue in issues:
    tags = [str(tag) for tag in issue.get("tags") or []]
    title = str(issue.get("title") or "")
    if "roadmap12w" not in tags:
        continue
    if issue_type(tags) not in {"epic", "story"}:
        continue
    if "merge-conflict" in tags or "escalation" in tags:
        continue
    if title.startswith("[MERGE CONFLICT]") or title.startswith("[ESCALATION]"):
        continue
    bead_status[str(issue["id"])] = str(issue.get("status") or "").lower()

rows = list(csv.DictReader(Path("docs/backlog-jira-linear.csv").open(newline="", encoding="utf-8")))
csv_status = {row["id"]: row["status"].lower() for row in rows}

missing = sorted(set(bead_status) - set(csv_status), key=lambda value: int(value))
extra = sorted(set(csv_status) - set(bead_status), key=lambda value: int(value))
mismatch = sorted(
    [issue_id for issue_id, status in bead_status.items() if csv_status.get(issue_id) != status],
    key=lambda value: int(value),
)

if missing or extra or mismatch:
    print("status sync mismatch detected", file=sys.stderr)
    print(f"missing={missing}", file=sys.stderr)
    print(f"extra={extra}", file=sys.stderr)
    print(
        f"mismatch={[(issue_id, csv_status.get(issue_id), bead_status[issue_id]) for issue_id in mismatch]}",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"status sync OK: {len(rows)} csv rows match {len(bead_status)} canonical roadmap beads")
PY
```

Execution evidence (`2026-02-21`):
- `scripts/cyntra/sync-backlog-csv.sh`
  - `[sync-backlog-csv] wrote 48 roadmap rows to docs/backlog-jira-linear.csv from HEAD:.beads/issues.jsonl (...)`
  - first reconciliation run added the missing remediation rows (`added=10`); repeat runs are idempotent (`added=0`)
- verification command above
  - `status sync OK: 48 csv rows match 48 canonical roadmap beads`

## 7. Deterministic merge-failure recovery

When merge-to-`main` fails and Cyntra emits `[MERGE CONFLICT]` beads:

1. Retire recursive shadow beads and dedupe conflict targets:

```bash
scripts/cyntra/cyntra.sh repair-merge-conflicts
```

2. Re-run using the canonical issue id. If you only have a merge-conflict bead id, pass it directly and the wrapper remaps it:

```bash
scripts/cyntra/cyntra.sh run --once --issue <merge-conflict-or-canonical-id>
```

3. If merge still fails, perform the merge manually from the recorded workcell branch and re-run gates:

```bash
git switch main
git merge --no-ff wc/<issue-id>/<timestamp>
bash scripts/cyntra/gates.sh --mode=all
```
