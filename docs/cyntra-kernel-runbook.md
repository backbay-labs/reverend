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
- pinned toolchain compatibility (`python3 >= 3.11`, `java` + `javac` on JDK 21)
- disk headroom (`CYNTRA_MIN_FREE_GB`, default `35`)
- active workcell count limit (`CYNTRA_MAX_ACTIVE_WORKCELLS`, defaults to configured `max_concurrent_workcells`)
- `.beads` integrity
- `context_files` exist and are committed on `main`
- kernel status command succeeds via `uv tool run`

If you need to bypass the `main`-commit requirement temporarily:

```bash
CYNTRA_STRICT_CONTEXT_MAIN=0 scripts/cyntra/preflight.sh
```

Deterministic local toolchain verification (same version policy as CI):

```bash
python3 --version | grep -E '^Python 3\.11\.'
java -version 2>&1 | head -n 1 | grep -E '"21(\.|")'
javac -version 2>&1 | grep -E '^javac 21(\.|$)'
bash scripts/cyntra/preflight.sh | tee /tmp/cyntra-preflight.log
grep -F '[preflight] python toolchain OK:' /tmp/cyntra-preflight.log
grep -F '[preflight] java toolchain OK:' /tmp/cyntra-preflight.log
grep -F '[preflight] preflight checks passed' /tmp/cyntra-preflight.log
```

Expected outcomes:
- every command exits with status `0`
- `preflight` prints both toolchain OK lines and ends with `preflight checks passed`

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

Gate context resolution in `scripts/cyntra/gates.sh` uses deterministic fallback order:
1. `manifest.json` issue context
2. `CYNTRA_GATE_ISSUE_ID` + `.beads/issues.jsonl`
3. current branch issue id (`wc/<id>/...` or `wc-<id>-...`)
4. repo-root fallback (only when strict mode is explicitly disabled)

`CYNTRA_GATE_CONTEXT_STRICT` now defaults to `1` (fail-closed).
Set `CYNTRA_GATE_CONTEXT_STRICT=0` only for intentional non-workcell debug runs.

For strict Java module gates, make sure dependency metadata has been fetched:

```bash
gradle -I gradle/support/fetchDependencies.gradle
```

Additional gate modes:

```bash
bash scripts/cyntra/gates.sh --mode=java
bash scripts/cyntra/gates.sh --mode=evidence
```

Failure taxonomy and completion-policy binding:
- Canonical runtime failure codes:
  - `runtime.prompt_stall_no_output`
- Canonical gate failure codes:
  - `gate.quality_gate_failed`
  - `gate.context_missing_on_main`
- Canonical policy failure codes:
  - `policy.completion_blocked`
- `scripts/cyntra/run-once.sh` completion fallback now routes using `failure_code` (not free-form class text).
- `CYNTRA_DETERMINISTIC_FAILURE_CODES` controls which canonical codes are eligible for deterministic fallback (legacy `CYNTRA_DETERMINISTIC_FAILURE_CLASSES` is still accepted as an alias).
- `scripts/cyntra/cyntra.sh` reads `CYNTRA_FAILURE_CODE` first (legacy `CYNTRA_FAILURE_CLASS` remains an alias).
- Fallback provenance (`.cyntra/state/fallback-routing.json`) now includes canonical `failure_code`.
- Completion integrity policy is fail-closed:
  - completion results with zero diff require explicit manifest `noop_justification` (`manifest.issue.noop_justification` or `manifest.noop_justification`)
  - missing explicit justification is classified as `policy.completion_blocked`
  - `run-once` exits non-zero and does not trigger fallback rerun for `policy.completion_blocked`
- Deterministic classification also annotates workcell artifacts with canonical `failure_code`:
  - `proof.json` top-level `failure_code`
  - `proof.json.metadata.failure_code`
  - `proof.json.verification.failure_code`
  - appended `telemetry.jsonl` entry with `event: "failure_code_classified"` and `failure_code`
- Completion policy gate summary telemetry:
  - workcell telemetry: `.workcells/<id>/telemetry.jsonl`
  - kernel telemetry: `.cyntra/logs/events.jsonl`
  - event: `completion_policy_gate_summary`
  - gate summary fields: `completion_classification`, `noop_reason`, `noop_reason_source`, `noop_justification_source`, `explicit_noop_justification_present`, `policy_result`

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
- Sync is full-row canonical: title/priority/risk/tags/acceptance/description are rewritten from `.beads` (not status-only patching).
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

Verification (full-row parity + roadmap closure):

```bash
scripts/cyntra/sync-backlog-csv.sh
scripts/cyntra/validate-roadmap-completion.sh
```

Execution evidence (`2026-02-21`):
- `scripts/cyntra/sync-backlog-csv.sh`
  - `[sync-backlog-csv] wrote 48 roadmap rows to docs/backlog-jira-linear.csv from .beads/issues.jsonl (...)`
- `scripts/cyntra/validate-roadmap-completion.sh`
  - `[validate-roadmap] OK`
  - `roadmap exportable issues: 48 total, 48 done`

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

## 8. R1 Remediation Closure Snapshot (2026-02-21)

- Backlog truth closure state: `.beads/issues.jsonl` records `1800` and all `epic:R1` stories (`1801-1809`) as `done`.
- Escalation closure evidence:
  - story `14`: commit `39f9d585ff`
  - story `15`: commit `a2b0f6a3a9` and merge `d12d4d1ae4`
  - story `16`: commit `714b440f7c` and merge `e8941eac4d`
- Workcell closure gate evidence is published at `docs/evidence/r1-remediation-closure-1800/quality-gates.md`.
- Deterministic verification command:

```bash
python3 - <<'PY'
import json
from pathlib import Path
issues = [json.loads(line) for line in Path(".beads/issues.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
remaining = []
for issue in issues:
    tags = [str(tag) for tag in issue.get("tags") or []]
    status = str(issue.get("status") or "").lower()
    if "epic:R1" in tags and status in {"open", "blocked", "escalated"}:
        remaining.append((issue.get("id"), status))
if remaining:
    raise SystemExit(f"R1 unresolved statuses: {remaining}")
print("R1 closure status OK: no open/blocked/escalated issues")
PY
```
