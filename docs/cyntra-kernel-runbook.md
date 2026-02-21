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

- Epics `1000`-`1700` are blocked parents; stories are executable children.
- Dependency ordering is in `.beads/deps.jsonl`.
- Initial ready issue is `1001`.

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
