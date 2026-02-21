# Quality Gate Evidence (Issue 1704)

**Date:** 2026-02-21 (UTC)  
**Branch:** `wc/1704/20260221T014410Z`  
**Workcell:** `wc-1704-20260221T014410Z`

## Commands

```bash
bash scripts/cyntra/gates.sh --mode=all
bash scripts/cyntra/gates.sh --mode=context
bash scripts/cyntra/gates.sh --mode=diff
```

## Results

| Gate | Result | Evidence summary |
|---|---|---|
| `test` | PASS | Context check passed (`2` files); Python suites passed (`68` + `15` tests); Java threshold-contract gate passed; eval regression passed (`5/5`). |
| `typecheck` | PASS | Context check passed (`2` files); Python suites passed (`68` + `15` tests). |
| `lint` | PASS | Diff sanity check passed; Java threshold-contract gate passed. |
| `max-diff-size` | PASS | Manifest thresholds: `max_files=200`, `max_lines=4000`; measured `diff_files=4`, `diff_lines=155`. |
| `secret-detection` | PASS | Diff/untracked scan completed with `matched_patterns=0` on `155` scanned lines (`8620` bytes). |

## Diff-Check Commands

Deterministic local checks used for diff-check gates:

```bash
python3 - <<'PY'
# max-diff-size checker
# - reads manifest thresholds (max_files/max_lines)
# - counts tracked diff changes via `git diff --numstat`
# - counts untracked text files and line totals
# - fails if totals exceed manifest limits
PY

python3 - <<'PY'
# secret-detection checker
# - scans added tracked diff lines + untracked text
# - evaluates high-risk secret patterns (keys/tokens/private keys)
# - fails if any pattern matches
PY
```
