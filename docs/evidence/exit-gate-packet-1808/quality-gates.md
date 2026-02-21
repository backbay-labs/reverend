# Quality Gate Evidence (Issue 1808)

**Date:** 2026-02-21 (UTC)  
**Branch:** `wc/1808/20260221T013616Z`  
**Workcell:** `wc-1808-20260221T013616Z`

## Commands

```bash
bash scripts/cyntra/gates.sh --mode=all
bash scripts/cyntra/gates.sh --mode=context
bash scripts/cyntra/gates.sh --mode=diff
```

## Results

| Gate | Result | Evidence summary |
|---|---|---|
| `test` | PASS | Context check passed; Python suites passed (`68` + `15` tests); Java threshold-contract gate passed; eval regression passed (`5/5`). |
| `typecheck` | PASS | Context check passed; Python suites passed (`68` + `15` tests). |
| `lint` | PASS | Diff sanity check passed; Java threshold-contract gate passed. |
| `max-diff-size` | PASS | Manifest thresholds: `max_files=200`, `max_lines=4000`; measured `diff_files=5`, `diff_lines=129`. |
| `secret-detection` | PASS | Diff/untracked scan completed with `matched_patterns=0` on `129` scanned lines. |

## Diff-Check Commands

Deterministic local checks used for diff-check gates:

```bash
python3 - <<'PY'
# max-diff-size checker (manifest thresholds + tracked/untracked diff totals)
PY

python3 - <<'PY'
# secret-detection checker (added-line/untracked scan for high-risk secret patterns)
PY
```
