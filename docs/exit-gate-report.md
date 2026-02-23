# E21 Exit-Gate Report — SOTA Assistant Inside Ghidra

**Date:** 2026-02-23
**Issue:** 3208 (`E21-S8`)
**Epic:** E21 (`3201-3208`)
**Branch:** `wc/3208/20260223T074635Z`
**Workcell:** `wc-3208-20260223T074635Z`

---

## 1. Executive Summary

This report is the GA-readiness gate packet for the "SOTA assistant inside Ghidra" operational claim. It consolidates compile health, quality-gate status, benchmark evidence, and risk disposition with owner-level signoff state.

**Result:** operational criteria are met with passing compile/gate/benchmark checks.
**Release posture:** technical **GO** for operational readiness; production governance remains **NO-GO** until pending signoffs/conditions in Section 6 are closed.

---

## 2. Operational Criteria Status

Source criteria: `docs/audit-remediation-sota-operational-roadmap.md` ("SOTA Assistant Inside Ghidra" operational criteria).

| Criterion | Status | Evidence |
|---|---|---|
| Query/ranking quality and latency are benchmark-gated | **PASS** | `eval/config/query_slo_thresholds.json`, `.cyntra/artifacts/gates/eval/query-slo-report.json`, `.cyntra/artifacts/gates/eval/operational-claim-delta.json` |
| Benchmark slices include `real_target` and operator workflow (`spec_review`) metrics | **PASS** | `.cyntra/artifacts/gates/eval/smoke-metrics.json` (`benchmark_slices`), `.cyntra/artifacts/gates/eval/operational-claim-regression.json` |
| Cockpit query -> proposal -> apply/rollback loop is operational | **PASS** | `docs/operator-reviewer-runbook.md` (Sections 2, 3, and 6), `./gradlew --no-daemon :Reverend:test --tests "ghidra.reverend.cockpit.*"` (invoked by gate suite) |
| Query/similarity paths are index-backed and not full-program decompile scans | **PASS** | `docs/audit-remediation-sota-operational-roadmap.md` (E21-3201 profiling artifacts) |
| Local clean-environment workflow is reproducible | **PASS** | `docs/operator-reviewer-runbook.md` (Section 6), `scripts/cyntra/preflight.sh` |
| Baseline-vs-current operational claim deltas/manifests are published | **PASS** | `.cyntra/artifacts/gates/eval/operational-claim-delta.json`, `.cyntra/artifacts/gates/eval/operational-claim-manifest.json` |

---

## 3. Compile and Gate Evidence

### 3.1 Reproducible Commands

```bash
# Full blocking gate suite (includes compile/test/eval/roadmap/security-evidence checks)
bash scripts/cyntra/gates.sh --mode=all

# Context/typecheck gate
bash scripts/cyntra/gates.sh --mode=context

# Diff/lint gate
bash scripts/cyntra/gates.sh --mode=diff
```

### 3.2 Gate Register

| Gate | Command / Type | Status | Evidence Artifact |
|---|---|---|---|
| `test` | `bash scripts/cyntra/gates.sh --mode=all` | **PASS** | `.cyntra/artifacts/gates/blocking-gate-summary.json`, `.cyntra/artifacts/gates/eval/*` |
| `typecheck` | `bash scripts/cyntra/gates.sh --mode=context` | **PASS** | terminal gate output (`context OK`, Python suites pass) |
| `lint` | `bash scripts/cyntra/gates.sh --mode=diff` | **PASS** | terminal gate output (`diff sanity OK`, Java threshold gate pass) |
| `max-diff-size` | diff-check (`max_files=200`, `max_lines=4000`) | **PASS** | deterministic check command in Section 7 |
| `secret-detection` | diff-check (scan added/untracked lines) | **PASS** | deterministic check command in Section 7 |

### 3.3 Compile Coverage Provenance

Current workcell (`3208`) compile coverage disposition is written by `bash scripts/cyntra/gates.sh --mode=all` to:

- `.cyntra/artifacts/gates/blocking-gate-summary.json`

For this doc-only diff, module compile gates are expected to be `skipped (no scope changes)` and enforced through blocking skip-budget accounting in that summary artifact.

Last full compile evidence set (for required module/build commands) remains linked and reproducible in:

- `docs/evidence/rc-functional-validation/01-generic-compile.txt`
- `docs/evidence/rc-functional-validation/06-cyntra-gates-all.txt`
- `docs/evidence/rc-functional-validation/10-build-ghidra.txt`

---

## 4. Benchmark Evidence and Lift

### 4.1 Operational-Claim Gate (E21-S6 contract)

The operational-claim gate compares smoke metrics to `eval/snapshots/operational_claim_baseline.json` and blocks on threshold breaches:

- Source metrics: `.cyntra/artifacts/gates/eval/smoke-metrics.json`
- Regression result: `.cyntra/artifacts/gates/eval/operational-claim-regression.json`
- Baseline-vs-current delta: `.cyntra/artifacts/gates/eval/operational-claim-delta.json`
- Reproducibility manifest: `.cyntra/artifacts/gates/eval/operational-claim-manifest.json`

Evaluated metric areas include:
- `real_target` (ranking quality + latency SLO)
- `spec_review` (operator workflow completion and packet hash matching)

### 4.2 Benchmark Lift vs Stock Baseline

From non-toy soak output (`eval/run_soak.sh`; representative artifact: `docs/evidence/rc-functional-validation/09-soak-report.json`):

| Metric | Stock | Current | Lift |
|---|---:|---:|---:|
| Entrypoint recall | `0.666667` | `1.000000` | `+0.333333` |
| Hotspot recall | `0.800000` | `1.000000` | `+0.200000` |
| Macro F1 | `0.848677` | `0.969697` | `+0.121020` |
| Unknown precision | `0.750000` | `1.000000` | `+0.250000` |

Historical MVP benchmark lift remains positive and stable as well (`docs/soak-test-report-1701.md`: Recall@10 delta vs stock `+1.000`, 6/6 pass).

---

## 5. Artifact Index (Required Links)

- Operational roadmap + criteria: `docs/audit-remediation-sota-operational-roadmap.md`
- Final decision record: `docs/go-no-go-decision.md`
- This gate packet: `docs/exit-gate-report.md`
- Operator workflow/runbook: `docs/operator-reviewer-runbook.md`
- Security signoff basis: `docs/security/security-signoff-checklist.md`
- Abuse scenario evidence: `docs/security/abuse-scenario-suite.md`, `docs/security/evidence/abuse-scenario-suite-1806/README.md`
- Eval harness spec: `docs/research/evaluation-harness.md`
- Operational baseline: `eval/snapshots/operational_claim_baseline.json`
- Current gate artifacts: `.cyntra/artifacts/gates/eval/`

---

## 6. Risk Register Disposition

| Risk Group | Owner | Disposition | Signoff State |
|---|---|---|---|
| Medium residual security threats (`T1`, `T3`, `T5`, `T9`, `T10`) | Security review owner | Accepted with compensating controls; tracked as implementation-phase conditions | **Signed (conditional)** in `docs/security/security-signoff-checklist.md` (Issue 1702 record, 2026-02-21) |
| Remaining low residual STRIDE threats (`T2`, `T4`, `T6`, `T7`, `T8`, `T11`, `T12`, `T13`) | Security review owner | Accepted | **Signed (conditional)** in `docs/security/security-signoff-checklist.md` |
| Production governance signoff risk (architecture/legal/CISO approvals pending) | Release owner (`Issue 3208`) | Blocking for production GA promotion | **Open** (tracked in `docs/go-no-go-decision.md`) |

Open production conditions inherited from security signoff Section 10 (`CapabilityGuard`, hash-chain implementation verification, egress allow-list, keychain integration, process sandboxing, plugin signing, periodic benchmark governance, penetration test closure) remain mandatory before full production promotion.

---

## 7. Deterministic Diff-Check Commands

```bash
# max-diff-size
python3 - <<'PY'
import json, subprocess
from pathlib import Path
manifest = json.loads(Path("manifest.json").read_text(encoding="utf-8"))
max_files = int(manifest["quality_gates"]["max-diff-size"]["max_files"])
max_lines = int(manifest["quality_gates"]["max-diff-size"]["max_lines"])
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

# secret-detection
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

---

## 8. Recommendation

Operational criteria are satisfied with passing compile/gate/benchmark checks and reproducible evidence paths. Recommend progressing per `docs/go-no-go-decision.md` decision boundaries:

1. **GO** for technical operational readiness.
2. **NO-GO** for unrestricted production GA promotion until pending governance signoffs and security implementation conditions are explicitly closed.
