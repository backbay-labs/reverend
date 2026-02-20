# Operator and Reviewer Runbook — RC1

**Version:** 0.1.0-rc1
**Date:** 2026-02-20
**Audience:** Operators (deploy/maintain), analysts (import/annotate), reviewers (approve/reject proposals)

---

## 1. Setup and Prerequisites

### 1.1 System Requirements

| Component | Requirement |
|---|---|
| JDK | 21 (64-bit) |
| Gradle | 8.5+ (or use bundled `./gradlew`) |
| Python | 3.9–3.14 with pip |
| C/C++ compiler | GCC or Clang + make (native builds) |
| Disk | ≥ 35 GB free (configurable via `CYNTRA_MIN_FREE_GB`) |
| OS | Linux (x86_64), macOS (arm64/x86_64) |

### 1.2 Build from Source

```bash
# 1. Fetch non-Maven dependencies (first time only)
gradle -I gradle/support/fetchDependencies.gradle

# 2. Prepare development environment
gradle prepdev

# 3. Build native components
gradle buildNatives

# 4. Build full distribution
gradle buildGhidra
# Output: build/dist/ghidra_<version>_<date>.zip
```

### 1.3 Install from Distribution

```bash
# Unpack the RC1 distribution
unzip build/dist/ghidra_*.zip -d /opt/ghidra

# Verify JDK
/opt/ghidra/ghidra_*/support/launch.sh --version
```

### 1.4 First-Run Configuration

1. Launch Ghidra: `./ghidraRun` (GUI) or `./support/analyzeHeadless` (headless).
2. Create or connect to a shared project (File → New Project → Shared Project).
3. Configure the review server endpoint in `Edit → Tool Options → Collaboration`:
   - **Review server URL** — the REST endpoint for the collaboration server.
   - **API key** — analyst authentication token.
4. Configure agent policy mode in `Edit → Tool Options → Agent Security`:
   - `offline` (default) — no external API calls; local models only.
   - `allowlist` — only pre-approved endpoints.
   - `cloud` — external model APIs enabled (requires explicit opt-in).

### 1.5 Cyntra Orchestration (Operators)

For automated workcell dispatch (see also `docs/cyntra-kernel-runbook.md`):

```bash
# Bootstrap runtime dirs (once)
scripts/cyntra/bootstrap.sh

# Validate environment before dispatch
scripts/cyntra/preflight.sh

# Single dispatch cycle
scripts/cyntra/run-once.sh

# Continuous dispatch
scripts/cyntra/run-watch.sh

# Check status
scripts/cyntra/cyntra.sh status
scripts/cyntra/cyntra.sh workcells
```

---

## 2. Review Flow

### 2.1 Roles

| Role | Permissions | Typical Actions |
|---|---|---|
| **Analyst** | Import, annotate, submit proposals | Import binary, rename functions, apply types, submit changeset |
| **Reviewer** | View proposals, approve/reject, rollback | Inspect diffs, check evidence, approve or request changes |
| **Operator** | Deploy, configure, monitor | Manage infrastructure, run quality gates, handle incidents |
| **ML Agent** | Read-only analysis, propose changes | Generate rename/type proposals with confidence scores |

### 2.2 Analyst Workflow

1. **Import binary**: File → Import File → select binary → run auto-analysis.
2. **Annotate**: Rename functions, apply struct types, add comments. All changes are captured as `AnnotationDelta` records via the `ChangesetCapturingListener`.
3. **Create changeset**: Toolbar → New Changeset → add title and description.
4. **Submit for review**: Toolbar → Submit for Review. The changeset moves to `OPEN` status on the review server.
5. **Address feedback**: If the reviewer requests changes, revise annotations and update the changeset.

### 2.3 Reviewer Workflow

1. **Open review queue**: Dockable panel → Review Queue. Shows all `OPEN` changesets assigned to you.
2. **Inspect changeset**: Click a changeset to see the summary table grouped by artifact type (symbols, data types, comments, etc.).
3. **Examine diffs**: For each delta, view:
   - **Listing diff** — split-pane base vs. proposed, with changed addresses highlighted.
   - **Decompiler diff** — side-by-side decompiled output with renamed variables and types highlighted.
   - **Type diff** — structural diff for modified data types.
4. **Check evidence**: Expand the evidence drawer for any delta to see xrefs, constants, callsite context, and confidence scores.
5. **Decide**:
   - **Approve** — changeset proceeds to merge.
   - **Request Changes** — changeset returns to analyst with comments.
   - **Reject** — changeset is closed.
6. **Bulk actions**: For ML-generated changesets, use confidence-tier filtering and "accept all above threshold" for batch approval.

### 2.4 Merge and Apply

On approval:
1. The changeset is applied to the canonical program via Ghidra's transaction system.
2. An apply receipt is generated linking every applied delta to its evidence references.
3. Attribution records are written (author, timestamp, confidence, provenance chain).
4. The changeset status moves to `MERGED`.

### 2.5 ML Agent Proposals

ML agents submit proposals through the headless pipeline:
- Proposals include confidence scores (0.0–1.0).
- **High confidence (> 0.95)**: auto-approved per project policy (post-hoc review available).
- **Medium confidence (0.7–0.95)**: routed to human review queue.
- **Low confidence (< 0.7)**: parked in "suggestions" queue for optional browsing.

---

## 3. Rollback Procedures

### 3.1 Single-Delta Rollback

1. Open the changeset in the Review Queue panel.
2. Select the applied delta to roll back.
3. Click **Rollback**. This creates a rollback receipt that references the original apply receipt's evidence link IDs.
4. The Ghidra transaction is reverted. Evidence links remain intact for audit.

### 3.2 Batch Rollback

1. Open the changeset summary.
2. Select **Rollback Entire Changeset**.
3. All applied deltas revert as a single Ghidra undo transaction.
4. A batch rollback receipt is generated.

### 3.3 Rollback Integrity Guarantees

- Evidence link rows are immutable — rollback changes proposal/apply state, not evidence identity.
- Rollback receipts reference the original apply receipt's `evidence_link_ids`.
- The receipt hash chain verifies integrity: `receipt_hash = H(payload || previous_hash)`.
- Rollback success gate target: 100 % for approved batch apply/undo tests.

### 3.4 Type PR Rollback

For type assertion rollbacks:
1. Navigate to the Type PR detail panel.
2. The reviewer can reject an already-applied Type PR.
3. The server-side operation is atomic: both the PR status and assertion lifecycle state revert within a single database transaction.
4. If the transaction fails, neither PR status nor assertion lifecycle changes.

---

## 4. Incident Handling

### 4.1 Severity Levels

| Severity | Definition | Response Time | Examples |
|---|---|---|---|
| **P0 — Critical** | Data corruption, security breach, complete service failure | Immediate | Receipt chain broken, unauthorized agent write to canonical state, corpus data loss |
| **P1 — High** | Major feature broken, significant data integrity risk | < 4 hours | Review server unreachable, merge produces incorrect results, rollback fails |
| **P2 — Medium** | Feature degraded, workaround available | < 24 hours | Search latency exceeds target, ML confidence miscalibrated, UI panel crash |
| **P3 — Low** | Minor issue, cosmetic, or enhancement | Next sprint | Dashboard rendering glitch, attribution display incomplete |

### 4.2 Incident Response Playbook

**Step 1 — Detect and classify**
- Monitor CI gate dashboard (`eval/scripts/mvp_gate_dashboard.py`) for exit-gate regressions.
- Check review server health endpoint.
- Review Ghidra application logs and receipt store integrity.

**Step 2 — Contain**
- For P0/P1: immediately halt automated dispatch:
  ```bash
  # Stop continuous dispatch
  # (kill run-watch.sh process or remove cron entry)

  # Check workcell status
  scripts/cyntra/cyntra.sh status
  scripts/cyntra/cyntra.sh workcells
  ```
- For agent-related incidents: switch policy mode to `offline` to cut external API access.
- For merge/apply incidents: suspend auto-approve threshold (set to 1.01, effectively disabling it).

**Step 3 — Diagnose**
- Verify receipt chain integrity:
  ```bash
  # Run quality gates to check for regressions
  bash scripts/cyntra/gates.sh --mode=all
  ```
- Check recent changeset history on the review server for anomalous patterns.
- Review attribution records for the affected address range.
- Check `logs/` directory for application-level errors.

**Step 4 — Remediate**
- **Receipt chain broken**: Rebuild chain from last known-good checkpoint. All mutations after the break must be re-verified.
- **Unauthorized write**: Roll back the affected changeset. Audit capability tokens. Rotate API keys.
- **Merge corruption**: Restore program from last known-good Ghidra Server version. Replay approved changesets.
- **Review server down**: Analysts can continue local work. Queue submittals. No changesets are lost (local state preserved).

**Step 5 — Post-incident**
- Write incident report: timeline, root cause, remediation, preventive measures.
- Update quality gates if the incident class was not covered.
- Add regression test covering the failure mode.

### 4.3 Escalation Path

1. **Operator** detects issue → classifies severity.
2. **P0/P1** → notify team lead immediately; halt automated systems.
3. **P2** → file issue in backlog; apply workaround.
4. **P3** → file issue in backlog; address in next sprint.

### 4.4 Disk and Resource Incidents

```bash
# Check disk usage
scripts/cyntra/disk-report.sh

# Clean up old workcells (retain last N days)
scripts/cyntra/cleanup.sh 2

# Tune archive retention
CYNTRA_ARCHIVE_RETENTION_DAYS=7 scripts/cyntra/cleanup.sh
```

If disk usage exceeds threshold:
1. Run cleanup with aggressive retention (`cleanup.sh 1`).
2. Prune old Ghidra Server versions if safe.
3. Move completed workcell archives to cold storage.

---

## 5. Quality Gates

Operators must run all quality gates before any release decision:

```bash
# Full gate suite
bash scripts/cyntra/gates.sh --mode=all

# Context/typecheck validation
bash scripts/cyntra/gates.sh --mode=context

# Diff/lint validation
bash scripts/cyntra/gates.sh --mode=diff
```

Gate descriptions:

| Gate | Type | What It Checks |
|---|---|---|
| `test` | Functional | Unit and integration test suite |
| `typecheck` | Static | Context-level type consistency |
| `lint` | Static | Code style and diff hygiene |
| `max-diff-size` | Diff check | Ensures changes stay within size limits |
| `secret-detection` | Diff check | No credentials or secrets in committed code |

---

## 6. Configuration Reference

### 6.1 Cyntra Configuration

File: `.cyntra/config.yaml`

| Key | Default | Description |
|---|---|---|
| `max_concurrent_workcells` | 3 | Maximum parallel workcells |
| `CYNTRA_MIN_FREE_GB` | 35 | Minimum free disk (GB) before dispatch |
| `CYNTRA_ARCHIVE_RETENTION_DAYS` | (unset) | Days to retain archived workcells |
| `CYNTRA_STRICT_CONTEXT_MAIN` | 1 | Require context files committed on main |

### 6.2 Agent Security Policy

Configured via Ghidra Tool Options → Agent Security:

| Mode | External API | Agent Write | Receipt Required |
|---|---|---|---|
| `offline` | Blocked | Proposal only | Yes |
| `allowlist` | Approved endpoints only | Proposal only | Yes |
| `cloud` | Open | Proposal only | Yes |

In all modes, agents cannot write directly to canonical program state. All mutations flow through the proposal → review → apply pipeline.

### 6.3 Auto-Approve Thresholds

| Setting | Default | Description |
|---|---|---|
| Min confidence for auto-approve | 0.95 | ML proposals above this are auto-merged if no conflicts |
| Min confidence for review queue | 0.70 | Below this, proposals go to suggestions only |
| Human-over-ML priority | Enabled | Human changes always win over ML in conflicts |

---

## 7. Monitoring Checklist

Daily operator checks:

- [ ] CI gate dashboard shows all gates green
- [ ] Review server health endpoint returns 200
- [ ] No P0/P1 issues in the last 24 hours
- [ ] Disk usage below 80 % on analysis hosts
- [ ] Receipt chain integrity verified
- [ ] Active workcell count within limits
- [ ] Nightly regression suite passed
