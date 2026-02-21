# 12-Week Execution Board: Ghidra "Alien-Tech" MVP

As-of: 2026-02-21
Scope: Deliver a production-credible MVP that turns binary analysis into an evidence-backed, reviewable, and continuously improving workflow.

## 1. Target Outcome (Week 12)

Ship one vertical slice:
1. Analyst imports a binary.
2. System generates a triage map + ranked hotspots.
3. System proposes rename/type/comment changes with receipts.
4. Reviewer accepts/rejects proposals in a PR-like flow.
5. Approved changes apply via reversible transactions.
6. Accepted artifacts can sync to a corpus knowledge base.

## 2. Owner Lanes

- `Backend`: data plane schema/services, receipts, indexing, sync.
- `Plugin/UI`: Ghidra panels, review UX, workflow orchestration.
- `ML`: ranking, similarity retrieval, triage heuristics/models.
- `Security`: capability guard, policy modes, sandbox and egress controls.
- `Eval/DevOps`: datasets, CI gates, metric dashboards, regression harness.

## 3. MVP Exit Gates (Must Pass)

1. Receipt completeness: `100%` for all auto-applied mutations.
2. Rollback success: `100%` for approved batch apply/undo tests.
3. Search latency: `p95 < 300ms` on local 100K-function index.
4. Search quality: Recall@10 beats stock baseline by `>=10%` on chosen eval slice.
5. Triage quality: entrypoint/hotspot recall `>=85%` on curated internal set.
6. Security: no direct agent write path to canonical program state.
7. CI: per-commit smoke + nightly regression green for 7 consecutive days.

## 4. Epics, Dependencies, and Definition of Done

| Epic | Primary Lane | Weeks | Depends On | Done When |
|---|---|---|---|---|
| `E1` Evaluation Foundation | Eval/DevOps | 1-3 | None | Baseline metrics captured and published in CI artifacts. |
| `E2` Receipts + Proposal Workflow | Backend + Plugin/UI | 2-6 | E1 | All rename/comment/type proposals stored as receipts; review/apply/rollback works. |
| `E3` Capability Guard + Policy Modes | Security + Backend | 2-7 | E1 | Token-scoped permissions enforced; offline/allowlist/cloud policy modes implemented. |
| `E4` Local Semantic Search | Backend + ML + Plugin/UI | 4-8 | E1, E2 | Function similarity + intent query panel operational with measured latency/recall. |
| `E5` Triage Crew v1 (Deterministic) | ML + Plugin/UI | 7-10 | E2, E3, E4 | Mission output includes map, hotspots, unknowns, and evidence references. |
| `E6` Type PR Lifecycle v1 | Backend + Plugin/UI + ML | 8-11 | E2, E4 | Type assertions flow through proposed->reviewed->accepted->propagated states. |
| `E7` Corpus Sync Pilot | Backend + Security | 10-12 | E2, E3, E4 | Approved artifacts sync to shared store with provenance and access controls. |
| `E8` Hardening + Release Candidate | All lanes | 11-12 | E1-E7 | Exit gates pass; release notes and operator runbook complete. |

## 5. Week-by-Week Board

| Week | Backend | Plugin/UI | ML | Security | Eval/DevOps | Milestone Gate |
|---|---|---|---|---|---|---|
| 1 | Bootstrap data-plane repo module and schema migrations | Create MVP workflow wireframes | Define retrieval feature set and ranking baseline | Threat model to control mapping | Pin datasets + baseline scripts | `M1`: evaluation harness skeleton in CI |
| 2 | Implement receipt schema + append API | Build proposal inbox panel (read-only) | Baseline similarity run (stock) | Implement capability token spec | Run stock metric baselines | `M2`: baseline report v1 |
| 3 | Add transaction-linked receipt writer | Add delta diff renderer (before/after) | Build triage feature extractor prototype | Add policy mode config (`offline`, `allowlist`, `cloud`) | Add per-commit smoke metrics + MVP gate dashboard/alerts from artifacts | `M3`: receipts written for manual edits |
| 4 | Proposal state machine (`proposed`, `approved`, `rejected`) | Review actions (approve/reject/bulk) | Local embedding pipeline v1 | Guard MCP/tool calls by capability | Nightly regression job enabled | `M4`: review/apply path works in test project |
| 5 | Rollback chain + idempotent apply API | Rollback UX + change history view | Similarity index + top-k retrieval API | Endpoint allowlist enforcement | Add latency/recall dashboards | `M5`: rollback integration test green |
| 6 | Evidence-link storage (`xrefs`, strings, callsites) | Evidence drawer in review UI | Re-ranker using evidence weights | Permission audit logging | Add receipt completeness gate | `M6`: 100% proposal receipts in CI tests |
| 7 | Local search query service hardening | Semantic search panel (`intent` + `similar`) | Triage Crew rule set v1 | Sandbox boundary tests (plugin/agent) | Create curated triage eval set | `M7`: semantic search usable in UI |
| 8 | Performance tuning (index build/query) | Add triage mission run page | Triage scoring calibration | Security regression suite v1 | Evaluate recall/latency deltas | `M8`: search quality + latency interim pass |
| 9 | Type assertion persistence + propagation hooks | Type PR list/detail/review panel | Type suggestion generator v1 | High-impact mutation approval policy | Add type metrics to CI | `M9`: type PR end-to-end demo |
| 10 | Corpus sync worker (approved-only artifacts) | Sync status and provenance UI | Cross-binary reuse heuristics v1 | Access control + provenance checks for sync | Corpus pilot benchmark run | `M10`: corpus sync pilot operational |
| 11 | Fix bottlenecks from pilot; finalize APIs | UX polish + reviewer shortcuts | Triage/type quality tuning | Pen-test style abuse scenarios | Full regression + soak run | `M11`: release candidate cut |
| 12 | Freeze schema/API; release packaging | Operator and reviewer runbook UI links | Final model/config lock | Security sign-off checklist | Exit-gate validation report | `M12`: MVP release decision |

## 6. Week 12 Release Deliverables (Published)

- [x] Versioned RC changelog: `docs/CHANGELOG-rc1.md` (`0.1.0-rc1`)
- [x] RC packaging instructions + artifact/checksum command: `docs/CHANGELOG-rc1.md`
- [x] Operator and reviewer runbook: `docs/operator-reviewer-runbook.md`
- [x] Explicit known limitations catalog: `docs/known-limitations.md`
- [x] MVP exit-gate report: `docs/exit-gate-report.md`
- [x] Final go/no-go decision artifact: `docs/go-no-go-decision.md`

## 7. Backlog Items (Ticket Seeds)

1. `BE-101`: Receipt append-only store with hash-chain verification.
2. `BE-118`: Proposal apply/rollback transaction adapter for Ghidra.
3. `UI-201`: Review inbox with artifact-type filters and bulk actions.
4. `UI-219`: Evidence panel showing exact supporting features per proposal.
5. `ML-301`: Similarity baseline adapter (BSim/FID features) with eval hooks.
6. `ML-327`: Triage Crew v1 mission graph (entrypoints, config, crypto, network).
7. `SEC-401`: Capability guard middleware for all tool invocations.
8. `SEC-417`: Policy mode enforcement and endpoint allowlist controls.
9. `EVAL-501`: Dataset lock + deterministic baseline pipeline.
10. `EVAL-529`: CI gates for receipt completeness, rollback, recall, latency.
11. `EVAL-534`: Artifact-driven MVP gate dashboard (`eval/scripts/mvp_gate_dashboard.py`) with threshold config (`eval/config/mvp_gate_thresholds.json`), current/trend views, and actionable alerts.

## 8. Risks and Kill Criteria

- **Risk:** Search quality fails to beat stock baseline by Week 8.  
  **Action:** Drop advanced embedding work; ship deterministic feature retrieval only.
- **Risk:** Receipt/apply/rollback unstable by Week 6.  
  **Action:** Block all auto-apply; remain proposal-only for MVP.
- **Risk:** Security controls break analyst workflow.  
  **Action:** Keep strict default mode (`offline`) with explicit per-project override.
- **Risk:** Type PR quality too low by Week 10.  
  **Action:** Limit type automation to high-confidence primitives + signatures.

## 9. Operating Rhythm

1. Weekly planning: lock scope for next 7 days, no mid-week epic switches.
2. Mid-week checkpoint: metric trend + blocker review (30 minutes).
3. End-week demo: show one artifact, one metric delta, one risk update.
4. Weekly decision log: capture defer/kill/ship calls with rationale.

## 10. Source Alignment

This board operationalizes:
- `docs/deep-research-report.md`
- `docs/research/INDEX.md`
- `docs/research/evaluation-harness.md`
- `docs/research/analysis-data-plane-spec.md`
- `docs/research/agent-runtime-security-spec.md`
- `docs/research/type-lifecycle-ux.md`
- `docs/research/collaboration-review-design.md`
- `docs/research/corpus-kb-architecture.md`

## 11. E8-S1 Reopen Closure (2026-02-21)

- Story: `E8-S1` (`issue 1701`) reopened in Week 11 to require real executable gates and JDK21-enforced CI test execution.
- Published run evidence: `docs/soak-test-report-1701.md`.
- Blocking failures resolved:
  - `scripts/cyntra/gates.sh --mode=all` upgraded from placeholder checks to executable Python + Java regression gates.
  - Missing dashboard implementation added (`eval/scripts/mvp_gate_dashboard.py`) with threshold config (`eval/config/mvp_gate_thresholds.json`).
  - CI now enforces JDK21 for Gradle test execution on affected module `eval/java-regression` in smoke/nightly/release lanes (`.github/workflows/eval.yaml`).
- Soak outcome: `6/6` runs passed; recall delta vs stock stayed `1.000`; p95 latency stayed within `10.327-10.743 ms`; dashboard alert count `0`.
- Waivers: none.

## 12. R1-S6 Reopen Security Signoff Closure (2026-02-21)

- Story: `R1-S6` (`issue 1806`) reopened to require an executable abuse-scenario suite artifact against current controls.
- Published suite results: `docs/security/abuse-scenario-suite.md` (v1.2, executable run matrix).
- Published run evidence bundle: `docs/security/evidence/abuse-scenario-suite-1806/README.md`.
- Scenario execution summary: `5/5` scenarios passed; no failed controls; no waivers.

## 13. R1-S8 Exit-Gate Packet Publication (2026-02-21)

- Story: `R1-S8` (`issue 1808`) published the final MVP exit-gate decision packet grounded in reopened regression/security/benchmark evidence.
- Published packet: `docs/exit-gate-packet-1808.md`.
- Packet contents:
  - full gate register with artifact paths and `pass`/`fail`/`waived` status
  - waiver registry with owner, justification, and review date
  - formal go/no-go record with date, approvers, and final rationale

## 14. E8-S4 Reopen Final Decision Packet (2026-02-21)

- Story: `E8-S4` (`issue 1704`) reopened to publish a final MVP exit-gate packet with explicit pass/fail mapping, waiver/risk ownership, and decision provenance.
- Published packet: `docs/exit-gate-packet-1704.md`.
- Published workcell gate evidence: `docs/evidence/exit-gate-packet-1704/quality-gates.md`.
- Reopen acceptance closure:
  - each gate maps to measurable evidence artifact + `pass`/`fail`/`waived` status
  - open risks/waivers include owner, rationale, and expiration/revisit condition
  - go/no-go decision record includes approvers and a dated final determination

## 15. R1 Remediation Epic Closure (2026-02-21)

- Epic: `R1` (`issue 1800`) is closed; `.beads/issues.jsonl` now records `1800` and all child stories `1801-1809` as `done`.
- Reopened escalation story `14` closure evidence: commit `39f9d585ff` (`scripts/cyntra/preflight.sh`, `.github/workflows/eval.yaml`, `docs/research/python-integration-ops-matrix.md`, `docs/cyntra-kernel-runbook.md`).
- Reopened escalation story `15` closure evidence: commit `a2b0f6a3a9` + merge `d12d4d1ae4` (`scripts/cyntra/sync-backlog-csv.sh`, `docs/backlog-jira-linear.csv`, `docs/cyntra-kernel-runbook.md`).
- Reopened escalation story `16` closure evidence: commit `714b440f7c` + merge `e8941eac4d` (`scripts/cyntra/cyntra.sh`, `scripts/tests/test_cyntra_merge_path.py`, `docs/cyntra-kernel-runbook.md`).
- Final closure quality-gate evidence: `docs/evidence/r1-remediation-closure-1800/quality-gates.md`.
