# 12-Week Execution Board: Ghidra "Alien-Tech" MVP

As-of: 2026-02-19  
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
| 3 | Add transaction-linked receipt writer | Add delta diff renderer (before/after) | Build triage feature extractor prototype | Add policy mode config (`offline`, `allowlist`, `cloud`) | Add per-commit smoke metrics | `M3`: receipts written for manual edits |
| 4 | Proposal state machine (`proposed`, `approved`, `rejected`) | Review actions (approve/reject/bulk) | Local embedding pipeline v1 | Guard MCP/tool calls by capability | Nightly regression job enabled | `M4`: review/apply path works in test project |
| 5 | Rollback chain + idempotent apply API | Rollback UX + change history view | Similarity index + top-k retrieval API | Endpoint allowlist enforcement | Add latency/recall dashboards | `M5`: rollback integration test green |
| 6 | Evidence-link storage (`xrefs`, strings, callsites) | Evidence drawer in review UI | Re-ranker using evidence weights | Permission audit logging | Add receipt completeness gate | `M6`: 100% proposal receipts in CI tests |
| 7 | Local search query service hardening | Semantic search panel (`intent` + `similar`) | Triage Crew rule set v1 | Sandbox boundary tests (plugin/agent) | Create curated triage eval set | `M7`: semantic search usable in UI |
| 8 | Performance tuning (index build/query) | Add triage mission run page | Triage scoring calibration | Security regression suite v1 | Evaluate recall/latency deltas | `M8`: search quality + latency interim pass |
| 9 | Type assertion persistence + propagation hooks | Type PR list/detail/review panel | Type suggestion generator v1 | High-impact mutation approval policy | Add type metrics to CI | `M9`: type PR end-to-end demo |
| 10 | Corpus sync worker (approved-only artifacts) | Sync status and provenance UI | Cross-binary reuse heuristics v1 | Access control + provenance checks for sync | Corpus pilot benchmark run | `M10`: corpus sync pilot operational |
| 11 | Fix bottlenecks from pilot; finalize APIs | UX polish + reviewer shortcuts | Triage/type quality tuning | Pen-test style abuse scenarios | Full regression + soak run | `M11`: release candidate cut |
| 12 | Freeze schema/API; release packaging | Operator and reviewer runbook UI links | Final model/config lock | Security sign-off checklist | Exit-gate validation report | `M12`: MVP release decision |

## 6. Backlog Items (Ticket Seeds)

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

## 7. Risks and Kill Criteria

- **Risk:** Search quality fails to beat stock baseline by Week 8.  
  **Action:** Drop advanced embedding work; ship deterministic feature retrieval only.
- **Risk:** Receipt/apply/rollback unstable by Week 6.  
  **Action:** Block all auto-apply; remain proposal-only for MVP.
- **Risk:** Security controls break analyst workflow.  
  **Action:** Keep strict default mode (`offline`) with explicit per-project override.
- **Risk:** Type PR quality too low by Week 10.  
  **Action:** Limit type automation to high-confidence primitives + signatures.

## 8. Operating Rhythm

1. Weekly planning: lock scope for next 7 days, no mid-week epic switches.
2. Mid-week checkpoint: metric trend + blocker review (30 minutes).
3. End-week demo: show one artifact, one metric delta, one risk update.
4. Weekly decision log: capture defer/kill/ship calls with rationale.

## 9. Source Alignment

This board operationalizes:
- `docs/deep-research-report.md`
- `docs/research/INDEX.md`
- `docs/research/evaluation-harness.md`
- `docs/research/analysis-data-plane-spec.md`
- `docs/research/agent-runtime-security-spec.md`
- `docs/research/type-lifecycle-ux.md`
- `docs/research/collaboration-review-design.md`
- `docs/research/corpus-kb-architecture.md`
