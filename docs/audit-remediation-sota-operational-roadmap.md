# Audit Remediation + SOTA Operationalization Roadmap (E20-E21)

## Goal
Close every finding from the 2026-02-22 audit, then prove Reverend is operational as an in-Ghidra assistant with reproducible build, gate, benchmark, and runtime evidence.

## Scope
- Delivery integrity: compile health, gate/CI coverage, roadmap-source consistency, and kernel completion correctness.
- Runtime integrity: remove stub fallbacks and require production service wiring in cockpit paths.
- Performance/quality integrity: replace O(N) query/decompile hot paths with indexed retrieval and measurable lift.
- Program integrity: keep `master` and integrated `main` convergence paths verifiable.

## Finding-to-Bead Closure Matrix
| Finding ID | Finding | Bead(s) | Required Proof |
|---|---|---|---|
| F1 | `:Reverend` compile break | `3101` | `:Reverend:compileJava` and `:Reverend:test` pass |
| F2 | Gate/CI misses Reverend/frontier breakage | `3102` | `scripts/cyntra/gates.sh` + `.github/workflows/eval.yaml` module coverage expanded |
| F3 | Cockpit defaults to stub services | `3103` | `CockpitPlugin` bootstraps live query/evidence/proposal services by default |
| F4 | Python gate path not self-contained | `3104` | gate Python suites pass without implicit optional deps |
| F5 | Integrated-branch compile blockers pending | `3105` | `:Framework-TraceModeling:compileJava` and `:Reverend:compileJava :Reverend:test --tests "ghidra.reverend.cockpit.*"` pass in active + integrated worktrees |
| F6 | Hash-collision-prone cache keys | `3106` | canonical serialization + digest cache keys with tests |
| F7 | Roadmap/docs drift | `3107` | `.beads`/CSV/docs validator parity + CI enforcement |
| F8 | Zero-diff auto-close integrity gap | `3108`, `3110`, `3111`, `3112` | no-op close requires explicit manifest `noop_justification` (`manifest.issue.noop_justification` or `manifest.noop_justification`) + completion gate-summary telemetry (`completion_policy_gate_summary`) + blocking-gate skip-budget enforcement (allowlisted reasons + skip counts/reasons evidence) + reopen policy |
| F9 | O(N) query architecture + TODO embedding | `3201-3204` | indexed retrieval + embedding-backed ranking path |
| F10 | Weak Java/Python/plugin runtime integration | `3205` | query -> proposal -> apply/rollback loop operational in cockpit |
| F11 | “Operational” claim not benchmark-gated | `3206-3208` | benchmark thresholds enforced and GA packet published |
| F12 | Kernel toolchain deadlock at `prompt_sent` (no telemetry progress) | `3113` | stalled runs fail-fast with deterministic retry/reopen policy |
| F13 | Sleeptime evolution schema mismatch traceback | `3114` | sleeptime consolidation runs cleanly with validated input schema |

## Epic E20: Audit Closure + Delivery Integrity (`3100`)
Stories: `3101-3114`

Dispatch waves:
1. Wave A (kernel/runtime unblock): `3113`, `3114`.
2. Wave B (critical functional fixes): `3103`, `3105`, `3106`, `3109`.
3. Wave C (gate hardening + completion integrity): `3102`, `3107`, `3108`, `3110`, `3111`, `3112`.

## Epic E21: SOTA Assistant Operationalization (`3200`)
Stories: `3201-3208`

Dispatch waves:
1. Query engine hardening: `3201`, `3202`, `3204`.
2. Plugin/runtime integration: `3203`, `3205`.
3. Operational validation: `3206`, `3207`, `3208`.

## Roadmap Source-of-Truth Status (Validator-Aligned)
- Roadmap exportable issues: `121`
- Done: `95`
- Open: `17`
- Blocked: `9`
- E20 (`3100` + children): `blocked=1, done=5, open=9`
- E21 (`3200` + children): `blocked=1, open=8`

## “SOTA Assistant Inside Ghidra” Operational Criteria
- Search latency and retrieval quality are benchmarked against pinned baselines (`3206`).
- Benchmark slices include ranking quality (`real_target`) and operator workflow completion (`spec_review`) metrics, both enforced by blocking thresholds (`3206`).
- Cockpit actions use real services and emit evidence/receipt chains (`3203`, `3205`).
- Query and similarity paths are index-backed, not full-program decompile scans (`3201`, `3202`).
- End-to-end operator path is reproducible from a local clean setup (`3207`, `3208`).
- Gate artifacts publish baseline-vs-current deltas and reproducible manifests at `.cyntra/artifacts/gates/eval/operational-claim-delta.json` and `.cyntra/artifacts/gates/eval/operational-claim-manifest.json`.

## E21-3201 Profiling Artifacts
- `semantic-search-stage ... stage=embedding ... details={primaryRanker=indexed-features, indexedFresh=..., indexedReused=..., refineCandidateCount=...}` documents that semantic ranking is index-first and only decompile-refines a bounded shortlist.
- `similarity-index-profile ... decompileCandidates=0` documents that `findSimilarFunctions` primary scoring no longer decompiles every candidate function.
- E21-S4 overlay policy: query results now emit explicit `weight_policy` + `static_weight`/`dynamic_weight` provenance fields and deterministic `evidence_ref:{static|dynamic}:...` links for cockpit drilldown rendering.
- E21-S5 cockpit mission loop: proposal review/apply/rollback mutations now emit linked receipt artifacts and append proposal-level provenance chains so repeated scenario runs can verify deterministic loop outputs.
- E21-S7 operator runbook publication: `docs/operator-reviewer-runbook.md` now includes a local clean-environment assistant workflow with prerequisites, launch/verification commands, deterministic mission execution, and failure-signature remediation mapping.

## E21-S8 GA Readiness Packet Artifacts (2026-02-23)
- Exit-gate packet: `docs/exit-gate-report.md`
- Formal decision record: `docs/go-no-go-decision.md`
- Operational-claim gate artifacts:
  - `.cyntra/artifacts/gates/eval/operational-claim-regression.json`
  - `.cyntra/artifacts/gates/eval/operational-claim-delta.json`
  - `.cyntra/artifacts/gates/eval/operational-claim-manifest.json`
- Compile/gate provenance artifact: `.cyntra/artifacts/gates/blocking-gate-summary.json`
- Benchmark lift evidence: `docs/evidence/rc-functional-validation/09-soak-report.json` and `docs/soak-test-report-1701.md`
- Risk/signoff evidence: `docs/security/security-signoff-checklist.md` and `docs/security/evidence/abuse-scenario-suite-1806/README.md`

## E22 Kernel Reliability GA Controls (2026-02-23)
- Supervised deadlock guard: `scripts/cyntra/run-once.sh` applies inactivity timeout controls (`CYNTRA_SUPERVISED_STALL_TIMEOUT_SECONDS`, `CYNTRA_SUPERVISED_STALL_POLL_SECONDS`, `CYNTRA_SUPERVISED_ACTIVITY_PATHS`) to eliminate silent `prompt_sent` stalls.
- Deterministic failure telemetry: supervised stalls emit `failure_code_classified` with canonical `failure_code=runtime.prompt_stall_no_output` and `reason_code=supervision.inactivity_timeout` in `.cyntra/logs/events.jsonl`.
- Deterministic fallback routing: supervised stall classification now routes fallback even when no fresh `proof.json` exists for the stalled cycle.
- Reliability SLO artifacts (reproducible + threshold-enforced):
  - soak artifact: `.cyntra/artifacts/gates/eval/soak-report.json`
  - machine report: `.cyntra/artifacts/gates/eval/reliability-slo-report.json`
  - markdown report: `.cyntra/artifacts/gates/eval/reliability-slo-report.md`
  - reproduction command: `bash scripts/cyntra/gates.sh --mode=all`

## Required Verification Commands
- `./gradlew --no-daemon :Framework-TraceModeling:compileJava`
- `./gradlew --no-daemon :Reverend:compileJava :Reverend:test --tests "ghidra.reverend.cockpit.*"`
- `cd "$CYNTRA_INTEGRATED_WORKTREE_PATH" && ./gradlew --no-daemon :Framework-TraceModeling:compileJava :Reverend:compileJava :Reverend:test --tests "ghidra.reverend.cockpit.*"`
- `./gradlew --no-daemon :Reverend:compileJava :Reverend:test --tests "ghidra.reverend.*"`
- `./gradlew --no-daemon :Generic:compileJava :Generic:test --tests "ghidra.security.*"`
- `./gradlew --no-daemon :SoftwareModeling:compileJava :Base:compileJava`
- `bash scripts/cyntra/gates.sh --mode=all`
- `scripts/cyntra/validate-roadmap-completion.sh`
- `CYNTRA_PREFLIGHT_SYNC_COMPILE_VERIFY=1 scripts/cyntra/preflight.sh`
- `scripts/cyntra/converge-worktrees.sh` (or `--checklist-only` for nightly/per-wave drift sanity)

## Kernel Control Loop
- Dispatch one cycle: `scripts/cyntra/run-once.sh`
- Continuous dispatch: `scripts/cyntra/run-watch.sh`
- Status: `scripts/cyntra/cyntra.sh status`
- Live telemetry: `tail -f .cyntra/logs/events.jsonl`
- Completion anomaly guard: `bash scripts/cyntra/cyntra.sh completion-anomaly-guard`
- Reconcile queue after edits: `scripts/cyntra/sync-backlog-csv.sh`

## References
- `docs/deep-research-report.md`
- `docs/research/INDEX.md`
- `docs/e9-frontier-roadmap.md`
- `docs/e13-e19-frontier-ga-roadmap.md`
- `docs/exit-gate-report.md`
- `docs/go-no-go-decision.md`
