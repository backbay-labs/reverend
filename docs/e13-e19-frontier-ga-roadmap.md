# E13-E19 Frontier GA Roadmap: Native RE Platform to Zero-Trust Production

As-of: 2026-02-22  
Scope: Extend Reverend from E12 native capability wave into production-grade benchmark rigor, in-tool operator workflows, deep type/dynamic intelligence, corpus scale-out, zero-trust runtime hardening, and patch/remediation operations.

## 1) Program Outcomes

E13-E19 closes the gap between a high-potential RE platform and an operational system that can be trusted for real targets, team-scale usage, and remediation pipelines.

Target outcomes:

1. Real-target benchmark program with signed releases and trend visibility.
2. First-class Reverend plugin workflow inside Ghidra (UI/headless parity).
3. Higher-fidelity type/structure intelligence from decompiler-native signals.
4. Dynamic, symbolic, taint, coverage, and crash evidence merged into one query plane.
5. Corpus platform hardening for integrity, replication, tenancy, and load.
6. Zero-trust runtime controls for agents, plugins, and model execution.
7. Patch and exploitability workbench for red/blue remediation decisions.

## 2) Global Technical Requirements (Applies to Every Story)

- Determinism: all pipelines accept pinned manifests, seeds, and schema versions.
- Provenance: all generated artifacts include receipt links and source attribution.
- Safety: policy modes (`offline`, `allowlist`, `cloud`) and capability guardrails remain enforced.
- Reproducibility: each bead must include runnable command sets and artifact paths.
- Compatibility: Java 21 + current repository gate stack (`scripts/cyntra/gates.sh`) is non-optional.
- Evidence quality: benchmark and security outputs must include machine-readable plus markdown reports.

## 3) Epic E13 (2400): Real-Target Benchmark Program GA

### Mission
Build a benchmark system that is legally clean, architecture-diverse, confidence-calibrated, human-time-aware, and releaseable as signed evaluation packs.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2401` | OSS binary corpus ingestion + license/provenance manifesting | Add ingestion pipeline that emits locked manifest rows with `sha256`, SPDX license, source URL, acquisition timestamp, architecture, compiler metadata, and usage policy class; reject unknown license classes by default. | `datasets/datasets.lock.json`, `eval/reports/e13/corpus_manifest_validation.json`, `docs/evidence/e13/2401-corpus-provenance.md` | `2308` |
| `2402` | Ground-truth curation tooling for similarity/type/diff tasks | Build curator tooling for pair/task labeling with reviewer IDs, adjudication state, disagreement notes, and dataset split stability; support export to eval harness format. | `eval/datasets/ground_truth/*.jsonl`, `eval/reports/e13/ground_truth_quality.md` | `2401` |
| `2403` | Architecture coverage pack (x86_64/ARM64/MIPS/RISCV/PPC) | Extend corpus profiles and test runners for multi-architecture slices; enforce per-architecture minimum sample counts and per-lane fallback behavior. | `eval/reports/e13/arch_coverage_matrix.md`, `eval/reports/e13/arch_slice_metrics.json` | `2401` |
| `2404` | OOD score + confidence calibration gates | Add OOD detector and confidence calibration (temperature/isotonic) for retrieval/type/diff outputs; fail when calibration error exceeds thresholds. | `eval/reports/e13/calibration.json`, `eval/reports/e13/ood_gate.md` | `2402`, `2403` |
| `2405` | Human-time-to-answer benchmark harness | Implement timed analyst workflow harness with deterministic prompts/tasks; capture time-to-first-correct, time-to-mergeable-proposal, and reviewer correction rate. | `eval/reports/e13/human_time_study.csv`, `eval/reports/e13/human_time_summary.md` | `2402` |
| `2406` | Signed benchmark release pack + trend dashboard | Package signed benchmark release bundle (manifest, metrics, changelog, checksums), and publish trend dashboard input artifacts for CI/nightly deltas. | `eval/releases/e13/*`, `eval/reports/e13/trend_dashboard.json`, `docs/evidence/e13/2406-release-pack.md` | `2404`, `2405` |

## 4) Epic E14 (2500): Native Reverend Pluginization

### Mission
Move frontier capabilities from script-heavy surfaces to native Ghidra plugin services with safe transactions, policy controls, and headless/UI parity.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2501` | Create Features/Reverend plugin module and service contracts | Create dedicated `Ghidra/Features/Reverend` module with service interfaces for query, proposal, evidence, missions, and policy-aware actions; include API versioning contract. | `Ghidra/Features/Reverend/*`, `docs/evidence/e14/2501-service-contracts.md` | `2308` |
| `2502` | Bind semantic query engine to live Program/Decompiler state | Integrate query services with active `Program`, symbol table, decompiler context, and address navigation; ensure cache invalidation on analysis updates. | `docs/evidence/e14/2502-live-query-bindings.md`, plugin integration tests | `2501` |
| `2503` | Cockpit v2 dockable providers with jump-to-evidence actions | Implement dockable provider set for semantic search, evidence drilldown, and graph facets with direct jump-to-address, jump-to-xref, and proposal creation actions. | UI screenshots/test logs, `docs/evidence/e14/2503-cockpit-v2.md` | `2502` |
| `2504` | Transaction-safe apply/revert wired to Ghidra undo stack | Wire apply/revert through Ghidra transactions and undo/redo; provide atomic batch operations with rollback guarantees and receipt linkage. | transaction regression suite, `docs/evidence/e14/2504-undo-integration.md` | `2503` |
| `2505` | Headless/UI parity harness for mission and proposal flows | Ensure mission/proposal workflows return equivalent outputs in headless and UI modes; include parity diff checks and deterministic fixtures. | `eval/reports/e14/parity_report.json`, `docs/evidence/e14/2505-headless-ui-parity.md` | `2502`, `2504`, `2406` |
| `2506` | Operator settings + policy controls in-tool | Add settings panels and persisted config for model policy mode, egress policy class, confidence thresholds, and apply permissions with audit visibility. | settings integration tests, `docs/evidence/e14/2506-operator-policy-controls.md` | `2501` |

## 5) Epic E15 (2600): Decompiler-Native Type/Structure Intelligence

### Mission
Improve type recovery quality by operating directly on SSA/alias features, generating conflict proofs, reconstructing interfaces, and ranking alternate hypotheses.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2601` | SSA + alias feature extractor from decompiler IR | Build extractor for SSA use-def chains, alias classes, pointer arithmetic patterns, and callsite type clues; persist deterministic feature vectors keyed by function+version. | `eval/reports/e15/ssa_alias_features.json`, extractor tests | `2505`, `2406` |
| `2602` | Struct layout solver with conflict proofs | Implement constraint solver for struct field offsets/sizes/types; emit machine-readable conflict proofs and minimal unsat core summaries for reviewers. | `eval/reports/e15/struct_solver_results.json`, `docs/evidence/e15/2602-conflict-proofs.md` | `2601` |
| `2603` | Vtable/interface reconstruction across callgraph | Add vtable candidate detection, method slot clustering, interface hypothesis generation, and confidence tagging across callgraph components. | `eval/reports/e15/vtable_interface_metrics.json` | `2601` |
| `2604` | Cross-function and cross-binary type propagation v3 | Propagate accepted types across call boundaries and corpus-linked clones with provenance constraints and policy-aware import limits. | `eval/reports/e15/propagation_v3.json`, cross-binary replay logs | `2602`, `2603`, `2506` |
| `2605` | Alternate-hypothesis ranking for uncertain types | Rank top-k type hypotheses using multi-signal scoring (SSA, alias, callsite, symbolic, corpus prior) and expose rationale components. | `eval/reports/e15/hypothesis_ranking.json`, `docs/evidence/e15/2605-ranking.md` | `2604` |
| `2606` | Type accuracy benchmark pack vs baseline decompiler output | Publish benchmark pack comparing Reverend type output vs stock baseline with precision/recall/F1 by type family and architecture. | `eval/releases/e15/*`, `eval/reports/e15/type_accuracy_summary.md` | `2604`, `2605`, `2406` |

## 6) Epic E16 (2700): Dynamic/Symbolic/Taint Evidence Fabric

### Mission
Create a unified runtime evidence fabric that ingests traces/taint/constraints/coverage/crash data and supports temporal investigation with deterministic replay.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2701` | Normalized ingest for debugger, Frida, QEMU trace formats | Implement normalized event schema with adapters for Ghidra debugger, Frida, and QEMU trace feeds; include versioned parser contracts. | `eval/reports/e16/trace_ingest_compat.json`, parser fixtures | `2505`, `2406` |
| `2702` | Taint evidence schema + ingest adapters | Add taint source/sink/propagation schema and adapters for at least one dynamic taint engine; preserve entity linkage to static functions/variables. | `eval/reports/e16/taint_ingest.json`, schema docs | `2701` |
| `2703` | Constraint/counterexample replay overlays in cockpit | Render constraint and counterexample evidence in cockpit views with jump-to-block and branch-condition context; include deterministic replay controls. | `docs/evidence/e16/2703-replay-overlay.md`, UI parity tests | `2701`, `2702`, `2503` |
| `2704` | Coverage/crash evidence auto-link to static entities | Ingest coverage and crash records; auto-link to static function/block/data entities and mission hotspot queues. | `eval/reports/e16/coverage_crash_linking.json` | `2701` |
| `2705` | Temporal query API over static+dynamic evidence graph | Expose temporal query API (time windows, event joins, before/after relations) over merged static/dynamic graph with bounded latency targets. | API conformance tests, `eval/reports/e16/temporal_query_perf.json` | `2703`, `2704` |
| `2706` | Deterministic replay artifacts for incident reproduction | Package replay bundles with pinned traces, symbolic states, taint snapshots, and expected outcomes for incident reproduction workflows. | `eval/releases/e16/*`, `docs/evidence/e16/2706-replay-pack.md` | `2705`, `2406` |

## 7) Epic E17 (2800): Corpus Platform GA + Team Scale

### Mission
Upgrade corpus infrastructure to support integrity guarantees, replication and recovery, low-latency sharded retrieval, secure multi-tenant operations, and analyst-scale load.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2801` | Content-addressable artifact storage and integrity verification | Implement CAS object layout and digest-verification enforcement for synced artifacts, proposals, and benchmark packs; reject hash mismatches by default. | `docs/evidence/e17/2801-cas-integrity.md`, integrity tests | `2401`, `2307` |
| `2802` | Receipt replication/compaction and recovery drills | Add receipt replication with compaction strategy, chain continuity checks, and scheduled restore drills with recovery SLOs. | `docs/evidence/e17/2802-recovery-drill.md`, recovery logs | `2801` |
| `2803` | Sharded index service + cache layer for low-latency retrieval | Introduce shard-aware retrieval service with cache hierarchy and shard health telemetry; define p95 latency and stale-read budgets. | `eval/reports/e17/shard_latency.json`, load test logs | `2801`, `2406` |
| `2804` | Negative-example sync (rejected proposals) for model hardening | Extend sync path for rejected proposals as negative training/eval examples with policy-aware anonymization and reviewer attribution controls. | `eval/reports/e17/negative_examples_quality.md` | `2801`, `2803` |
| `2805` | Multi-tenant ACL + SSO + audit-attribution hardening | Implement tenant boundaries, RBAC/ABAC enforcement, SSO claims mapping, and immutable attribution audit trails for all cross-tenant operations. | security integration tests, `docs/evidence/e17/2805-multitenant-security.md` | `2801`, `2506` |
| `2806` | 10->100 analyst load/soak validation | Run load and soak campaigns simulating 10 to 100 analysts with mixed query/review/sync workloads; report capacity limits and tuning guidance. | `eval/reports/e17/load_soak_10_100.json`, operations playbook | `2802`, `2803`, `2804`, `2805` |

## 8) Epic E18 (2900): Zero-Trust Agent Runtime

### Mission
Move from policy-guided safety to enforceable zero-trust runtime controls with sandboxing, short-lived credentials, DLP constraints, attestation, adversarial testing, and automated posture response.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `2901` | Process-level sandbox runner (seccomp/AppArmor/macOS profile) | Implement per-tool process sandbox launcher with OS profile abstraction; enforce deny-by-default filesystem/network/process capabilities with explicit allowlists. | `docs/evidence/e18/2901-os-sandbox.md`, sandbox tests | `2506`, `2805` |
| `2902` | Short-lived creds + key rotation control plane | Add credential broker with TTL-bound tokens, rotation schedules, revocation hooks, and audit trails; remove long-lived static secret assumptions. | `docs/evidence/e18/2902-credential-rotation.md`, rotation drill logs | `2805`, `2806` |
| `2903` | Egress DLP budget + deterministic redaction filters | Enforce request/response DLP policies with deterministic redaction and egress budget accounting (bytes/entities/categories) per mission and tenant. | `eval/reports/e18/dlp_redaction_eval.json` | `2901`, `2902` |
| `2904` | Signed plugin/model attestation enforcement | Require signature and provenance verification for plugin/model artifacts before execution; block unsigned or revoked components. | `docs/evidence/e18/2904-attestation.md`, attestation gate logs | `2901`, `2902`, `2801` |
| `2905` | Adversarial prompt/binary test suite expansion | Expand abuse test suite with prompt injection, binary-embedded payloads, policy bypass attempts, and model inversion probes; integrate into gates. | `docs/security/abuse-scenario-suite.md`, `eval/reports/e18/adversarial_suite.json` | `2903`, `2904` |
| `2906` | Security posture scorecard and auto-remediation hooks | Publish posture scorecards from runtime controls and wire automated remediation hooks (credential revocation, sandbox lockdown, policy downgrade). | `eval/releases/e18/posture_scorecard.json`, `docs/evidence/e18/2906-remediation-hooks.md` | `2903`, `2904`, `2905` |

## 9) Epic E19 (3000): Patching + Exploitability Workbench

### Mission
Deliver exploitability-aware patch planning and validation workflows that convert analysis evidence into safe remediation decisions with reproducible packets.

| Bead | Story | Technical Requirements | Validation Artifacts | Dependencies |
|---|---|---|---|---|
| `3001` | Binary rewrite proposal adapter (GTIRB/e9patch interop) | Implement rewrite proposal adapters for GTIRB/e9patch flows with reversible patch specs, target constraints, and provenance receipts. | `docs/evidence/e19/3001-rewrite-adapter.md`, adapter fixtures | `2606`, `2906` |
| `3002` | Exploitability scoring from static+dynamic evidence | Build exploitability scoring engine combining static indicators, dynamic evidence, and environmental assumptions with confidence and uncertainty bounds. | `eval/reports/e19/exploitability_scoring.json` | `2606`, `2706`, `2806`, `2906` |
| `3003` | PoC template generation with sandboxed replay | Generate PoC templates from scored findings and validate execution only in sandboxed replay environments with explicit legal/policy controls. | `docs/evidence/e19/3003-poc-replay.md`, replay logs | `3002`, `2901` |
| `3004` | Patch correctness validation harness | Validate semantic equivalence, safety properties, and regression behavior for proposed patches across benchmark targets and replay traces. | `eval/reports/e19/patch_validation.json` | `3001`, `3002` |
| `3005` | Vulnerability query DSL + saved hunt packs | Add vulnerability query DSL, saved hunt packs, and shareable filters tied to corpus evidence and receipt history. | `docs/evidence/e19/3005-vuln-dsl.md`, DSL conformance tests | `3002`, `2806` |
| `3006` | Red/Blue decision packet workflow for remediation rollout | Build decision packet workflow with red-team exploit evidence, blue-team patch options, risk score deltas, owner signoff, and rollout checkpoints. | `docs/go-no-go-decision.md` updates, `eval/releases/e19/decision_packets/*` | `3003`, `3004`, `3005` |

## 10) Cross-Epic Dependency Spine

Dependency spine used for bead graph wiring:

```text
2308 -> 2401, 2501
2406 -> 2505, 2601, 2701, 2803
2505 -> 2601, 2701
2506 -> 2604, 2805, 2901
2307 -> 2801
2401 -> 2801
2606 -> 3001, 3002
2706 -> 3002
2806 -> 2902, 3002, 3005
2906 -> 3001, 3002, 3006
```

## 11) Dispatch Strategy

Recommended dispatch waves once E12 reaches closure on its remaining open stories:

1. Wave A (parallel): `2401`, `2501`
2. Wave B (parallel): `2402`, `2403`, `2502`, `2506`
3. Wave C (parallel): `2404`, `2405`, `2503`, `2801`
4. Wave D (parallel): `2406`, `2504`, `2802`, `2803`
5. Wave E (parallel): `2505`, `2601`, `2701`, `2805`
6. Wave F (parallel): `2602`, `2603`, `2702`, `2704`, `2804`, `2901`
7. Wave G (parallel): `2604`, `2703`, `2806`, `2902`, `2904`
8. Wave H (parallel): `2605`, `2705`, `2903`, `2905`
9. Wave I (parallel): `2606`, `2706`, `2906`
10. Wave J (parallel): `3001`, `3002`
11. Wave K (parallel): `3003`, `3004`, `3005`
12. Wave L: `3006`

## 12) Reference Set

- `docs/deep-research-report.md`
- `docs/e9-frontier-roadmap.md`
- `docs/research/INDEX.md`
- `docs/research/analysis-data-plane-spec.md`
- `docs/research/binary-similarity-semantic-search.md`
- `docs/research/decompilation-type-recovery.md`
- `docs/research/dynamic-static-evidence-model.md`
- `docs/research/corpus-kb-architecture.md`
- `docs/research/agent-runtime-security-spec.md`
- `docs/research/binary-rewriting-transformation.md`
- `docs/research/vulnerability-discovery-exploit-dev.md`
- `docs/research/evaluation-harness.md`
