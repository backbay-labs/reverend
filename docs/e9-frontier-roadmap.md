# E9/E10/E11 Frontier Roadmap: SOTA Buildout to Adversarial Lift

As-of: 2026-02-22  
Scope: Extend Reverend beyond RC guardrails into frontier capabilities, productize those capabilities into operator-visible workflows, and then execute the next SOTA expansion on diff/deobf/symex/fuzz/firmware lift.

## 1) Why E9 Exists

E1-E8 and R1-R2 delivered a production-safe RC baseline (receipts, policy controls, deterministic gates, validation evidence).  
E9 is the next implementation wave to close the remaining gap to "alien-tech" workflows:

1. Whole-artifact mapping and intent-level querying.
2. Evidence-backed auto-annotation at scale.
3. Dynamic-static fusion and deterministic mission crews.
4. Corpus learning + spec extraction for compounding analyst velocity.

## 2) Research Alignment

| E9 Story | Capability | Primary Research References |
|---|---|---|
| E9-S1 | Whole-program knowledge graph + index | `docs/deep-research-report.md`, `docs/research/analysis-data-plane-spec.md`, `docs/research/ghidra-internals-architecture.md` |
| E9-S2 | Intent + similarity retrieval | `docs/research/binary-similarity-semantic-search.md`, `docs/research/evaluation-harness.md` |
| E9-S3 | Evidence-backed auto-annotation | `docs/research/ai-assisted-reverse-engineering.md`, `docs/research/dynamic-static-evidence-model.md`, `docs/research/collaboration-review-design.md` |
| E9-S4 | Type recovery + propagation lifecycle | `docs/research/decompilation-type-recovery.md`, `docs/research/type-lifecycle-ux.md` |
| E9-S5 | Dynamic-static fusion overlays | `docs/research/symbolic-execution-fuzzing-dynamic.md`, `docs/research/dynamic-static-evidence-model.md` |
| E9-S6 | Deterministic autopilot crews | `docs/research/ai-assisted-reverse-engineering.md`, `docs/research/diffing-matching-deobfuscation.md`, `docs/research/malware-analysis-anti-analysis.md` |
| E9-S7 | Cross-binary learning/codebook | `docs/research/corpus-kb-architecture.md`, `docs/research/analysis-data-plane-spec.md`, `docs/research/agent-runtime-security-spec.md` |
| E9-S8 | Spec extraction + PR-grade review packs | `docs/research/collaboration-review-design.md`, `docs/research/analysis-data-plane-spec.md`, `docs/research/evaluation-harness.md` |

## 3) E9 Bead Plan (Execution Snapshot)

| Bead ID | Story | Current Status | Lane | Output |
|---|---|---|---|---|
| `2001` | E9-S1 Knowledge Graph Foundation | `done` | Backend/Data | Graph schema + ingest/index service |
| `2002` | E9-S2 Intent + Similarity Retrieval | `done` | ML/Backend | Ranked intent/similarity query API |
| `2003` | E9-S3 Evidence-Backed Auto-Annotation | `done` | Backend/Security | Proposals with receipts, confidence, alternatives |
| `2004` | E9-S4 Type Recovery + Propagation | `done` | ML/Backend | Inference + lifecycle + propagation/conflict handling |
| `2005` | E9-S5 Dynamic-Static Fusion | `done` | Debugger/Data | Trace overlays and runtime-attributed evidence |
| `2006` | E9-S6 Deterministic Autopilot Crews | `done` | ML/Plugin | Triage/protocol/diff/deobf mission pipelines |
| `2007` | E9-S7 Cross-Binary Learning Codebook | `done` | Backend/Security | Approved-artifact reuse and transfer suggestions |
| `2008` | E9-S8 Spec Extraction + Review Packets | `done` | Plugin/Docs | Exportable schemas/spec artifacts + review workflow |

## 4) Dependency Graph

```mermaid
flowchart LR
    RC["1704 / 1909 baseline complete"] --> S1["2001 E9-S1"]
    S1 --> S2["2002 E9-S2"]
    S1 --> S3["2003 E9-S3"]
    S1 --> S5["2005 E9-S5"]

    S3 --> S4["2004 E9-S4"]

    S2 --> S6["2006 E9-S6"]
    S3 --> S6
    S5 --> S6

    S2 --> S7["2007 E9-S7"]
    S4 --> S7

    S6 --> S8["2008 E9-S8"]
    S7 --> S8
```

## 5) E9 Dispatch Waves (Parallel by Design)

1. Wave 0: `2001`
2. Wave 1 (parallel): `2002`, `2003`, `2005`
3. Wave 2 (parallel): `2004`, `2006`
4. Wave 3: `2007`
5. Wave 4: `2008`

Kernel readiness commands:

```bash
scripts/cyntra/preflight.sh
scripts/cyntra/cyntra.sh status
```

## 6) E10 Productization Wave (Next Execution Set)

E9 delivered core primitives. E10 focuses on making them analyst-visible in Ghidra and proving lift on real-world binary slices.

| E10 Story | Bead ID | Initial Status | Lane | Primary Outcome |
|---|---|---|---|---|
| E10-S1 Semantic Query Cockpit Panel | `2101` | `ready` | Plugin/UI | Operator cockpit for intent queries + similarity navigation |
| E10-S2 Mission Hotspot Map | `2102` | `open` | Backend/ML | Ranked auth/network/crypto/protocol hotspot mapping |
| E10-S3 Proposal Review Inbox | `2103` | `open` | Plugin/Collab | Accept/reject/revert workflow with evidence and rollback |
| E10-S4 Corpus Retrieval Hardening | `2104` | `open` | Backend/Data | Non-toy corpus index/retrieval with SLA evidence |
| E10-S5 Multi-Source Trace Adapters | `2105` | `open` | Debugger/Data | Unified trace evidence ingestion from multiple sources |
| E10-S6 Mission Orchestrator | `2106` | `open` | ML/Plugin | Deterministic mission runs with artifact packs |
| E10-S7 Real-World Benchmark Lift Suite | `2107` | `open` | Eval/Research | Lift metrics vs baseline on representative binaries |
| E10-S8 GA Readiness Packet | `2108` | `open` | Release/Validation | GA decision packet and reproducible demo workflow |

### E10 Dependency Graph

```mermaid
flowchart LR
    E9DONE["2008 E9 complete"] --> T1["2101 E10-S1"]
    T1 --> T2["2102 E10-S2"]
    T1 --> T3["2103 E10-S3"]
    T1 --> T4["2104 E10-S4"]
    T1 --> T5["2105 E10-S5"]

    T2 --> T6["2106 E10-S6"]
    T3 --> T6
    T4 --> T6
    T5 --> T6

    T4 --> T7["2107 E10-S7"]
    T5 --> T7

    T6 --> T8["2108 E10-S8"]
    T7 --> T8
```

### E10 Dispatch Waves

1. Wave 0: `2101`
2. Wave 1 (parallel): `2102`, `2103`, `2104`, `2105`
3. Wave 2 (parallel): `2106`, `2107`
4. Wave 3: `2108`

## 7) E11 SOTA Expansion Wave (Post-E10)

E11 turns E10 productization into deep technical lift on still-open SOTA fronts called out in the deep research report: diffing quality, deobfuscation, symbolic + fuzz evidence fusion, firmware verticalization, and multi-analyst branch/merge workflows.

| E11 Story | Bead ID | Initial Status | Lane | Primary Outcome |
|---|---|---|---|---|
| E11-S1 Semantic Diff Narrative Engine | `2201` | `open` | Backend/Plugin | Evidence-backed semantic diff and impact narratives |
| E11-S2 Deobfuscation Detector/Transform Pack | `2202` | `open` | ML/Backend | Deterministic obfuscation detection + reversible transforms |
| E11-S3 Symbolic Evidence Bridge | `2203` | `open` | Debugger/Data | Counterexample/path-constraint overlays in static views |
| E11-S4 Fuzz Harness + Coverage Sync | `2204` | `open` | Eval/ML | Harness generation and coverage/crash feedback into analysis |
| E11-S5 Firmware Vertical Pipeline | `2205` | `open` | Pipeline/Data | Reproducible firmware ingest/component-attribution/triage |
| E11-S6 Branch/Merge Review Topology | `2206` | `open` | Plugin/Collab | Multi-analyst proposal branching, merge, and conflict workflows |
| E11-S7 Adversarial Lift Benchmark | `2207` | `open` | Eval/Research | Red-team style scorecard for practical analyst lift |
| E11-S8 Frontier-v2 Decision Packet | `2208` | `open` | Release/Validation | Final packet, rollout playbook, and residual risk register |

### E11 Dependency Graph

```mermaid
flowchart LR
    E10DONE["2108 E10 complete"] --> U1["2201 E11-S1"]
    U1 --> U2["2202 E11-S2"]
    U1 --> U3["2203 E11-S3"]
    U1 --> U4["2204 E11-S4"]
    U1 --> U5["2205 E11-S5"]

    U2 --> U6["2206 E11-S6"]
    U3 --> U6
    U4 --> U6

    U2 --> U7["2207 E11-S7"]
    U3 --> U7
    U4 --> U7
    U5 --> U7

    U6 --> U8["2208 E11-S8"]
    U7 --> U8
```

### E11 Dispatch Waves

1. Wave 0: `2201`
2. Wave 1 (parallel): `2202`, `2203`, `2204`, `2205`
3. Wave 2 (parallel): `2206`, `2207`
4. Wave 3: `2208`
