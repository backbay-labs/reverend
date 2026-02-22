# Jira/Linear Backlog Map

Canonical backlog source of truth is `.beads/issues.jsonl` plus `.beads/deps.jsonl`.

## Program Epics

| Epic | Bead ID | Status |
|---|---|---|
| E1-E8 MVP + RC | `1000-1700` | Done |
| R1-R2 Remediation | `1800-1900` | Done |
| E9 Frontier SOTA Buildout | `2000` | Done |
| E10 Exosuit Productization + Real-World Lift | `2100` | Done |
| E11 SOTA Engine Expansion + Adversarial RE Lift | `2200` | Done |
| E12 Native SOTA RE Core + Real-Target Validation | `2300` | Blocked (story queue seeded) |

## E9 Story Index

| Story | Bead ID | Current Status | Parent |
|---|---|---|---|
| E9-S1: Knowledge graph foundation | `2001` | `done` | `2000` |
| E9-S2: Intent + similarity retrieval | `2002` | `done` | `2000` |
| E9-S3: Evidence-backed auto-annotation | `2003` | `done` | `2000` |
| E9-S4: Type recovery + propagation | `2004` | `done` | `2000` |
| E9-S5: Dynamic-static fusion overlays | `2005` | `done` | `2000` |
| E9-S6: Deterministic autopilot crews | `2006` | `done` | `2000` |
| E9-S7: Cross-binary learning codebook | `2007` | `done` | `2000` |
| E9-S8: Spec extraction + review packets | `2008` | `done` | `2000` |

## E10 Story Index

| Story | Bead ID | Current Status | Parent |
|---|---|---|---|
| E10-S1: Semantic query cockpit panel | `2101` | `done` | `2100` |
| E10-S2: Ranked mission hotspot map | `2102` | `done` | `2100` |
| E10-S3: Proposal review inbox + safe rollback | `2103` | `done` | `2100` |
| E10-S4: Corpus retrieval hardening (non-toy) | `2104` | `done` | `2100` |
| E10-S5: Multi-source trace adapter pack | `2105` | `done` | `2100` |
| E10-S6: Deterministic mission orchestrator | `2106` | `done` | `2100` |
| E10-S7: Real-world benchmark lift suite | `2107` | `done` | `2100` |
| E10-S8: GA readiness packet + demo flow | `2108` | `done` | `2100` |

## E11 Story Index

| Story | Bead ID | Current Status | Parent |
|---|---|---|---|
| E11-S1: Semantic diff narrative + change-impact graph | `2201` | `done` | `2200` |
| E11-S2: Deterministic deobfuscation detectors/transforms | `2202` | `done` | `2200` |
| E11-S3: Symbolic evidence bridge + overlays | `2203` | `done` | `2200` |
| E11-S4: Fuzz harness synthesis + coverage sync | `2204` | `done` | `2200` |
| E11-S5: Firmware/IoT corpus-to-mission pipeline | `2205` | `done` | `2200` |
| E11-S6: Multi-analyst branch/merge review topology | `2206` | `done` | `2200` |
| E11-S7: Adversarial benchmark lift scorecard | `2207` | `done` | `2200` |
| E11-S8: Frontier-v2 decision packet + playbook | `2208` | `done` | `2200` |

## E12 Story Index

| Story | Bead ID | Current Status | Parent |
|---|---|---|---|
| E12-S1: P-code/CFG/SSA extractor + persisted KG | `2301` | `done` | `2300` |
| E12-S2: Hybrid vector+symbolic retrieval + reranking | `2302` | `open` | `2300` |
| E12-S3: Semantic cockpit v2 + evidence drilldown | `2303` | `open` | `2300` |
| E12-S4: Interprocedural type inference v2 | `2304` | `open` | `2300` |
| E12-S5: Dynamic ingest adapters + timeline overlays | `2305` | `open` | `2300` |
| E12-S6: Deterministic mission DAG + signed packs | `2306` | `open` | `2300` |
| E12-S7: Pullback governance + merge policy scoring | `2307` | `open` | `2300` |
| E12-S8: Real-target lift campaign + GA3 packet | `2308` | `open` | `2300` |

## Dependency Edges

```text
1909 -> 2001
2001 -> 2002, 2003, 2005
2003 -> 2004
2002,2003,2005 -> 2006
2002,2004 -> 2007
2006,2007 -> 2008

2008 -> 2101
2101 -> 2102,2103,2104,2105
2102,2103,2104,2105 -> 2106
2104,2105 -> 2107
2106,2107 -> 2108

2108 -> 2201
2201 -> 2202,2203,2204,2205
2202,2203,2204 -> 2206
2202,2203,2204,2205 -> 2207
2206,2207 -> 2208

2208 -> 2301
2301 -> 2302,2303,2304,2305
2302,2303,2304,2305 -> 2306
2302,2304 -> 2307
2306,2307 -> 2308
```

## Research References

- `docs/e9-frontier-roadmap.md`
- `docs/deep-research-report.md`
- `docs/research/INDEX.md`
- `docs/research/analysis-data-plane-spec.md`
- `docs/research/binary-similarity-semantic-search.md`
- `docs/research/decompilation-type-recovery.md`
- `docs/research/dynamic-static-evidence-model.md`
