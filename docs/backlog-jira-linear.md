# Jira/Linear Backlog Map

Canonical backlog source of truth is `.beads/issues.jsonl` plus `.beads/deps.jsonl`.

## Program Epics

| Epic | Bead ID | Status |
|---|---|---|
| E1-E8 MVP + RC | `1000-1700` | Done |
| R1-R2 Remediation | `1800-1900` | Done |
| E9 Frontier SOTA Buildout | `2000` | Open |

## E9 Story Index

| Story | Bead ID | Initial Status | Parent |
|---|---|---|---|
| E9-S1: Knowledge graph foundation | `2001` | `ready` | `2000` |
| E9-S2: Intent + similarity retrieval | `2002` | `open` | `2000` |
| E9-S3: Evidence-backed auto-annotation | `2003` | `open` | `2000` |
| E9-S4: Type recovery + propagation | `2004` | `open` | `2000` |
| E9-S5: Dynamic-static fusion overlays | `2005` | `open` | `2000` |
| E9-S6: Deterministic autopilot crews | `2006` | `open` | `2000` |
| E9-S7: Cross-binary learning codebook | `2007` | `open` | `2000` |
| E9-S8: Spec extraction + review packets | `2008` | `open` | `2000` |

## Dependency Edges

```text
1909 -> 2001
2001 -> 2002, 2003, 2005
2003 -> 2004
2002,2003,2005 -> 2006
2002,2004 -> 2007
2006,2007 -> 2008
```

## Research References

- `docs/e9-frontier-roadmap.md`
- `docs/deep-research-report.md`
- `docs/research/INDEX.md`
- `docs/research/analysis-data-plane-spec.md`
- `docs/research/binary-similarity-semantic-search.md`
- `docs/research/decompilation-type-recovery.md`
- `docs/research/dynamic-static-evidence-model.md`
