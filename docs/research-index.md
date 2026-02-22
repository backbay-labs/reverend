# Research and Documentation Index

## Scope
This is the live control document for research outputs in `docs/`. It tracks coverage, verification state, and publication blockers.

## Live Status (2026-02-20)
| Document | Status | Accuracy Notes |
|---|---|---|
| `docs/CHANGELOG-rc1.md` | Published | Versioned changelog for RC1 (`0.1.0-rc1`), includes packaging command (`gradle buildGhidra`), artifact path (`build/dist/ghidra_*.zip`), and checksum step. |
| `docs/operator-reviewer-runbook.md` | Published | Covers setup, review flow, rollback, incident handling, quality gates, and configuration reference for operators/reviewers. |
| `docs/known-limitations.md` | Published | 27 documented limitations across all subsystems with IDs, impact, and workarounds. |
| `docs/deep-research-report.md` | Draft | Citation artifacts removed; still needs explicit claim-to-source footnoting before final publication. |
| `docs/sources.md` | Working | Canonical reference list for time-sensitive and high-impact claims. |
| `docs/claims-ledger.md` | Working | Claim-by-claim verification tracker with status and source mapping. |
| `docs/execution-board-12-weeks.md` | Published | Concrete 12-week implementation board with owner lanes, milestones, exit gates, and Week 12 RC publication evidence links. |
| `docs/backlog-jira-linear.md` | Published | Active backlog map for epics/stories, including E9-E12 bead IDs and dependency wiring. |
| `docs/backlog-e9.csv` | Published | Jira/Linear import-ready CSV for E9-S1..E9-S8 execution set. |
| `docs/cyntra-kernel-runbook.md` | Working | Operational runbook for executing the roadmap in Cyntra against `.beads/` graph files. |
| `docs/e9-frontier-roadmap.md` | Published | Post-RC frontier/productization/expansion/native-integration board with research cross-reference, wave plan, and dependency graph for E9-S1..E12-S8. |
| `docs/research/INDEX.md` | Draft | Good map; depends on per-topic docs for claim-level verification. |
| `docs/research/ghidra-internals-architecture.md` | Draft | Core structural claims spot-checked against repo paths/classes and look consistent. |
| `docs/research/decompilation-type-recovery.md` | Draft | Dense research references; needs focused pass on benchmark naming consistency. |
| `docs/research/binary-similarity-semantic-search.md` | Draft | Strong synthesis; time-sensitive product claims should carry "as-of" dates. |
| `docs/research/diffing-matching-deobfuscation.md` | Draft | Good coverage; interoperability/tool status claims should be revalidated before publish. |
| `docs/research/symbolic-execution-fuzzing-dynamic.md` | Draft | Source-rich; verify "latest" framing and successor language for fuzzing tools. |
| `docs/research/ecosystem-plugins-firmware.md` | Draft | Highest churn risk (plugins/pricing/maintenance status). Revalidate near publish date. |
| `docs/research/ai-assisted-reverse-engineering.md` | Draft | Broad coverage; highest drift risk in model/plugin ecosystem details. |
| `docs/research/binary-rewriting-transformation.md` | Draft | Good architecture survey; benchmark/perf deltas should be treated as source-reported. |
| `docs/research/malware-analysis-anti-analysis.md` | Draft | Practical pipeline content; vendor capability and success-rate claims need periodic refresh. |
| `docs/research/vulnerability-discovery-exploit-dev.md` | Draft | High-value techniques; verify exploit/CVE/tool-maintenance claims before operational use. |
| `docs/research/collaboration-review-design.md` | Draft | Good design coverage; verify Ghidra interface path references against release tags before publish. |
| `docs/research/analysis-data-plane-spec.md` | Draft | Detailed spec and DDL; storage/sizing assumptions should be benchmarked on representative corpora. |
| `docs/research/agent-runtime-security-spec.md` | Draft | Strong threat model; revalidate sandbox/control recommendations against deployment OS constraints. |
| `docs/research/corpus-kb-architecture.md` | Draft | Strong operational model; throughput/latency targets are estimates pending measurement. |
| `docs/research/type-lifecycle-ux.md` | Draft | Covers governance and review flows; needs claim mapping for external benchmark references. |
| `docs/research/dynamic-static-evidence-model.md` | Draft | Strong schema and UI model; validate trace-volume assumptions with real workloads. |
| `docs/research/legal-compliance-playbook.md` | Draft | Useful template; requires counsel review and dated legal-source checks before operational use. |
| `docs/research/evaluation-harness.md` | Draft | Comprehensive metric matrix; target thresholds should be treated as provisional until baseline runs exist. |
| `docs/research/python-integration-ops-matrix.md` | Draft | High practical value; version/platform claims are high churn and need near-publication recheck. |

## Current QA Snapshot
- RC1 release-doc bundle is explicit and cross-linked: `docs/CHANGELOG-rc1.md`, `docs/operator-reviewer-runbook.md`, `docs/known-limitations.md`.
- `docs/deep-research-report.md`: unresolved citation artifacts removed; verify claim-to-source mapping via companion docs before publication.
- `docs/research/*.md`: `0` unresolved citation artifacts; explicit links present.
- Local markdown links across `docs/`: no broken local links detected in this pass.
- Verification-note banner present across all `docs/research/*.md` files.

## Immediate Accuracy Priorities
1. Add explicit claim-to-source footnotes in `docs/deep-research-report.md` using `docs/sources.md` and `docs/claims-ledger.md`.
2. Promote high-impact factual claims from new spec docs (legal, Python compatibility, security controls) into `docs/claims-ledger.md`.
3. Add concrete "as-of" dates for pricing/version/maintenance claims across research docs.
4. Normalize naming collisions (e.g., similarly named benchmarks/tools) and link each claim to one canonical source.
5. Keep `docs/e9-frontier-roadmap.md` synchronized with `.beads/issues.jsonl` IDs (`2001-2308`) before each Cyntra dispatch wave.

## Source Hierarchy
- Official vendor/project docs and release notes.
- This repository's source and docs for Ghidra-internal claims.
- Peer-reviewed papers for research assertions.
- Primary legal/government sources for legal/policy statements.

## Publish Gate
- Every material claim has at least one explicit link.
- No unresolved citation artifacts remain.
- Time-sensitive facts include explicit date context.
- Analytical recommendations are clearly separated from factual statements.
