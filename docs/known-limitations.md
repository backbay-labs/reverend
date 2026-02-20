# Known Limitations — RC1

**Version:** 0.1.0-rc1
**Date:** 2026-02-20

This document lists known limitations, constraints, and caveats for the Alien-Tech MVP release candidate. Items are grouped by subsystem.

---

## 1. Collaboration and Review

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-01 | Review server is a separate deployment; not bundled in the Ghidra distribution. | Operators must deploy and maintain the review server independently. | Use the review server Docker image from the platform repository. |
| L-02 | Real-time co-editing is not supported. The collaboration model is async-first (PR-like). | Analysts cannot see each other's in-progress edits. | Coordinate via changeset titles and review queue. |
| L-03 | Branching is limited to one level (no branch-from-branch). | Complex exploratory workflows may require manual branch management. | Create branches only from the main line. |
| L-04 | Conflict auto-resolution rules are project-global; per-function or per-module overrides are not supported. | Teams with heterogeneous review policies must use the broadest rule set. | Override individual conflicts manually during merge. |

## 2. Receipts and Rollback

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-05 | Receipt store is append-only SQLite on local disk. No built-in replication. | Single point of failure for receipt data. | Back up the receipt database regularly. |
| L-06 | Rollback of a partial changeset (some deltas applied, others not) may leave evidence links in an inconsistent display state until the review server re-indexes. | Temporary UI inconsistency after partial rollback. | Trigger a manual re-index on the review server. |
| L-07 | Receipt hash-chain verification runs synchronously; large chains (> 100 K receipts) may cause noticeable latency. | Slow startup on long-running projects. | Archive old receipts periodically. |

## 3. Semantic Search

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-08 | Search quality targets (Recall@10 ≥ baseline + 10 %) are measured on the curated eval set only; results on novel binaries may vary. | Search quality is not guaranteed on out-of-distribution binaries. | Report unexpected results; they will improve the eval set. |
| L-09 | Index build is single-threaded. Indexing a 100 K-function binary takes significant time on first run. | Initial analysis setup is slow for large binaries. | Pre-build the index via headless mode during off-hours. |
| L-10 | Embedding model is local-only in `offline` mode. Quality may be lower than cloud-hosted models. | Reduced search accuracy in air-gapped environments. | Switch to `allowlist` or `cloud` mode if network access is permitted. |

## 4. Triage Crew

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-11 | Triage Crew v1 is deterministic and rule-based; no ML model inference. | Entrypoint/hotspot detection relies on pattern matching, not learned models. | Supplement triage output with manual review for unusual binaries. |
| L-12 | Rule set is tuned for x86/x86_64 and ARM binaries. Other architectures (MIPS, PPC, RISC-V) have reduced triage accuracy. | Analysts working on niche architectures get less useful triage maps. | Contribute architecture-specific rules to the rule set. |
| L-13 | Triage confidence scores are heuristic; no calibration guarantee across different binary families. | Confidence 0.8 in one binary family may not mean the same as 0.8 in another. | Treat confidence as relative ranking, not absolute probability. |

## 5. Type PR Lifecycle

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-14 | Type suggestion generator is limited to high-confidence primitives and known library signatures. | Complex custom struct recovery is not automated. | Manually define and propose struct types via the standard annotation workflow. |
| L-15 | Type propagation is intra-program only. Cross-binary type sharing requires manual export/import via corpus sync. | Type work is duplicated across related binaries. | Use corpus sync to share approved type definitions. |
| L-16 | Type PR atomic apply depends on PostgreSQL `FOR UPDATE` row locking. SQLite fallback mode does not support concurrent reviewers on the same Type PR. | Only one reviewer can act on a Type PR at a time in SQLite mode. | Deploy PostgreSQL for multi-reviewer environments. |

## 6. Corpus Sync

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-17 | Corpus sync is pilot-grade: single-node, no horizontal scaling. | Not suitable for large team deployments (> 10 concurrent analysts). | Limit pilot to small teams; scale after GA. |
| L-18 | Sync is approved-only; rejected or draft proposals are not synced. | Rejected proposals cannot be shared as negative examples. | Export rejected proposals manually if needed. |
| L-19 | Provenance checks enforce access control but do not verify artifact integrity end-to-end (no content-addressable storage yet). | A compromised sync server could serve tampered artifacts. | Verify critical artifacts against receipt hashes. |

## 7. Security

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-20 | Agent sandbox relies on JVM-level isolation and capability tokens. No OS-level sandboxing (seccomp, AppArmor) is enforced by default. | A JVM escape or Ghidra API exploit could bypass agent isolation. | Deploy Ghidra in a container with OS-level restrictions for high-security environments. |
| L-21 | API key rotation must be done manually. No built-in key lifecycle management. | Stale keys accumulate over time. | Integrate with external secret management (Vault, AWS Secrets Manager). |
| L-22 | Security regression suite covers known attack patterns from the STRIDE analysis but not all possible evasion techniques. | Novel attack vectors may not be caught. | Update the regression suite as new threats are identified. |

## 8. Infrastructure and Build

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-23 | Cyntra workcells are git worktrees; each consumes significant disk for the Ghidra checkout. | Disk usage scales linearly with concurrent workcells. | Limit `max_concurrent_workcells` (default: 3) and run cleanup regularly. |
| L-24 | Native component builds (decompiler) require a C/C++ toolchain. Pre-built binaries are not distributed for all platforms. | Operators on less common platforms must build from source. | Use the `gradle buildNatives` target with the platform's native toolchain. |
| L-25 | Headless/CI testing on Linux requires Xvfb for GUI-dependent tests. | Tests may fail without a display server. | Start `Xvfb :99 -nolisten tcp &` and `export DISPLAY=:99` before test runs. |

## 9. Documentation

| ID | Limitation | Impact | Workaround |
|---|---|---|---|
| L-26 | Research documents (`docs/research/*.md`) are in Draft status. Some claims lack explicit source footnotes. | Readers should cross-reference `docs/claims-ledger.md` and `docs/sources.md` for verification. | Promote claims to the claims ledger before operational reliance. |
| L-27 | Legal compliance playbook (`docs/research/legal-compliance-playbook.md`) is a template. It has not been reviewed by counsel. | Do not rely on legal guidance without independent legal review. | Engage counsel before operational deployment in regulated environments. |

---

## Reporting New Limitations

If you discover a limitation not listed here:
1. File an issue in the project backlog with the `known-limitation` label.
2. Include: observed behavior, expected behavior, reproduction steps, and workaround (if any).
3. Reference this document by limitation ID if related to an existing entry.
