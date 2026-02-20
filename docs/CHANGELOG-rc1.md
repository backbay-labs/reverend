# Changelog — Release Candidate 1 (RC1)

**Version:** 0.1.0-rc1
**Date:** 2026-02-20
**Codename:** Alien-Tech MVP
**Status:** Release Candidate

---

## Summary

First release candidate for the Ghidra "Alien-Tech" MVP vertical slice. This RC delivers an end-to-end workflow: binary import → triage map → rename/type/comment proposals with receipts → reviewer accept/reject → reversible apply → corpus knowledge-base sync.

---

## Features

### E1 — Evaluation Foundation (Weeks 1–3)
- Evaluation harness skeleton integrated into CI.
- Pinned datasets and deterministic baseline scripts.
- Per-commit smoke metrics and MVP gate dashboard with alerts (`eval/scripts/mvp_gate_dashboard.py`).
- Baseline metric report v1 published as CI artifact.

### E2 — Receipts and Proposal Workflow (Weeks 2–6)
- Receipt append-only store with hash-chain verification (BE-101).
- Proposal state machine: `proposed → approved → rejected`.
- Transaction-linked receipt writer for all auto-applied mutations.
- Proposal apply/rollback transaction adapter for Ghidra (BE-118).
- Review actions: approve, reject, bulk operations.
- Rollback chain and idempotent apply API.
- Delta diff renderer (before/after) in proposal inbox panel.
- Evidence-link storage for xrefs, strings, and callsites.

### E3 — Capability Guard and Policy Modes (Weeks 2–7)
- Token-scoped capability permissions enforced at tool-call boundary.
- Policy mode configuration: `offline`, `allowlist`, `cloud`.
- MCP/tool-call capability guard middleware (SEC-401).
- Endpoint allowlist enforcement (SEC-417).
- Permission audit logging.
- Sandbox boundary tests for plugin and agent isolation.

### E4 — Local Semantic Search (Weeks 4–8)
- Local embedding pipeline v1 with configurable model backends.
- Similarity index and top-k retrieval API.
- Semantic search panel (`intent` + `similar`) in Ghidra UI.
- Re-ranker using evidence weights.
- Performance tuning: index build/query optimized for p95 < 300 ms on 100K-function index.

### E5 — Triage Crew v1 (Weeks 7–10)
- Deterministic triage rule set v1: entrypoints, config, crypto, network patterns.
- Mission output: triage map, ranked hotspots, unknowns, evidence references.
- Triage scoring calibration against curated eval set.
- Cross-binary reuse heuristics v1.

### E6 — Type PR Lifecycle v1 (Weeks 8–11)
- Type assertion persistence with propagation hooks.
- Type PR list/detail/review panel.
- Type suggestion generator v1 (high-confidence primitives + signatures).
- Type assertions flow: `proposed → reviewed → accepted → propagated`.
- Atomic server-side apply for Type PR decisions with receipt linking.

### E7 — Corpus Sync Pilot (Weeks 10–12)
- Corpus sync worker: approved-only artifacts pushed to shared store.
- Sync status and provenance UI.
- Access control and provenance checks enforced on sync path.
- Corpus pilot benchmark run completed.

### E8 — Hardening and Release Candidate (Weeks 11–12)
- Schema and API frozen.
- Security regression suite v1 and pen-test-style abuse scenarios executed.
- Full regression and soak run completed.
- Operator and reviewer runbook published.
- Security sign-off checklist completed.
- Exit-gate validation report generated.

---

## MVP Exit-Gate Status

| Gate | Target | RC1 Status |
|---|---|---|
| Receipt completeness | 100 % for all auto-applied mutations | Pass |
| Rollback success | 100 % for approved batch apply/undo | Pass |
| Search latency | p95 < 300 ms on local 100K-function index | Pass |
| Search quality | Recall@10 ≥ stock baseline + 10 % | Pass |
| Triage quality | Entrypoint/hotspot recall ≥ 85 % | Pass |
| Security | No direct agent write to canonical state | Pass |
| CI stability | Per-commit smoke + nightly regression green 7 days | Pass |

---

## Infrastructure

- **JDK:** 21 (64-bit)
- **Gradle:** 8.5+
- **Python:** 3.9–3.14
- **Protobuf (Java):** 4.31.0
- **Build target:** `gradle buildGhidra` → `build/dist/`

---

## Release Candidate Package

RC1 packaging is tied to the version `0.1.0-rc1` and published with its release documentation bundle.

```bash
# Build installable distribution archive(s)
gradle buildGhidra

# Select the packaged archive and compute checksum for release notes/signoff
artifact="$(ls -1 build/dist/ghidra_*.zip | head -n 1)"
shasum -a 256 "${artifact}"
```

Release bundle contents:
- Installable archive: `build/dist/ghidra_*.zip`
- Versioned changelog: `docs/CHANGELOG-rc1.md`
- Operator/reviewer runbook: `docs/operator-reviewer-runbook.md`
- Known limitations: `docs/known-limitations.md`

---

## Known Limitations

See [`docs/known-limitations.md`](known-limitations.md) for the full list.

Key items:
- Collaboration features require a running review server (not bundled in this RC).
- Type PR lifecycle limited to high-confidence primitives and signatures.
- Corpus sync is pilot-grade; single-node only.
- Triage Crew is deterministic rule-based; no ML model inference in this release.
- Search quality targets measured on curated eval set only.

---

## Migration Notes

This is the first release candidate; no prior version to migrate from.

---

## Next Steps

- Collect operator/reviewer feedback during RC1 evaluation period.
- Address any P0 issues discovered during exit-gate validation.
- Cut final release (v0.1.0) after RC1 sign-off.
