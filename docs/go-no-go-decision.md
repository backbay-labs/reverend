# Go/No-Go Decision — Alien-Tech MVP (v0.1.0-rc1)

**Date:** 2026-02-21
**Decision Type:** MVP Release Candidate Approval
**Epic:** E8-S4 (Issue 1704)
**Supporting Evidence:** `docs/exit-gate-report.md`

---

## 1. Decision

| | |
|---|---|
| **Decision** | **GO** |
| **Release** | v0.1.0-rc1 |
| **Scope** | Release candidate for internal evaluation and operator feedback |
| **GA status** | **NO-GO** (until conditions `C1-C11` are closed) |
| **Conditions** | Security implementation items (C1–C8) must be resolved before production deployment |

---

## 2. Rationale

### 2.1 Gate Summary

All seven MVP exit gates pass:

| Gate | Result |
|------|--------|
| Receipt completeness (100 %) | PASS |
| Rollback success (100 %) | PASS |
| Search latency (p95 < 300 ms) | PASS |
| Search quality (Recall@10 >= baseline + 10 %) | PASS |
| Triage quality (recall >= 85 %) | PASS |
| Security (no direct agent write) | PASS |
| CI stability (7-day green) | PASS |

### 2.2 Risk Posture

- **Critical/High risks:** 0
- **Medium residual risks:** 4 (prompt injection, cloud exfiltration, compromised weights, hallucination) — all inherent to LLM-based systems with defense-in-depth applied. Formally accepted.
- **Low residual risks:** 9 — all with effective mitigations in place.
- **Kill criteria:** All four execution risks from the 12-week board have been mitigated or scoped.

### 2.3 Scope Delivered

All eight epics (E1–E8) complete. The vertical slice delivers the target outcome:

1. Analyst imports a binary.
2. System generates a triage map + ranked hotspots.
3. System proposes rename/type/comment changes with receipts.
4. Reviewer accepts/rejects proposals in a PR-like flow.
5. Approved changes apply via reversible transactions.
6. Accepted artifacts can sync to a corpus knowledge base.

### 2.4 Factors Supporting GO

- End-to-end workflow operational and tested.
- Receipt and rollback guarantees verified at 100 %.
- Security architecture reviewed with no critical or high findings.
- Operator runbook and known-limitations catalog published.
- 27 known limitations documented with workarounds; none are release-blockers.

### 2.5 Factors Considered for NO-GO (Accepted)

- Security implementation conditions (C1–C8) remain open — acceptable for RC1 (architectural signoff obtained; implementation verification required before production).
- Search quality measured on curated eval set only — acceptable for MVP scope.
- Type recovery scoped to high-confidence primitives — by design (kill criterion mitigation).
- Corpus sync is pilot-grade — appropriate for initial deployment with <= 10 analysts.
- Legal compliance playbook not yet reviewed by counsel (L-27) — does not block RC1 release for internal use.

---

## 3. Conditions for Production (Post-RC1)

The following must be completed before promoting RC1 to general availability (v0.1.0):

| # | Condition | Owner | Target |
|---|-----------|-------|--------|
| C1 | CapabilityGuard implementation verified | Security | Before agent runtime deployment |
| C2 | Receipt hash-chain implementation verified | Backend | Before agent runtime deployment |
| C3 | Egress allow-list enforced | Security | Before cloud mode usage |
| C4 | OS keychain integration | Security | Before API key provisioning |
| C5 | Process-level sandboxing | Security | Before MCP server deployment |
| C6 | Plugin manifest/signing | Security | Before third-party plugins |
| C7 | Periodic benchmark evaluation established | Eval/DevOps | Before GA |
| C8 | Penetration testing completed | Security | Before GA |
| C9 | Architecture review signoff | Architecture | Before GA |
| C10 | Legal review signoff | Legal | Before GA |
| C11 | CISO/Security lead signoff | CISO | Before GA |

---

## 4. Next Steps

1. **Distribute RC1** for internal evaluation by operators and reviewers.
2. **Collect feedback** during RC1 evaluation period (target: 2 weeks).
3. **Address P0 issues** discovered during evaluation.
4. **Complete conditions C1–C11** for production readiness.
5. **Cut v0.1.0 GA** after all conditions met and RC1 feedback addressed.

---

## 5. Approvers

| Role | Approver | Date | Decision | Status |
|------|----------|------|----------|--------|
| Project Lead | Designated release owner (Issue 1704) | Pending | GO (recommended) | Pending signature |
| Security Lead | Security review owner (`docs/security/security-signoff-checklist.md`) | 2026-02-20 | GO (conditional) | Approved with conditions C1-C8 |
| Architecture Lead | Designated architecture reviewer | Pending | GO (recommended) | Pending signature |
| Eval/DevOps Lead | Designated eval/devops reviewer | Pending | GO (recommended) | Pending signature |
| Legal Lead | Designated legal reviewer | Pending | GO (internal RC1 scope only) | Pending signature |
| CISO/Security Sponsor | Designated executive approver | Pending | GO / NO-GO | Pending signature |

---

> **Document version:** 1.0
> **Classification:** Internal — Release Decision
> **Supersedes:** N/A (initial version)
