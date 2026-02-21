# Security Signoff Checklist

> Versioned security signoff for the agent runtime architecture.
>
> **Spec under review**: `docs/research/agent-runtime-security-spec.md` (v1, 2026-02-19)
> **Compliance reference**: `docs/research/legal-compliance-playbook.md` (v1.0, 2026-02-19)
> **Abuse scenario results**: `docs/security/abuse-scenario-suite.md` (v1.3, 2026-02-21)
> **Review date**: 2026-02-21
> **Review scope**: E8-S2 reopened executable abuse-scenario rerun (Issue 1702) with prior rerun continuity check (Issue 1806)

---

## 1. Threat Model Review

- [x] STRIDE analysis covers all six threat categories (Spoofing, Tampering,
      Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- [x] Threat actors identified with motivations, capabilities, and entry points
      (6 actors: malicious binary author, compromised model provider, rogue plugin,
      network adversary, malicious insider, compromised dependency)
- [x] Attack surface diagram documents all trust boundaries
- [x] 13 threats enumerated in STRIDE threat matrix with impact and likelihood ratings
- [x] Each threat has at least one specified mitigation
- [x] Residual risk documented for each threat after mitigation

## 2. Permission Model

- [x] Capability-based architecture follows principle of least privilege
- [x] Permission hierarchy defined (ADMIN > WRITE > READ > EXECUTE with sub-capabilities)
- [x] Five permission profiles defined (Observer, Annotator, Analyst, Engineer, Admin)
- [x] Token-based scoping with expiry, principal binding, and program restrictions
- [x] Enforcement mapped to Ghidra API interposition points (4 enforcement points:
      MCP Server, Plugin API wrapper, Script sandbox, Receipt builder)
- [x] CapabilityGuard implementation pattern specified with code examples

## 3. Egress Controls

- [x] Default-deny network policy with explicit allow-list
- [x] Four-layer enforcement (application, process, host firewall, network proxy)
- [x] Allow-list configuration format specified with TLS requirements
- [x] Blocked patterns include common exfiltration destinations
- [x] Data exfiltration detection heuristics defined (6 signals: payload size,
      request rate, content type, destination, prompt structure, binary coverage)
- [x] EgressMonitor implementation pattern specified with code example
- [x] Organizational proxy architecture documented (mTLS, DLP, key injection, audit)
- [x] Air-gapped deployment mode specified with offline model update mechanism

## 4. Secrets Handling

- [x] API key storage hierarchy defined (OS keychain > encrypted config > env var > proxy)
- [x] OS keychain integration pattern specified for macOS/Windows/Linux
- [x] Key rotation policies defined (automatic 30-day, manual, per-session)
- [x] Organizational key proxy architecture eliminates direct key handling
- [x] Five secrets hygiene rules: never in logs, receipts, error messages, VCS, or
      long-lived memory
- [x] Pre-commit hook scanning for key patterns specified

## 5. Sandbox Boundaries

- [x] Process isolation architecture separates Ghidra, MCP server, and inference
- [x] Linux sandboxing via systemd + seccomp specified (filesystem, network, syscalls,
      resources)
- [x] macOS sandboxing via sandbox-exec profile specified
- [x] Container-based isolation via Docker Compose specified (read-only, no privileges,
      resource limits)
- [x] Timeout enforcement table covers all operation types (5 categories with defaults
      and maximums)
- [x] MCP server sandboxing requirements: manifest, consent, runtime enforcement,
      least privilege, update verification

## 6. Enforcement Architecture

- [x] Post-SecurityManager strategy addresses JDK 17+ deprecation
- [x] Three options specified: process isolation (recommended), custom classloader,
      bytecode rewriting
- [x] ProcessBuilder sandboxing with environment sanitization
- [x] Network namespace isolation for Linux documented with script
- [x] Audit logging pipeline: 5 event sources, structured event bus, 3 outputs
      (local log, alert engine, SIEM export)
- [x] Audit event schema specified with 8 critical event types
- [x] Implementation priority order defined (8 phases from receipts to plugin signing)

## 7. Abuse Scenario Execution

- [x] All 5 primary attack scenarios from spec Section 6 executed as runtime regression checks
- [x] Executable harness is versioned at `scripts/security/run_abuse_scenario_suite.py`
- [x] Scenario logs, machine-readable outcomes, and checksums are stored in
      `docs/security/evidence/abuse-scenario-suite-1702/`
- [x] 8 additional STRIDE scenarios are documented as **legacy tabletop** coverage
      (non-executable appendix)
- [x] 13 total scenarios documented (`5` executable runtime + `8` legacy tabletop),
      with executable outcomes tracked in `scenario-outcomes.json`
- [x] Zero critical findings requiring immediate remediation
- [x] Five findings with MEDIUM residual risk formally accepted (T1: prompt injection,
      T3: cloud exfiltration, T5: compromised weights, T9: hallucination,
      T10: plugin/dependency supply chain)
- [x] Eight findings with LOW residual risk formally accepted
- [x] OWASP Top 10 for LLM Applications 2025 cross-referenced (9/10 covered, 1 N/A)
- [x] OWASP Top 10 for Agentic Applications 2026 cross-referenced (10/10 covered)

## 8. Legal and Compliance Coverage

- [x] DMCA/anti-circumvention decision tree provided with 2024 triennial exemption status
- [x] CFAA good-faith security research documentation requirements specified
- [x] EU Directive 2009/24/EC interoperability decompilation rights documented
- [x] Data classification tiers (T1-T4) with cloud vs. offline policy templates
- [x] GDPR implications for binary analysis addressed (PII in binaries, cross-border transfers)
- [x] Audit requirements mapped to NIST SP 800-53 Rev 5 controls (14 controls)
- [x] Export control considerations documented (EAR, ITAR, encryption, Wassenaar)
- [x] Organizational deployment checklist covers 6 phases (legal, data handling,
      technical controls, incident response, training, ongoing compliance)

## 9. Residual Risk Summary

| Risk Level | Count | Threat IDs | Disposition |
|------------|-------|------------|-------------|
| **Low** | 8 | T2, T4, T6, T7, T8, T11, T12, T13 | Accepted |
| **Medium** | 5 | T1, T3, T5, T9, T10 | Accepted with justification |
| **High** | 0 | — | — |
| **Critical** | 0 | — | — |

All MEDIUM residual risks are inherent limitations of LLM-based systems
(prompt injection, hallucination, cloud data exposure, model supply chain)
where defense-in-depth is applied but cannot fully eliminate the risk.
These are consistent with industry-standard risk posture for AI/agent
systems per OWASP, NIST AI RMF, and BSI/ANSSI guidance.

## 10. Open Items and Conditions

| Item | Status | Condition |
|------|--------|-----------|
| Implementation of CapabilityGuard | Pending | Must be completed before agent runtime deployment |
| Receipt system with hash chain | Pending | Prerequisite for all other enforcement (Phase 1) |
| Egress allow-list implementation | Pending | Required before cloud API usage in production |
| OS keychain integration | Pending | Required before API key provisioning |
| Process-level sandboxing | Pending | Required before MCP server deployment |
| Plugin manifest/signing ecosystem | Pending | Longer-term; required before third-party plugin approval |
| Periodic benchmark evaluation | Pending | Required for ongoing detection of model bias (T5) |
| Penetration testing of implementation | Pending | Required at implementation phase gate |

**Signoff is conditional on**: implementation of the architectural controls
specified in the security spec, verified by penetration testing at the
implementation phase gate (E8-S3 or equivalent).

---

## 11. Issue 1702 Signoff Record (2026-02-21)

| Approver | Date | Decision | Unresolved-risk notes |
|------|------|------|--------|
| Security review (automated evidence review) | 2026-02-21 | **Approved (conditional)** | Medium residual threats `T1`, `T3`, `T5`, `T9`, and `T10` remain accepted as inherent LLM/system constraints with required compensating controls; all implementation-phase open items in Section 10 stay mandatory. |

---

## Signoff

| Role | Name | Date | Status |
|------|------|------|--------|
| Security review (automated) | E8-S2 / Issue 1702 (reopen rerun) | 2026-02-21 | **Approved (conditional)** |
| Architecture review | — | — | Pending |
| Legal review | — | — | Pending |
| CISO/Security lead | — | — | Pending |

**Approval basis**: The agent runtime security architecture provides
comprehensive coverage of identified threats through defense-in-depth.
All 13 adversarial scenarios have documented mitigations. No unaddressed
critical or high-severity findings. Five MEDIUM residual risks are
formally accepted as inherent to LLM-based systems with appropriate
compensating controls.

**Approval condition**: This signoff covers the *architectural design*.
Implementation must be verified separately through code review and
penetration testing before production deployment.

---

> **Document version**: 1.2
> **Classification**: Internal — Security Review
> **Next review**: At implementation phase gate
> **Supersedes**: v1.1 (2026-02-20)
