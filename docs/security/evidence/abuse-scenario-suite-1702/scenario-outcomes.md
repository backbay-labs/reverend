# Abuse Scenario Outcomes (Issue 1702)

- Executed: `2026-02-21T06:29:42+00:00`
- Spec under test: `docs/research/agent-runtime-security-spec.md`
- Compliance reference: `docs/research/legal-compliance-playbook.md`

## Summary

- Total scenarios: `5`
- Passed: `5`
- Failed: `0`
- Open remediations: `0`

## Scenario Matrix

| ID | Scenario | Status | Expected controls | Observed controls | Remediation if failed |
|---|---|---|---|---|---|
| S1 | Direct or indirect agent write attempt to canonical corpus state | **PASS** | Capability checks deny unauthorized sync writes and emit paired corpus_access_audit + corpus_violation_incident records. | Invariant suite returned PASS for all checks; unauthorized write paths were denied before backend/state mutation. | Restore fail-closed authorization in scripts/ml/corpus_sync_worker.py (WRITE.CORPUS_SYNC precheck plus deny/audit emission on violation). |
| S2 | Egress policy bypass by targeting non-allowlisted cloud endpoint | **PASS** | allowlist mode blocks non-approved destinations and emits deterministic EGRESS_BLOCKED incident remediation. | Allowlist-mode blocking test passed and recorded deterministic block behavior. | Re-enable endpoint allowlist matching and EGRESS_BLOCKED incident emission in scripts/ml/corpus_sync_worker.py. |
| S3 | Project-level policy override bypass (offline project tries remote sync) | **PASS** | Per-project policy modes override defaults; offline project is denied while cloud project may proceed. | Per-project mode scoping test passed; offline-deny semantics remained enforced. | Repair project policy resolution in EndpointPolicyConfig/EndpointPolicyRule to preserve offline deny semantics. |
| S4 | Provenance-chain tampering to bypass read-side trust checks | **PASS** | Read path rejects malformed chain continuity and emits PROVENANCE_CHAIN_INVALID deny audit. | Provenance continuity validation test passed; malformed artifacts were rejected. | Reinstate provenance continuity validation in scripts/ml/corpus_sync_worker.py::_validate_provenance_chain(...) and deny malformed artifacts. |
| S5 | Receipt-history tampering (mutate historic record) | **PASS** | Hash-chain integrity checks detect mutation and block further appends. | Receipt integrity tampering test passed and append was blocked on tampered state. | Restore canonical hash verification and append-time integrity guard in scripts/ml/receipt_store.py. |

## Evidence Links

- `S1` log: `docs/security/evidence/abuse-scenario-suite-1702/scenario-01-no-direct-agent-write.log`
- `S1` artifact: `docs/security/evidence/abuse-scenario-suite-1702/no-direct-agent-write/no-direct-agent-write-invariant.json`
- `S1` artifact: `docs/security/evidence/abuse-scenario-suite-1702/no-direct-agent-write/no-direct-agent-write-invariant.md`
- `S2` log: `docs/security/evidence/abuse-scenario-suite-1702/scenario-02-allowlist-egress.log`
- `S3` log: `docs/security/evidence/abuse-scenario-suite-1702/scenario-03-policy-mode-scope.log`
- `S4` log: `docs/security/evidence/abuse-scenario-suite-1702/scenario-04-provenance-chain.log`
- `S5` log: `docs/security/evidence/abuse-scenario-suite-1702/scenario-05-receipt-tamper.log`
