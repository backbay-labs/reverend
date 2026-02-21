# Abuse Scenario Suite Evidence (Issue 1702)

Executed: 2026-02-21T06:29:42+00:00
Branch: `unknown`
Workcell: `unknown`

## Execution

Run from repository root:

```bash
python3 scripts/security/run_abuse_scenario_suite.py --issue-id 1702 --output-dir docs/security/evidence/abuse-scenario-suite-1702
```

## Scenario Evidence Files

| Scenario | Command evidence | Additional artifact(s) |
|---|---|---|
| S1 - Direct or indirect agent write attempt to canonical corpus state | `scenario-01-no-direct-agent-write.log` | `no-direct-agent-write/no-direct-agent-write-invariant.json`, `no-direct-agent-write/no-direct-agent-write-invariant.md` |
| S2 - Egress policy bypass by targeting non-allowlisted cloud endpoint | `scenario-02-allowlist-egress.log` | — |
| S3 - Project-level policy override bypass (offline project tries remote sync) | `scenario-03-policy-mode-scope.log` | — |
| S4 - Provenance-chain tampering to bypass read-side trust checks | `scenario-04-provenance-chain.log` | — |
| S5 - Receipt-history tampering (mutate historic record) | `scenario-05-receipt-tamper.log` | — |

## Run Summary

- Executed scenarios: `5`
- Passed: `5`
- Failed: `0`
- Open remediation items from this run: `0`

## Integrity

SHA-256 checksums for all suite evidence files are stored in:

- `checksums.sha256`
