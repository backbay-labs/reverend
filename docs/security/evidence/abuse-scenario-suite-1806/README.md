# Abuse Scenario Suite Evidence (Issue 1806)

Executed: 2026-02-21 (UTC)
Branch: `wc/1806/20260221T003808Z`
Workcell: `wc-1806-20260221T003808Z`

## Scenario Evidence Files

| Scenario | Command Evidence | Additional Artifact |
|---|---|---|
| S1 - No direct agent write invariant | `scenario-01-no-direct-agent-write.log` | `no-direct-agent-write/no-direct-agent-write-invariant.json`, `no-direct-agent-write/no-direct-agent-write-invariant.md` |
| S2 - Allowlist egress block | `scenario-02-allowlist-egress.log` | `scripts/ml/tests/test_corpus_sync_worker.py` |
| S3 - Per-project policy mode enforcement | `scenario-03-policy-mode-scope.log` | `scripts/ml/tests/test_corpus_sync_worker.py` |
| S4 - Provenance chain rejection | `scenario-04-provenance-chain.log` | `scripts/ml/tests/test_corpus_sync_worker.py` |
| S5 - Receipt tamper detection | `scenario-05-receipt-tamper.log` | `scripts/ml/tests/test_receipt_store.py` |

## Integrity

SHA-256 checksums for all suite evidence files are stored in:

- `checksums.sha256`
