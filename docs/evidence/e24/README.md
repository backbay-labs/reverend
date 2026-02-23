# E24 Provenance Chain Verifier + Explainability Packet

This directory tracks the evidence contract for `E24-S4`.

## Artifact Contract

- Machine-readable verifier report:
  - `kind: "provenance_chain_verification_report"`
  - `ok` + `issue_count` + `issues[]`
  - `explainability_packet.kind: "applied_proposal_explainability_packet"`
  - `explainability_packet.applied_proposals[].canonical_chain[]`

## Verifier Command

```bash
python3 scripts/ml/receipt_store.py verify-provenance \
  --store /path/to/receipts.json \
  --output docs/evidence/e24/provenance-verifier-report.json
```

Gate behavior:
- Exit code `0`: provenance links and receipt integrity are valid.
- Exit code `1`: verifier found missing/broken provenance links or receipt integrity issues.

## Notes

- The verifier checks receipt hash-chain integrity first, then enforces provenance continuity from canonical raw-signal evidence entities (`static`, `dynamic`, `symbolic`, `taint`) to each applied proposal.
- The explainability packet emits one canonical chain per applied proposal.
