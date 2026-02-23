# E25 Signed Mission Artifact Bundles

This directory tracks the evidence contract for `E25-S3`.

## Bundle Contract

`scripts/ml/receipt_store.py pack-bundle` emits a deterministic `.tar.gz` mission bundle containing:

- `manifest.json`:
  - `kind: "mission_artifact_bundle_manifest"`
  - SHA256 checksums for `receipts.json`, `provenance-verification-report.json`, and each `artifacts/*` file
  - Signature block (`algorithm: "hmac-sha256"`, `key_id`, `digest`) over the canonical manifest payload
- `receipts.json`: append-only receipt history
- `provenance-verification-report.json`: machine-readable output of provenance verification
- `artifacts/*`: mission output files included by `--artifact`

## Pack Command

```bash
python3 scripts/ml/receipt_store.py pack-bundle \
  --store /path/to/receipts.json \
  --artifact /path/to/artifact-a.json \
  --artifact /path/to/artifact-b.json \
  --mission-id mission-e25-s3 \
  --output docs/evidence/e25/mission-bundle.tar.gz \
  --key-id ops-key-2026 \
  --signing-key-env MISSION_BUNDLE_SIGNING_KEY
```

Behavior:
- Exit code `0`: provenance checks pass and bundle is packed.
- Exit code `1`: receipt/provenance checks failed, bundle is not emitted.

## Verify Command

```bash
python3 scripts/ml/receipt_store.py verify-bundle \
  --bundle docs/evidence/e25/mission-bundle.tar.gz \
  --signing-key-env MISSION_BUNDLE_SIGNING_KEY \
  --output docs/evidence/e25/mission-bundle-verification.json
```

Behavior:
- Exit code `0`: signature, content checksums, and provenance chain are all valid.
- Exit code `1`: one or more checks failed.

## Replay Command (E25-S4)

`replay-bundle` restores mission bundle state and checks deterministic stage replay hashes:

```bash
python3 scripts/ml/receipt_store.py replay-bundle \
  --bundle docs/evidence/e25/mission-bundle.tar.gz \
  --signing-key-env MISSION_BUNDLE_SIGNING_KEY \
  --runtime-profile auto \
  --restore-dir docs/evidence/e25/replay-state \
  --stage-input extract_features=/tmp/extract-features-input.json \
  --output docs/evidence/e25/mission-bundle-replay.json
```

Behavior:
- Exit code `0`: bundle verification succeeded and replay had zero divergences.
- Exit code `1`: verification failed or replay detected divergence.
- Divergence payloads include exact `stage_id` plus `input_sha256`/`output_sha256` expected-vs-actual values.

## Replay + Environment Manifests

`pack-bundle` can embed optional manifests:

```bash
python3 scripts/ml/receipt_store.py pack-bundle \
  --store /path/to/receipts.json \
  --artifact /path/to/stage-output.json \
  --mission-id mission-e25-s4 \
  --output docs/evidence/e25/mission-bundle.tar.gz \
  --replay-manifest docs/evidence/e25/replay-manifest.json \
  --environment-manifest docs/evidence/e25/environment-manifest.json \
  --signing-key-env MISSION_BUNDLE_SIGNING_KEY
```

- `replay-manifest.json`: stage-level replay contract (`stage_id`, `input_sha256`, `output.path`, `output.sha256`).
- `environment-manifest.json`: pinned toolchain versions for `profiles.local` and `profiles.ci` (for example `python`, `java`, `javac`).
- `replay-bundle --runtime-profile auto` resolves to `ci` when `CI=true`, else `local`.

## Reproducibility Notes

- Bundle generation is deterministic for identical mission inputs:
  - fixed tar entry metadata (`mtime`, owner/group)
  - stable artifact ordering by archive path
  - canonical JSON ordering for manifest/signature payloads
  - fixed gzip timestamp (`mtime=0`)
