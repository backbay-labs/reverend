# Datasets

This directory contains version-pinned datasets for the evaluation harness.

## Layout

- `datasets/registry/`: small, repo-local datasets used for deterministic smoke runs.
- `datasets/data/`: materialized datasets (runtime output; can be deleted).
- `datasets/datasets.lock.json`: locked manifest with per-file SHA-256 checksums.

## Notes

- The lockfile is the source of truth for dataset contents. Any dataset update must
  update the corresponding checksums in `datasets/datasets.lock.json`.
- The evaluation harness validates checksums before running.
