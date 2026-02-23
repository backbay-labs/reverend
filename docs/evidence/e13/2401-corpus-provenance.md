# E13-2401: OSS Binary Corpus Ingestion + License/Provenance Manifesting

**Issue:** 2401
**Epic:** E13 (Real-Target Benchmark Program GA)
**Status:** Implemented
**Date:** 2026-02-22

## Summary

This story implements deterministic ingestion for real-target OSS binaries with locked provenance and license policy enforcement. The system emits manifest rows containing all required provenance metadata and enforces license policy at ingestion time.

## Acceptance Criteria Verification

### AC1: Corpus ingest emits manifest rows with required metadata

**Status:** PASS

Each manifest entry contains:
- `sha256`: SHA-256 checksum of the binary artifact
- `source_url`: Original source URL for provenance attribution
- `spdx_license`: SPDX license identifier
- `architecture`: Target architecture (x86_64, aarch64, arm, mips, etc.)
- `compiler`: Compiler used (GCC, clang, etc.)
- `compiler_version`: Compiler version string
- `acquired_at`: ISO 8601 acquisition timestamp

Additional metadata captured:
- `format`: Binary format (ELF, PE32, PE64, Mach-O)
- `bits`: Architecture bit width (32, 64)
- `endian`: Endianness (little, big)
- `stripped`: Whether debug symbols are stripped
- `dynamic`: Whether dynamically linked
- `bytes`: File size in bytes

**Evidence:** See `datasets/registry/oss-corpus-sample-v1/manifest.json`

### AC2: License policy rejects unsupported/unknown classes with explicit failure evidence

**Status:** PASS

License policy enforcement implemented in `eval/scripts/license_policy.py`:

**Allowed License Classes:**
- `permissive`: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unlicense, CC0-1.0, 0BSD, BSL-1.0
- `copyleft_weak`: LGPL-*, MPL-2.0, EPL-*
- `copyleft_strong`: GPL-*, AGPL-*
- `public_domain`: CC0-1.0, Unlicense, WTFPL

**Rejected Patterns:**
- `proprietary`, `commercial`, `unknown`, `NOASSERTION`

**Failure Evidence Format:**
```json
{
  "spdx_id": "UNKNOWN-LICENSE",
  "valid": false,
  "policy_class": null,
  "rejection_reason": "unknown SPDX identifier: UNKNOWN-LICENSE",
  "evaluated_at": "2026-02-22T14:08:37+00:00"
}
```

**Evidence:** Run `python eval/scripts/license_policy.py validate --license PROPRIETARY-1.0`

### AC3: Ingest is reproducible from pinned manifest inputs and command logs

**Status:** PASS

Reproducibility mechanisms:
1. **Pinned manifests:** `datasets/datasets.lock.json` locks all artifact checksums
2. **Command logs:** Each manifest includes `command_log` array with exact invocation
3. **Timestamps:** `ingested_at` and per-artifact `acquired_at` timestamps
4. **Version tracking:** Schema version in lockfile (`schema_version: 1`)

**Evidence:** See `datasets/datasets.lock.json` entry for `oss-corpus-sample-v1`

## Implementation Details

### New Files

| File | Purpose |
|------|---------|
| `eval/scripts/license_policy.py` | SPDX license validation with policy enforcement |
| `eval/scripts/corpus_ingest.py` | Binary corpus ingestion with metadata extraction |
| `eval/scripts/validate_corpus_manifest.py` | Manifest validation against E13 acceptance criteria |
| `datasets/registry/oss-corpus-sample-v1/manifest.json` | Sample OSS corpus manifest |

### Lockfile Schema Extensions

The `datasets.lock.json` schema has been extended for OSS corpus entries:

```json
{
  "oss-corpus-sample-v1": {
    "version": "1.0.0",
    "kind": "oss_binary_corpus",
    "source": {
      "type": "local_directory",
      "path": "datasets/registry/oss-corpus-sample-v1"
    },
    "provenance": {
      "manifest_schema": "1.0.0",
      "ingested_at": "2026-02-22T14:08:37Z",
      "command_log": ["..."]
    },
    "license_policy": {
      "allowed_classes": ["permissive", "copyleft_weak", "copyleft_strong", "public_domain"],
      "enforcement": "strict"
    },
    "files": {
      "manifest.json": {
        "bytes": 3469,
        "sha256": "..."
      }
    }
  }
}
```

### CLI Usage

**Ingest from URL sources:**
```bash
python eval/scripts/corpus_ingest.py ingest \
  --source sources.json \
  --output-dir datasets/data/corpus \
  --output manifest.json
```

**Ingest from local directory:**
```bash
python eval/scripts/corpus_ingest.py ingest \
  --input-dir ./binaries \
  --output manifest.json
```

**Validate licenses:**
```bash
python eval/scripts/license_policy.py validate \
  --manifest manifest.json \
  --output license_report.json
```

**Validate manifest:**
```bash
python eval/scripts/validate_corpus_manifest.py \
  --manifest manifest.json \
  --data-dir ./binaries \
  --output eval/reports/e13/corpus_manifest_validation.json
```

**Generate lockfile entry:**
```bash
python eval/scripts/corpus_ingest.py lock \
  --manifest manifest.json \
  --dataset-name my-corpus-v1 \
  --output lockfile_entry.json
```

## Validation Artifacts

| Artifact | Path | Status |
|----------|------|--------|
| Dataset lockfile | `datasets/datasets.lock.json` | Updated |
| Sample manifest | `datasets/registry/oss-corpus-sample-v1/manifest.json` | Created |
| This evidence doc | `docs/evidence/e13/2401-corpus-provenance.md` | Created |

## Dependencies

- Depends on: `2308` (baseline evaluation infrastructure)
- Enables: `2402` (ground-truth curation), `2403` (architecture coverage)

## Quality Gates

Run validation:
```bash
bash scripts/cyntra/gates.sh --mode=all
```

## Next Steps

1. Populate corpus with real OSS binaries from permissive-licensed projects
2. Run corpus through Ghidra headless analysis for E13-2402 ground truth curation
3. Extend architecture coverage for E13-2403 (x86_64/ARM64/MIPS/RISCV/PPC)
