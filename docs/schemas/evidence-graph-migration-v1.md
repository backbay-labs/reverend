# Canonical Evidence Graph v1 Migration

This document defines the migration path from pre-canonical receipt evidence rows to the canonical evidence graph schema in `docs/schemas/evidence-graph.schema.json`.

## Scope

- Source: legacy `receipt.evidence[]` entries using `evidence_type`, `source_type`, `source_id`, and `metadata`.
- Target: canonical entities and edges with stable IDs and `*_schema_version = 1`.
- Compatibility mode: legacy fields remain supported during rollout.

## Stable ID Contracts

- `static`: `evs_<stable-token>`
- `dynamic`: `evd_<stable-token>`
- `symbolic`: `evy_<stable-token>`
- `taint`: `evt_<stable-token>`
- `proposal`: `evp_<stable-token>`
- `receipt`: `evr_<stable-token>`

Use deterministic tokens (for example sha256 of canonical payload, truncated and namespaced) so repeated imports produce identical IDs.

## Field Mapping

1. Map legacy source rows to canonical entity fields:
- `entity_type`: derived from legacy `source_type` classifier.
- `entity_id`: deterministic stable ID with the prefix for `entity_type`.
- `entity_schema_version`: set to `1`.

2. Preserve existing legacy linkage for compatibility:
- Keep `source_type` and `source_id` unchanged while writers/consumers migrate.

3. Add optional canonical edge:
- `edge.edge_type`: one of `supports`, `derived_from`, `corroborates`, `supersedes`.
- `edge.target_entity_type`, `edge.target_entity_id`, `edge.target_entity_schema_version`.

## Cross-Source Edge Rules

Allowed source->target contracts:

- `supports`: `static|dynamic|symbolic|taint|receipt -> proposal`
- `derived_from`: `proposal -> static|dynamic|symbolic|taint`
- `corroborates`: `static <-> dynamic`, `symbolic <-> taint`
- `supersedes`: `proposal -> proposal`, `receipt -> receipt`

## Backward Compatibility Rollout

1. Read path first:
- Readers accept both legacy-only and canonical evidence objects.

2. Dual-write phase:
- Writers keep legacy fields and add canonical fields.

3. Canonical-required phase:
- Enforce canonical fields for newly written evidence.

4. Legacy deprecation:
- Remove dependency on `source_type/source_id` once all writers are migrated.

## Validation Hooks

- JSON Schema validation: `docs/schemas/evidence-graph.schema.json`.
- Runtime validation: `scripts/ml/receipt_store.py` validates canonical IDs, schema versions, and edge contracts when canonical fields are present.

