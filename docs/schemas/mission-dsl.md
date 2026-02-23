# Mission DSL Schema (v1)

This schema defines deterministic mission execution contracts for crew-stage workflows.

- Schema file: `docs/schemas/mission-dsl.schema.json`
- Validator: `scripts/ml/mission_dsl_validator.py`
- Examples: `docs/schemas/examples/mission-dsl/`

## Required Top-Level Fields

- `schema_version`: fixed to `1`
- `mission_id`: stable mission identifier (`[a-z0-9][a-z0-9._:-]{2,127}`)
- `mission_kind`: one of `triage`, `protocol`, `diff`, `deobf`
- `description`: human-readable mission intent
- `inputs`: mission inputs and requiredness
- `outputs`: mission outputs mapped to explicit stage outputs
- `policies`: determinism, conflict resolution, approval, retry defaults
- `stages`: explicit ordered stage definitions

## Determinism Rules Enforced by Validator

The JSON schema validates shape, while `mission_dsl_validator.py` rejects ambiguous/non-deterministic payloads:

- Stage IDs must be unique.
- Stage `order` must be unique contiguous integers starting at `1`.
- `depends_on` references must exist and must not contain self-dependencies or duplicates.
- Stage-input references to `stage_output` must:
  - reference an existing upstream stage and output
  - include that upstream stage in `depends_on`
  - point to a strictly earlier `order`
- Retry jitter must be `none` for mission defaults and stage overrides.
- Stage dependency graph must be acyclic.

## Validation Command

```bash
python3 scripts/ml/mission_dsl_validator.py \
  --mission docs/schemas/examples/mission-dsl/triage-mission.json
```

## Published Example Missions

- `docs/schemas/examples/mission-dsl/triage-mission.json`
- `docs/schemas/examples/mission-dsl/protocol-mission.json`
- `docs/schemas/examples/mission-dsl/diff-mission.json`
- `docs/schemas/examples/mission-dsl/deobf-mission.json`
