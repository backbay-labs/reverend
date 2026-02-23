# E26 Domain Pack Evidence

This directory tracks artifact contracts for Epic E26 domain-pack deliveries.

## Artifact Contract

### E26-S1 Malware Triage Pack

- Pinned sample set: `pinned-sample-set.json`
  - `kind: "malware_domain_pack_sample_set"`
  - Immutable `pack_id`, deterministic `seed`, per-sample `sha256`, provenance, and disposition
- IOC bundles: `ioc-bundles.json`
  - `kind: "malware_ioc_bundle_pack"`
  - IOC categories (`ipv4`, `domain`, `url`, `mutex`, `registry`, `file_path`) with evidence links
- Evidence-linked behavior maps: `behavior-map-evidence.json`
  - `kind: "malware_behavior_map_bundle"`
  - ATT&CK-linked behavior map rows with explicit `evidence_refs[]`
- Risk register: `malware-risk-register.md`
- Operator guidance: `malware-operator-guidance.md`

### E26-S2 Firmware Analysis Pack

- Pipeline manifest: `firmware-pipeline-manifest.json`
  - `kind: "firmware_domain_pack_pipeline_manifest"`
  - Reproducible ingest/extract/emulate stages with pinned versions, architecture profiles, and failure diagnostics contracts
- Component attribution: `firmware-component-attribution.json`
  - `kind: "firmware_component_attribution_bundle"`
  - Per-firmware component mapping with package/version/license/provenance fields
- Hotspot maps: `firmware-hotspot-map.json`
  - `kind: "firmware_hotspot_map_bundle"`
  - Network and crypto hotspot triage rows with evidence references and confidence

## Mission Templates

Mission DSL templates for the malware triage domain pack:

- `docs/schemas/examples/mission-dsl/malware-ioc-triage-mission.json`
- `docs/schemas/examples/mission-dsl/malware-anti-analysis-mission.json`

Validation command:

```bash
python3 scripts/ml/mission_dsl_validator.py \
  --mission docs/schemas/examples/mission-dsl/malware-ioc-triage-mission.json

python3 scripts/ml/mission_dsl_validator.py \
  --mission docs/schemas/examples/mission-dsl/malware-anti-analysis-mission.json
```

## Malware Safety Policy Profiles (Enforced)

- Profiles: `scripts/security/malware_safety_policy_profiles.json`
- Enforcer: `scripts/security/validate_malware_safety_profiles.py`

Validation command:

```bash
python3 scripts/security/validate_malware_safety_profiles.py \
  --profiles scripts/security/malware_safety_policy_profiles.json
```

Enforcement rules checked by validator:

- `policy_mode` is restricted to `offline` or `allowlist` (no `cloud`)
- `sandbox_required` and `detonation_only_in_sandbox` must be true
- `allowlist` profiles must provide non-empty, explicit endpoints
- wildcard or catch-all allowlist entries are rejected
- all profiles must default to blocked on policy violations
