# E14-S1: Reverend Plugin Module Service Contracts

**Bead**: 2501
**Epic**: E14 (Native Reverend Pluginization)
**Status**: Complete
**Date**: 2026-02-22

## Summary

This story establishes the native Reverend plugin module (`Ghidra/Features/Reverend`) with versioned service API contracts for query, proposal, evidence, mission, and policy surfaces.

## Acceptance Criteria Validation

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Plugin module skeleton compiles in Gradle | ✅ | `Ghidra/Features/Reverend/build.gradle` applies standard Ghidra module scripts |
| Exposes explicit service interfaces | ✅ | Five service interfaces defined in `ghidra.reverend.api.v1` package |
| Service API contracts are versioned | ✅ | `ServiceVersion` class with semver support; all services implement `getVersion()` |
| Service API contracts are documented | ✅ | Comprehensive Javadoc on all interfaces; `package-info.java` describes versioning policy |
| Integration points to existing security/proposal primitives validated | ✅ | `ProposalIntegrationService` wraps `ProposalService`; `PolicyService` uses `PolicyMode`, `EgressPolicy`, `Capability` |

## Module Structure

```
Ghidra/Features/Reverend/
├── build.gradle
├── Module.manifest
└── src/
    ├── main/java/ghidra/reverend/
    │   ├── ReverendPluginModule.java
    │   └── api/v1/
    │       ├── package-info.java
    │       ├── ServiceVersion.java
    │       ├── QueryService.java
    │       ├── ProposalIntegrationService.java
    │       ├── EvidenceService.java
    │       ├── MissionService.java
    │       └── PolicyService.java
    └── test/java/ghidra/reverend/
        └── ServiceVersionTest.java
```

## Service API Contracts (v1.0.0)

### 1. QueryService

Semantic search and query operations against the program model and decompiler state.

**Key Operations:**
- `findSimilarFunctions()` - Semantic similarity search for functions
- `semanticSearch()` - Natural language query against code
- `patternSearch()` - Structural pattern matching
- `getContext()` - Detailed address context with decompiler output

**Nested Types:**
- `QueryResult` - Single result with score and evidence linkage
- `QueryContext` - Detailed address context information
- `QueryException` - Query operation failure

### 2. ProposalIntegrationService

Integration with the proposal workflow system for applying analysis suggestions.

**Key Operations:**
- `createFromSuggestion()` - Create proposal from analysis suggestion
- `createBatch()` - Batch proposal creation
- `queryProposals()` - Query proposals by state and filters
- `apply()` - Transaction-safe proposal application

**Integration Points:**
- Wraps `ghidra.security.proposal.ProposalService`
- Links proposals to evidence for provenance

**Nested Types:**
- `AnalysisSuggestion` - Suggestion input type
- `BatchProposalResult` - Batch creation result
- `ProposalApplicationResult` - Application result with receipt

### 3. EvidenceService

Evidence collection, retrieval, and linking for analysis provenance.

**Key Operations:**
- `record()` - Persist evidence with immutability guarantee
- `query()` - Query by program, type, source, and time
- `getForAddress()` - Address-linked evidence retrieval
- `linkToProposal()` - Proposal-evidence linkage
- `getDerivationChain()` - Provenance chain traversal

**Evidence Types:**
- `STATIC_ANALYSIS`, `DYNAMIC_TRACE`, `MODEL_INFERENCE`
- `SYMBOLIC`, `TAINT`, `COVERAGE`
- `SIMILARITY`, `USER_ANNOTATION`, `AGGREGATED`

### 4. MissionService

Mission orchestration for multi-step analysis workflows.

**Key Operations:**
- `create()` / `start()` / `pause()` / `resume()` / `cancel()` - Lifecycle
- `getProgress()` - Progress tracking
- `list()` - Mission queries by program and state

**Mission Types:**
- `FULL_ANALYSIS`, `TYPE_RECOVERY`, `FUNCTION_ID`
- `VULN_SEARCH`, `SIMILARITY_SEARCH`
- `ITERATIVE_REFINEMENT`, `CUSTOM`

**Mission States:**
- `PENDING` → `RUNNING` ⇄ `PAUSED`
- `RUNNING` → `COMPLETED` | `FAILED` | `CANCELLED`

### 5. PolicyService

Policy-aware action execution with capability and egress controls.

**Key Operations:**
- `getPolicyMode()` / `setPolicyMode()` - Policy mode management
- `checkAction()` - Pre-execution policy validation
- `requestCapabilities()` - Capability token acquisition
- `executeWithPolicy()` - Policy-enforced execution
- `getAuditLog()` - Audit trail retrieval

**Integration Points:**
- Uses `ghidra.security.policy.PolicyMode` (OFFLINE/ALLOWLIST/CLOUD)
- Uses `ghidra.security.policy.EgressPolicy` for network controls
- Uses `ghidra.security.capability.Capability` and `CapabilityToken`

**Action Types:**
- `LOCAL_QUERY`, `MODEL_QUERY`, `NETWORK_EGRESS`
- `PROGRAM_MODIFY`, `PROPOSAL_CREATE`, `PROPOSAL_APPLY`
- `EVIDENCE_RECORD`, `MISSION_EXECUTE`, `CONFIG_CHANGE`

## API Versioning Policy

All service interfaces follow semantic versioning (major.minor.patch):

| Change Type | Version Increment | Compatibility |
|-------------|-------------------|---------------|
| Breaking API change | Major (v1 → v2) | New package (`api.v2`) |
| Additive method (with default) | Minor | Backward compatible |
| Documentation/implementation fix | Patch | Backward compatible |

Deprecation policy:
1. Previous major version remains available for at least one release cycle
2. Deprecation warnings added to old version
3. Migration guides provided in release notes

## Dependencies

```gradle
dependencies {
    api project(":Generic")      // Security primitives (policy, capability, proposal)
    api project(":Base")         // Core Ghidra functionality
    api project(":SoftwareModeling")  // Program model, addresses
    api project(":Decompiler")   // Decompiler integration
}
```

## Validation

### Compilation
The module compiles successfully with Gradle using standard Ghidra module scripts:
- `distributableGhidraModule.gradle` - Distribution packaging
- `javaProject.gradle` - Java compilation
- `jacocoProject.gradle` - Coverage
- `javaTestProject.gradle` - Test configuration

### Unit Tests
`ServiceVersionTest` validates:
- Version parsing and formatting
- Compatibility checking
- Comparison operations
- Module constants

### Integration Point Validation
- `ProposalIntegrationService.getProposalService()` returns `ghidra.security.proposal.ProposalService`
- `PolicyService.getPolicyMode()` returns `ghidra.security.policy.PolicyMode`
- `PolicyService.getEgressPolicy()` returns `ghidra.security.policy.EgressPolicy`
- `PolicyService.requestCapabilities()` accepts `ghidra.security.capability.Capability`

## Follow-up Stories

| Bead | Story | Dependency on 2501 |
|------|-------|-------------------|
| 2502 | Live query bindings | Uses `QueryService` |
| 2503 | Cockpit v2 UI | Uses all services |
| 2504 | Transaction-safe apply | Uses `ProposalIntegrationService.apply()` |
| 2505 | Headless/UI parity | Uses `MissionService` |
| 2506 | Operator settings | Uses `PolicyService` |

## Files Changed

| Path | Change |
|------|--------|
| `Ghidra/Features/Reverend/` | New module (directory structure) |
| `Ghidra/Features/Reverend/build.gradle` | Module build configuration |
| `Ghidra/Features/Reverend/Module.manifest` | Module manifest |
| `ghidra/reverend/ReverendPluginModule.java` | Module class |
| `ghidra/reverend/api/v1/package-info.java` | API documentation |
| `ghidra/reverend/api/v1/ServiceVersion.java` | Version contract |
| `ghidra/reverend/api/v1/QueryService.java` | Query service interface |
| `ghidra/reverend/api/v1/ProposalIntegrationService.java` | Proposal integration interface |
| `ghidra/reverend/api/v1/EvidenceService.java` | Evidence service interface |
| `ghidra/reverend/api/v1/MissionService.java` | Mission service interface |
| `ghidra/reverend/api/v1/PolicyService.java` | Policy service interface |
| `ghidra/reverend/ServiceVersionTest.java` | Unit tests |
| `docs/evidence/e14/2501-service-contracts.md` | This document |
