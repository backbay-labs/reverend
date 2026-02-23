# E14-S2: Live Query Bindings Evidence

**Bead**: 2502
**Epic**: E14 (Native Reverend Pluginization)
**Status**: Complete
**Date**: 2026-02-22

## Summary

This story binds the semantic query engine to live Program and Decompiler state with deterministic refresh semantics. Queries resolve against active program context without stale state leakage.

## Acceptance Criteria Validation

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Queries resolve against active Program and decompiler context without stale state leakage | ✅ | `LiveQueryServiceImpl` binds to Program via `DomainObjectListener`, auto-invalidates on changes |
| Cache invalidation paths are covered for reanalysis/symbol updates | ✅ | `QueryCacheManager` handles FUNCTION_*, SYMBOL_*, CODE_*, MEMORY_* events with fine-grained invalidation |
| Latency and error telemetry are emitted for query operations | ✅ | `QueryTelemetry` records p50/p90/p99 latencies, error rates, cache hit rates |

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    LiveQueryServiceImpl                      │
│  - Implements QueryService interface                         │
│  - Binds to Program via DomainObjectListener                │
│  - Orchestrates cache, decompiler, and telemetry            │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ QueryCacheManager│  │DecompilerContext│  │  QueryTelemetry │
│                 │  │    Provider     │  │                 │
│ - Per-program   │  │ - Per-program   │  │ - Latency p50/  │
│   caches        │  │   DecompInterface│ │   p90/p99       │
│ - LRU eviction  │  │ - Result caching │  │ - Error rates   │
│ - Fine-grained  │  │ - Style support │  │ - Cache metrics │
│   invalidation  │  │   (normalize/   │  │                 │
│                 │  │    decompile)   │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Cache Invalidation Strategy

The system listens to Ghidra's `DomainObjectChangedEvent` and performs targeted cache invalidation:

| Event Type | Caches Invalidated | Rationale |
|------------|-------------------|-----------|
| `FUNCTION_ADDED/REMOVED/CHANGED/BODY_CHANGED` | Similar functions, semantic search | Function structure affects similarity scores and search results |
| `SYMBOL_ADDED/REMOVED/RENAMED` | Semantic search | Symbol names are matched in semantic queries |
| `CODE_ADDED/REMOVED/REPLACED` | Pattern search, context | Code changes affect instruction-level searches |
| `MEMORY_BLOCK_ADDED/REMOVED/BYTES_CHANGED` | All caches + decompiler | Major memory changes require full reanalysis |

### Telemetry Metrics

The `QueryTelemetry` class collects:

**Operation Latencies** (per operation type):
- Count of operations
- p50, p90, p99 percentiles in milliseconds
- Mean latency

**Error Tracking**:
- Total error count
- Errors by type (exception class name)
- Recent error log (last 100 errors with timestamps)

**Cache Performance**:
- Hit rate (hits / (hits + misses))
- Invalidation count

**Decompiler Performance**:
- Cache hit rate for decompilation results
- Success/failure rate
- Latency percentiles

Example summary output:
```
=== Query Telemetry Summary ===

--- Operation Latencies ---
  findSimilarFunctions: count=15, p50=45.23ms, p90=120.50ms, p99=250.00ms, mean=65.00ms
  semanticSearch: count=42, p50=12.50ms, p90=35.00ms, p99=80.00ms, mean=18.00ms
  getContext: count=128, p50=5.00ms, p90=15.00ms, p99=45.00ms, mean=8.50ms

--- Decompiler ---
  Decompilations: 156 (95.5% success)
  Cache hit rate: 72.3%
  Latency: p50=25.00ms, p90=80.00ms, mean=35.00ms

--- Query Cache ---
  Hit rate: 68.5% (hits=2450, misses=1130)
  Invalidations: 45

--- Errors ---
  Total: 7
    QueryException: 5
    TimeoutException: 2

--- Program Bindings ---
  Binds: 3, Unbinds: 1
```

## Files Changed

| Path | Change |
|------|--------|
| `ghidra/reverend/query/LiveQueryServiceImpl.java` | New: Main query service implementation with Program binding |
| `ghidra/reverend/query/DecompilerContextProvider.java` | New: Manages decompiler instances and result caching |
| `ghidra/reverend/query/QueryCacheManager.java` | New: Query result caching with fine-grained invalidation |
| `ghidra/reverend/query/QueryTelemetry.java` | New: Latency and error telemetry collector |
| `ghidra/reverend/query/package-info.java` | New: Package documentation |
| `ghidra/reverend/query/QueryCacheManagerTest.java` | New: Unit tests for cache manager |
| `ghidra/reverend/query/QueryTelemetryTest.java` | New: Unit tests for telemetry |
| `ghidra/reverend/query/LiveQueryServiceImplTest.java` | New: Integration tests for live query service |
| `docs/evidence/e14/2502-live-query-bindings.md` | New: This document |

## Module Structure (Updated)

```
Ghidra/Features/Reverend/
├── build.gradle
├── Module.manifest
└── src/
    ├── main/java/ghidra/reverend/
    │   ├── ReverendPluginModule.java
    │   ├── api/v1/
    │   │   ├── package-info.java
    │   │   ├── ServiceVersion.java
    │   │   ├── QueryService.java
    │   │   ├── ProposalIntegrationService.java
    │   │   ├── EvidenceService.java
    │   │   ├── MissionService.java
    │   │   └── PolicyService.java
    │   └── query/                          # NEW
    │       ├── package-info.java
    │       ├── LiveQueryServiceImpl.java
    │       ├── DecompilerContextProvider.java
    │       ├── QueryCacheManager.java
    │       └── QueryTelemetry.java
    ├── test/java/ghidra/reverend/
    │   ├── ServiceVersionTest.java
    │   └── query/                          # NEW
    │       ├── QueryCacheManagerTest.java
    │       └── QueryTelemetryTest.java
    └── test.slow/java/ghidra/reverend/     # NEW
        └── query/
            └── LiveQueryServiceImplTest.java
```

## Usage Example

```java
// Create components
QueryTelemetry telemetry = new QueryTelemetry();
QueryCacheManager cacheManager = new QueryCacheManager();
DecompilerContextProvider decompilerProvider = new DecompilerContextProvider(telemetry);

// Create and bind service
LiveQueryServiceImpl queryService = new LiveQueryServiceImpl(
    cacheManager, decompilerProvider, telemetry);
queryService.bindToProgram(currentProgram);

// Use the service
try {
    // Find similar functions
    List<QueryResult> similar = queryService.findSimilarFunctions(
        currentProgram, currentFunction, 10, monitor);

    // Semantic search
    List<QueryResult> searchResults = queryService.semanticSearch(
        currentProgram, "encryption", null, 20, monitor);

    // Get context for an address
    Optional<QueryContext> context = queryService.getContext(
        currentProgram, currentAddress);

} catch (QueryException e) {
    // Error handling - telemetry automatically records the error
    Msg.error(this, "Query failed: " + e.getMessage());
}

// Access telemetry
System.out.println(telemetry.getSummaryReport());

// Clean up
queryService.close();
```

## Integration Points

### With Existing Reverend Services

- **QueryService**: `LiveQueryServiceImpl` implements the `QueryService` interface defined in story 2501
- **EvidenceService**: Query results can be linked to evidence via the optional `evidenceId` field
- **PolicyService**: Future integration will add policy checks before query execution

### With Ghidra Core

- **Program**: Binds via `DomainObjectListener` for change notifications
- **DecompInterface**: Uses Ghidra's native decompiler with configurable simplification styles
- **FunctionManager**: Iterates functions for similarity and semantic search
- **Listing**: Accesses instructions for pattern search

## Follow-up Stories

| Bead | Story | Dependency on 2502 |
|------|-------|-------------------|
| 2503 | Cockpit v2 UI | Uses `LiveQueryServiceImpl` for UI queries |
| 2505 | Headless/UI parity | Uses query service in both modes |

## Testing

### Unit Tests
- `QueryCacheManagerTest`: 10 tests for cache operations and invalidation
- `QueryTelemetryTest`: 12 tests for telemetry recording and statistics

### Integration Tests
- `LiveQueryServiceImplTest`: 13 tests covering:
  - Program binding/unbinding
  - Query operations (findSimilarFunctions, semanticSearch, patternSearch, getContext)
  - Cache hit/miss behavior
  - Cache invalidation on program changes
  - Multi-program support
  - Error handling
  - Telemetry emission

### Quality Gates
Run with:
```bash
bash scripts/cyntra/gates.sh --mode=all
```
