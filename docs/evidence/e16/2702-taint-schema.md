# E16-S2: Taint Evidence Schema + Ingest Adapters

## Summary

This story implements the taint evidence schema and ingest adapters for the Dynamic/Symbolic/Taint Evidence Fabric (E16). The implementation preserves source/sink/propagation semantics with provenance links to enable temporal investigation and vulnerability discovery workflows.

## Schema Components

### 1. Taint Source (`TraceTaintSource`)

Defines where tainted data originates:

| Field | Type | Description |
|-------|------|-------------|
| `labelId` | int | Unique label identifier within session |
| `sourceType` | enum | FILE_INPUT, NETWORK, ENVIRONMENT, REGISTER, CUSTOM |
| `sourceDescription` | String | Human-readable description (e.g., "stdin byte 42") |
| `creationSnap` | long | Snapshot when taint was introduced |
| `byteOffset` | int | Byte offset within the source |
| `sessionId` | String | Analysis session identifier |

### 2. Taint Evidence (`TraceTaintEvidence`)

Byte-level taint state at specific locations and times:

| Field | Type | Description |
|-------|------|-------------|
| `moduleId` | int | Module identifier |
| `locationType` | enum | MEMORY, REGISTER, TEMP |
| `locationOffset` | long | Module-relative offset or register space offset |
| `size` | int | Size in bytes |
| `labelSet` | Set<Integer> | Taint label IDs affecting this location |
| `taintComputeNumber` | int | Propagation depth from source (TCN) |
| `sourceSnap` | long | When taint was introduced |
| `lifespan` | Lifespan | Temporal validity [start, end] |
| `confidence` | double | Confidence score (0.0 to 1.0) |
| `sessionId` | String | Analysis session identifier |

### 3. Taint Propagation (`TraceTaintPropagation`)

Data flow edges in the taint graph:

| Field | Type | Description |
|-------|------|-------------|
| `edgeId` | long | Unique edge identifier |
| `snapId` | long | Snapshot when propagation occurred |
| `fromLocationType` | enum | Source location type |
| `fromLocationOffset` | long | Source offset |
| `fromSize` | int | Source size |
| `toLocationType` | enum | Destination location type |
| `toLocationOffset` | long | Destination offset |
| `toSize` | int | Destination size |
| `operation` | String | P-code operation (e.g., "INT_ADD", "COPY") |
| `pcOffset` | long | Module-relative instruction offset |
| `moduleId` | int | Module identifier |
| `edgeType` | enum | DATA_FLOW, CONTROL_FLOW, ADDRESS_DEPENDENCY |
| `sessionId` | String | Analysis session identifier |

### 4. Taint Sink (`TraceTaintSink`)

Security-sensitive operations reached by taint:

| Field | Type | Description |
|-------|------|-------------|
| `moduleId` | int | Module identifier |
| `sinkOffset` | long | Module-relative sink offset |
| `sinkType` | enum | MEMCPY_SIZE, FORMAT_STRING, SYSTEM_ARG, etc. |
| `reachingLabels` | Set<Integer> | Labels reaching this sink |
| `snapId` | long | When taint reached the sink |
| `functionOffset` | long | Containing function offset |
| `calleeOffset` | long | Callee address for call sinks |
| `taintedArgIndex` | int | Tainted argument index (0-based) |
| `lifespan` | Lifespan | Temporal validity |
| `confidence` | double | Confidence score (0.0 to 1.0) |
| `sessionId` | String | Analysis session identifier |

## Sink Types

The schema covers common vulnerability classes:

| Sink Type | Vulnerability Class |
|-----------|-------------------|
| `MEMCPY_SIZE` | Buffer overflow (size argument) |
| `MEMCPY_DEST` | Buffer overflow (destination) |
| `FORMAT_STRING` | Format string vulnerability |
| `SYSTEM_ARG` | Command injection |
| `SQL_QUERY` | SQL injection |
| `FILE_PATH` | Path traversal |
| `NETWORK_OUTPUT` | Data exfiltration |
| `FREE_ARG` | Use-after-free, double-free |
| `RETURN_ADDRESS` | Stack-based control flow hijack |
| `FUNCTION_POINTER` | Indirect call hijack |
| `ARRAY_INDEX` | Out-of-bounds access |
| `CUSTOM` | User-defined sink |

## Query API

### Function-Level Queries

```java
// Get all taint evidence within a function
Collection<TraceTaintEvidence> getTaintForFunction(
    AddressRange functionRange, long snap, String sessionId);

// Get all sinks within a function
Collection<TraceTaintSink> getSinksForFunction(
    AddressRange functionRange, long snap, String sessionId);
```

### Variable-Level Queries

```java
// Get taint history for a specific variable
Collection<TraceTaintEvidence> getTaintForVariable(
    long locationOffset, LocationType locationType,
    Lifespan lifespan, String sessionId);
```

### Timeline Queries

```java
// Find taint overlapping a time range
Collection<TraceTaintEvidence> findTaintOverlapping(
    AddressRange range, Lifespan lifespan);

// Find by specific label over time
Collection<TraceTaintEvidence> findTaintByLabel(
    int labelId, Lifespan lifespan, String sessionId);
```

### Propagation Queries

```java
// Find all edges leading to a destination
Collection<TraceTaintPropagation> findPropagationTo(
    long toLocationOffset, LocationType toLocationType, String sessionId);
```

## Ingest Adapters

### PANDA taint2 Adapter

The `PandaTaint2Adapter` supports:

- JSON export format from PANDA taint analysis scripts
- Binary format for high-volume taint data
- File extensions: `.plog`, `.ptaint`, `.json`

Usage:
```java
TaintAdapter adapter = new PandaTaint2Adapter();
if (adapter.canParse(inputStream)) {
    TaintIngestResult result = adapter.parse(
        inputStream, sessionId, moduleMap, evidenceManager);
    System.out.println("Imported: " + result.getTotalImported());
}
```

## Integration with Evidence Manager

The `TraceEvidenceManager` interface now includes full taint evidence APIs integrated with the existing coverage and branch evidence functionality. All taint data:

- Uses the same module/offset addressing as other evidence types
- Supports temporal queries via `Lifespan`
- Is indexed by session for multi-session comparison
- Preserves entity linkage to static functions/variables

## Files Changed

### New Files
- `TraceTaintSource.java` - Source definition interface
- `TraceTaintEvidence.java` - Evidence interface
- `TraceTaintPropagation.java` - Propagation edge interface
- `TraceTaintSink.java` - Sink interface
- `DBTraceTaintSource.java` - DB implementation
- `DBTraceTaintEvidence.java` - DB implementation
- `DBTraceTaintPropagation.java` - DB implementation
- `DBTraceTaintSink.java` - DB implementation
- `TaintAdapter.java` - Adapter interface
- `PandaTaint2Adapter.java` - PANDA implementation
- `TaintEvidenceSchemaTest.java` - Unit tests

### Modified Files
- `TraceEvidenceManager.java` - Added taint API methods
- `DBTraceEvidenceManager.java` - Added taint implementations

## Validation

- Schema supports source, sink, propagation edges, and confidence metadata ✓
- PANDA taint2 adapter imports into normalized evidence store ✓
- Records queryable by function, variable, and timeline filters ✓

## Next Steps

- Integration tests with real PANDA taint2 output
- UI overlays for taint visualization (E16-2703)
- Coverage/crash evidence auto-link (E16-2704)
