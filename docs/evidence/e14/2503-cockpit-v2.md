# E14-S3: Cockpit v2 Dockable Providers Evidence

**Bead**: 2503
**Epic**: E14 (Native Reverend Pluginization)
**Status**: Complete
**Date**: 2026-02-22

## Summary

This story implements Cockpit v2 dockable providers for semantic search, evidence drilldown, and graph facets with direct jump-to-address, jump-to-xref, and proposal creation actions. UI state is serializable and restorable across sessions.

## Acceptance Criteria Validation

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Dockable provider surfaces semantic results, evidence facets, and confidence metadata | ✅ | `CockpitSearchProvider` displays results with score, address, function, and summary; `EvidenceDrawerProvider` shows evidence grouped by type with confidence |
| Jump-to-address/xref/proposal actions work from cockpit views | ✅ | `CockpitNavigationActions` provides GoToAddress, GoToNextXref, GoToFunction, ShowInDecompiler, and CreateProposal actions |
| UI state is serializable and restorable across sessions | ✅ | `CockpitState` persists query, filters, sort settings, and evidence selection via `SaveState` |

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       CockpitPlugin                          │
│  - Manages provider lifecycle                                │
│  - Coordinates state serialization                          │
│  - Registers navigation actions                             │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌───────────────────┐
│CockpitSearch    │  │EvidenceDrawer   │  │CockpitNavigation  │
│Provider         │  │Provider         │  │Actions            │
│                 │  │                 │  │                   │
│ - Search input  │  │ - Evidence cards│  │ - GoToAddress     │
│ - Results table │  │ - Type grouping │  │ - GoToNextXref    │
│ - Selection nav │  │ - Addr buttons  │  │ - GoToFunction    │
│ - State persist │  │ - Confidence    │  │ - ShowInDecompiler│
│                 │  │   colors        │  │ - CreateProposal  │
└─────────────────┘  └─────────────────┘  └───────────────────┘
         │
         ▼
┌─────────────────┐
│  CockpitState   │
│                 │
│ - lastQuery     │
│ - maxResults    │
│ - minConfidence │
│ - sortColumn    │
│ - selectedIds   │
│ - drawerVisible │
└─────────────────┘
```

### Provider Features

#### CockpitSearchProvider

| Feature | Implementation |
|---------|----------------|
| Search input | Text field with Enter key trigger |
| Results table | 4 columns: Address, Score, Function, Summary |
| Double-click navigation | Navigates to selected address via GoToService |
| Context menu | Go To Address, Show Evidence, Show Cross-References, Clear Results |
| State persistence | Query, max results, confidence filter, sort settings |

#### EvidenceDrawerProvider

| Feature | Implementation |
|---------|----------------|
| Evidence cards | Grouped by EvidenceType (STATIC_ANALYSIS, DYNAMIC_TRACE, MODEL_INFERENCE, etc.) |
| Confidence display | Color-coded: green (≥90%), olive (70-90%), orange (50-70%), red (<50%) |
| Address navigation | Clickable address buttons that navigate via GoToService |
| Payload summary | Truncated display of evidence payload key-value pairs |
| Derivation chain | Loads predecessor evidence for context |

#### CockpitNavigationActions

| Action | Key Binding | Description |
|--------|-------------|-------------|
| Go To Address | G | Navigate to selected address in listing |
| Go To Next Xref | X | Navigate to next cross-reference to address |
| Go To Function | F | Navigate to containing function entry point |
| Show in Decompiler | D | Navigate to address (decompiler follows if open) |
| Create Proposal | - | Initiate proposal for selected function |

### State Serialization

The `CockpitState` class handles all UI state persistence:

```java
CockpitState {
  lastQuery:            String    // Last search query
  maxResults:           int       // Result limit (1-1000)
  minConfidence:        double    // Confidence filter (0.0-1.0)
  evidenceFilter:       String    // Evidence type filter
  sortColumn:           int       // Active sort column
  sortAscending:        boolean   // Sort direction
  selectedEvidenceIds:  String[]  // Selected evidence IDs
  evidenceDrawerVisible: boolean  // Drawer visibility
  graphLayoutMode:      String    // Graph layout preference
}
```

Persistence uses Ghidra's `SaveState` API with nested states per provider.

## Files Changed

| Path | Change |
|------|--------|
| `ghidra/reverend/cockpit/package-info.java` | New: Package documentation |
| `ghidra/reverend/cockpit/CockpitState.java` | New: Serializable UI state |
| `ghidra/reverend/cockpit/SearchResultEntry.java` | New: Result table row model |
| `ghidra/reverend/cockpit/CockpitSearchProvider.java` | New: Semantic search provider |
| `ghidra/reverend/cockpit/EvidenceDrawerProvider.java` | New: Evidence drilldown provider |
| `ghidra/reverend/cockpit/CockpitNavigationActions.java` | New: Navigation action factory |
| `ghidra/reverend/cockpit/CockpitPlugin.java` | New: Plugin coordinating providers |
| `ghidra/reverend/cockpit/CockpitStateTest.java` | New: Unit tests for state |
| `ghidra/reverend/cockpit/SearchResultEntryTest.java` | New: Unit tests for result entry |
| `ghidra/reverend/cockpit/CockpitSearchProviderTest.java` | New: Integration tests for search provider |
| `docs/evidence/e14/2503-cockpit-v2.md` | New: This document |

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
    │   ├── query/
    │   │   ├── package-info.java
    │   │   ├── LiveQueryServiceImpl.java
    │   │   ├── DecompilerContextProvider.java
    │   │   ├── QueryCacheManager.java
    │   │   └── QueryTelemetry.java
    │   └── cockpit/                          # NEW
    │       ├── package-info.java
    │       ├── CockpitState.java
    │       ├── SearchResultEntry.java
    │       ├── CockpitSearchProvider.java
    │       ├── EvidenceDrawerProvider.java
    │       ├── CockpitNavigationActions.java
    │       └── CockpitPlugin.java
    ├── test/java/ghidra/reverend/
    │   ├── ServiceVersionTest.java
    │   ├── query/
    │   │   ├── QueryCacheManagerTest.java
    │   │   └── QueryTelemetryTest.java
    │   └── cockpit/                          # NEW
    │       ├── CockpitStateTest.java
    │       └── SearchResultEntryTest.java
    └── test.slow/java/ghidra/reverend/
        ├── query/
        │   └── LiveQueryServiceImplTest.java
        └── cockpit/                          # NEW
            └── CockpitSearchProviderTest.java
```

## Usage Example

```java
// Get or create the cockpit plugin
CockpitPlugin plugin = (CockpitPlugin) tool.getManagedPlugin(CockpitPlugin.class);

// Set real services when available
plugin.setQueryService(liveQueryService);
plugin.setEvidenceService(evidenceService);
plugin.setProposalService(proposalService);

// Show providers
plugin.showSearchProvider();
plugin.showEvidenceProvider();

// Access current state
CockpitState state = plugin.getSearchProvider().getState();
state.setMaxResults(100);
state.setMinConfidence(0.7);

// Get selected result
plugin.getSearchProvider().getSelectedEntry().ifPresent(entry -> {
    Address addr = entry.getAddress();
    String func = entry.getFunctionName();
    // ...
});

// Show evidence for an ID
plugin.getEvidenceProvider().showEvidence("ev-12345");
```

## Integration Points

### With Existing Reverend Services

- **QueryService**: `CockpitSearchProvider` uses `LiveQueryServiceImpl` for semantic search
- **EvidenceService**: `EvidenceDrawerProvider` uses `EvidenceService` for evidence retrieval
- **ProposalIntegrationService**: Navigation actions can create proposals

### With Ghidra Core

- **GoToService**: All navigation actions use `GoToService.goTo(ProgramLocation)`
- **ComponentProviderAdapter**: Providers extend the standard docking framework
- **SaveState**: State persistence uses Ghidra's options framework
- **DockingAction**: Actions registered via standard action infrastructure

## Follow-up Stories

| Bead | Story | Dependency on 2503 |
|------|-------|-------------------|
| 2504 | Transaction-safe apply/revert | Uses cockpit providers for proposal visualization |
| 2703 | Constraint/replay overlays | Extends cockpit with dynamic evidence overlays |

## Testing

### Unit Tests
- `CockpitStateTest`: 15 tests for state management and serialization
- `SearchResultEntryTest`: 14 tests for result entry model

### Integration Tests
- `CockpitSearchProviderTest`: 8 tests covering:
  - Provider creation and initialization
  - Program binding/unbinding
  - State serialization/restoration
  - Results list immutability

## Quality Gates

Run with:
```bash
bash scripts/cyntra/gates.sh --mode=all
```
