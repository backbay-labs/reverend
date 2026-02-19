# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

This is the **Ghidra** source repository — NSA's software reverse engineering (SRE) framework. It is a large, multi-module Gradle project written primarily in Java, with C++ native components (decompiler), Sleigh processor specifications, and Python 3 debugger connectors.

## Prerequisites

- JDK 21 (64-bit)
- Gradle 8.5+ (or use `./gradlew`)
- Python 3.9–3.14 with pip
- GCC or Clang + make (for native builds on macOS/Linux)

## Build Commands

```bash
# First-time setup: fetch non-Maven dependencies
gradle -I gradle/support/fetchDependencies.gradle

# Prepare dev environment (downloads Maven deps, generates needed files)
gradle prepdev

# Generate Eclipse projects + build native components
gradle prepdev eclipse buildNatives

# Build full Ghidra distribution to build/dist/
gradle buildGhidra

# Build uncompressed distribution
gradle assembleAll

# Build native components only
gradle buildNatives

# Compile Sleigh processor specifications
gradle sleighCompile

# Clean build artifacts
gradle clean

# Skip specific tasks (e.g., IP header checks)
gradle buildGhidra -x ip
```

## Testing

Tests use **JUnit 4**. There are three test source sets per module:

| Source Set | Directory | Gradle Task | Description |
|---|---|---|---|
| Unit tests | `src/test/java` | `test` | Fast tests; must NOT depend on integration base classes |
| Integration tests | `src/test.slow/java` | `integrationTest` | Slow tests; can use `AbstractGhidraHeadlessIntegrationTest` etc. |
| P-Code tests | `src/test.processors/java` | `pcodeTest` | Processor emulation tests |

```bash
# Run all unit tests with report
gradle unitTestReport

# Run all integration tests with report
gradle integrationTestReport

# Run both unit + integration tests
gradle combinedTestReport

# Run tests for a single module
gradle :Base:test
gradle :SoftwareModeling:integrationTest

# Run a single test class within a module
gradle :Base:test --tests "ghidra.app.plugin.core.analysis.AnalysisManagerTest"
```

Tests fork a new JVM per test class (`forkEvery = 1`). Suite classes (`*Suite*`) are automatically excluded to prevent double-execution.

**Important:** Do not place tests that depend on integration base classes (e.g., `AbstractGhidraHeadlessIntegrationTest`) in `src/test/java` — they must go in `src/test.slow/java`.

For headless/CI testing on Linux, start Xvfb first:
```bash
Xvfb :99 -nolisten tcp &
export DISPLAY=:99
```

## Architecture

### Module Hierarchy

Modules are organized under `Ghidra/` in a layered architecture:

- **`Ghidra/Framework/`** — Core libraries (bottom of dependency graph)
  - `Generic` — Base utilities, logging (log4j)
  - `Utility` — Application framework bootstrap
  - `DB` — Object database framework (used by Programs and Traces)
  - `SoftwareModeling` — Program model: addresses, code units, data types, symbols, p-code
  - `Project` — Project/repository management
  - `Docking` — Swing docking window framework, actions, dialogs
  - `Graph`, `Gui`, `Help` — UI support libraries
  - `Emulation` — P-code emulator
  - `FileSystem` — File system abstraction for binary containers
  - `Pty` — Pseudo-terminal access

- **`Ghidra/Features/`** — Feature plugins built on Framework
  - `Base` — Core Ghidra functionality (CodeBrowser, importers, analyzers, scripting)
  - `Decompiler` — Decompiler UI + native C++ decompiler engine (`src/decompile/`)
  - `BSim` — Binary similarity analysis
  - `PDB` — PDB symbol parsing
  - `FunctionID` — Function identification databases
  - `PyGhidra` — Python 3 integration for Ghidra scripting
  - Various others (FileFormats, VersionTracking, BytePatterns, etc.)

- **`Ghidra/Debug/`** — Debugger subsystem (Trace RMI architecture)
  - `Framework-TraceModeling` — Database schema for recording machine state over time
  - `Debugger-api` — Debugger UI interfaces
  - `Debugger` — Debugger UI plugins/services
  - `Debugger-rmi-trace` — Protobuf-based Trace RMI protocol (Java server + Python client)
  - `Debugger-agent-gdb`, `Debugger-agent-lldb`, `Debugger-agent-dbgeng` — Platform connectors

- **`Ghidra/Processors/`** — Processor language definitions (Sleigh `.slaspec`/`.sinc` files, `.pspec`, `.cspec`, `.ldefs`)

- **`GPL/`** — GPL-licensed standalone modules (DMG, DemanglerGnu, GnuDisassembler) — must be independently buildable

### Gradle Build Structure

Each module's `build.gradle` applies mix-in scripts from `gradle/`:
- `gradle/javaProject.gradle` — Defines source sets, Java compilation, and Eclipse config
- `gradle/javaTestProject.gradle` — Wires module tests into the global test report tasks
- `gradle/distributableGhidraModule.gradle` — Makes module part of the distribution
- `gradle/helpProject.gradle` — Help system compilation
- `gradle/root/test.gradle` — Root-level test orchestration and report generation

Configuration is driven by `Ghidra/application.properties` (version, Java/Gradle/Python requirements).

### Key Patterns

- **Module dependencies** use Gradle `api`/`implementation` with project references (e.g., `api project(':SoftwareModeling')`)
- **Test fixture sharing**: Modules export test classes via `testArtifacts` configuration, consumed as `testImplementation project(path: ':Docking', configuration: 'testArtifacts')`
- **Sleigh** is a custom language for defining processor instruction semantics; `.slaspec` files compile to `.sla` via the Sleigh compiler
- **Native code** (decompiler) lives in `Ghidra/Features/Decompiler/src/decompile/` and builds via Gradle native tasks
- **Python packages** (debugger connectors) live in `src/main/py/` within their modules; rebuild after changes with `gradle assemblePyPackage`
- **Scripts** can be placed in `ghidra_scripts/` or `developer_scripts/` directories within modules

## Backbay Context

This repository is checked out at `standalone/reverend` within the Backbay multi-repo workspace. It is part of the Backbay ecosystem but builds independently via Gradle (not Moon/Bun).
