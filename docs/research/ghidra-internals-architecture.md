# Ghidra Internals and Architecture

This document provides a detailed analysis of Ghidra's internal architecture, derived from direct examination of the source code in this repository. It covers the core subsystems that make Ghidra extensible and retargetable: the p-code IR, the SLEIGH processor specification language, the native decompiler engine, the debugger/trace RMI architecture, extension points, and the database framework.

Verification note: repository-derived paths/classes/opcode counts in this document were spot-checked against this checkout (2026-02-19). Re-verify if the upstream tree changes.

---

## P-code Intermediate Representation

### Overview

P-code is Ghidra's retargetable intermediate representation (IR). Every machine instruction from every supported processor is translated (via SLEIGH) into a sequence of p-code operations. This single IR enables all of Ghidra's analysis -- disassembly, decompilation, emulation, symbolic reasoning -- to be written once and work across all architectures.

The core design principle: a small, fixed set of operations that are sufficient to express the semantics of any processor instruction. P-code is a register-transfer language with explicit memory spaces.

### Key Java Classes

- **`PcodeOp`** (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/PcodeOp.java`): Represents a single p-code operation. Each PcodeOp has an opcode (integer constant), a sequence number (address + ordering within that address), an array of input Varnodes, and an optional output Varnode.

- **`Varnode`** (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/Varnode.java`): Represents a storage location -- a (space, offset, size) triple. Varnodes can live in several address space types:
  - `TYPE_RAM` -- memory-mapped (`.isAddress()`)
  - `TYPE_REGISTER` -- register file (`.isRegister()`)
  - `TYPE_CONSTANT` -- immediate values (`.isConstant()`)
  - `TYPE_UNIQUE` -- temporaries (`.isUnique()`)

- **`PcodeOpAST`** / **`VarnodeAST`** (`PcodeOpAST.java`, `VarnodeAST.java`): Extended versions used in the decompiler's syntax tree (SSA form). VarnodeAST tracks def/use chains, merge groups, and high-level variable associations.

- **`PcodeSyntaxTree`** (`PcodeSyntaxTree.java`): Container for a complete function's p-code in SSA form, including VarnodeBank and PcodeOpBank for indexed access.

- **`HighFunction`** (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/HighFunction.java`): The high-level abstraction produced by the decompiler. Extends PcodeSyntaxTree and adds local/global symbol maps, function prototype, and jump tables.

- **`HighVariable`** (`HighVariable.java`): Groups multiple Varnodes that represent the same logical variable after decompiler analysis. Subtypes: `HighLocal`, `HighGlobal`, `HighParam`, `HighConstant`, `HighOther`.

### The P-code Operation Set

P-code defines 75 operations (opcodes 0-74, `PCODE_MAX = 75`), organized into categories:

**Data movement (0-3):**
- `UNIMPLEMENTED` (0) -- placeholder for unimplemented instructions
- `COPY` (1) -- register-to-register copy
- `LOAD` (2) -- memory read (dereference pointer in a specified space)
- `STORE` (3) -- memory write

**Control flow (4-10):**
- `BRANCH` (4) -- unconditional jump
- `CBRANCH` (5) -- conditional branch
- `BRANCHIND` (6) -- indirect branch (jump table)
- `CALL` (7) -- direct call
- `CALLIND` (8) -- indirect call
- `CALLOTHER` (9) -- special calling conventions / user-defined pcodeops
- `RETURN` (10) -- return from subroutine

**Integer arithmetic and comparison (11-36):**
- Comparisons: `INT_EQUAL`, `INT_NOTEQUAL`, `INT_SLESS`, `INT_SLESSEQUAL`, `INT_LESS`, `INT_LESSEQUAL`
- Extensions: `INT_ZEXT`, `INT_SEXT`
- Arithmetic: `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_SDIV`, `INT_REM`, `INT_SREM`
- Carry/borrow: `INT_CARRY`, `INT_SCARRY`, `INT_SBORROW`
- Bitwise: `INT_2COMP`, `INT_NEGATE`, `INT_XOR`, `INT_AND`, `INT_OR`
- Shifts: `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT`

**Boolean (37-40):** `BOOL_NEGATE`, `BOOL_XOR`, `BOOL_AND`, `BOOL_OR`

**Floating point (41-59):** Full set of float comparison, arithmetic, conversion, and rounding operations.

**Internal / SSA (60-74):**
- `MULTIEQUAL` (60) -- phi-node in SSA
- `INDIRECT` (61) -- indirect effect (e.g., call side effects)
- `PIECE` (62) / `SUBPIECE` (63) -- concatenation/extraction
- `CAST` (64) -- type cast
- `PTRADD` (65) / `PTRSUB` (66) -- pointer arithmetic
- `POPCOUNT` (72), `LZCOUNT` (73) -- bit counting

### How P-code Enables Retargetable Analysis

1. **All analysis algorithms operate on p-code, not native instructions.** The decompiler, emulator, data flow analysis, and symbolic execution all consume p-code. Adding a new processor only requires writing a SLEIGH specification.

2. **The Varnode address space model** abstracts away ISA differences. Whether a value is in a register, memory, or a temporary, the analysis treats it uniformly as a (space, offset, size) triple.

3. **CALLOTHER** with user-defined p-code operations allows modeling processor-specific semantics (e.g., CPUID, crypto instructions) without expanding the core opcode set.

### Comparison with Other Binary IRs

| Feature | P-code (Ghidra) | VEX (Valgrind/angr) | LLIL/MLIL/HLIL (Binary Ninja) | BAP BIL | GTIRB |
|---|---|---|---|---|---|
| **Abstraction level** | Single low-level IR | Single low-level IR | Three-tier (Low/Medium/High) | Single low-level IR | Container format, not an IR |
| **SSA form** | Yes (in decompiler) | No (uses temps) | Yes (MLIL-SSA, HLIL) | Yes (optional) | N/A (wraps existing IRs) |
| **Memory model** | Named address spaces (ram, register, unique, const) | Flat with temps | Named segments | Flat memory model | Address/section based |
| **Specification method** | SLEIGH (declarative) | Hand-written C lifters per ISA | Hand-written C++ lifters | BAP lifters | Lifters produce GTIRB |
| **Community extensibility** | High (SLEIGH specs are text) | Moderate (C code) | Moderate (C++ plugins) | Moderate | Format-level (language agnostic) |
| **Decompiler integration** | Tight (p-code is the decompiler's input) | Separate (angr uses its own) | Tight (three ILs are progressive) | Separate | N/A |

**Key differentiator for p-code:** The SLEIGH specification language means adding processor support is a *specification task*, not a *coding task*. This is Ghidra's primary advantage for retargetability.

---

## SLEIGH Processor Specification Language

### Overview

SLEIGH is a domain-specific language for describing instruction set architectures. A `.slaspec` file declares how bytes are decoded into assembly mnemonics and how those instructions map to p-code operations. Ghidra compiles `.slaspec` files into `.sla` (SLEIGH compiled) files used at runtime.

### File Structure and Organization

Processor specifications live under `Ghidra/Processors/<arch>/data/languages/`. For example, x86:

```
Ghidra/Processors/x86/data/languages/
  x86.slaspec          # Top-level spec (includes all sub-specs)
  ia.sinc              # Core x86 register/space definitions and instructions
  lockable.sinc        # Lock-prefix instructions
  avx.sinc             # AVX instruction extensions
  avx2.sinc            # AVX2 extensions
  avx512.sinc          # AVX-512 extensions
  sse.sinc             # SSE instructions
  macros.sinc          # Shared macros
  ...
```

The `.slaspec` is the master file; `.sinc` files are included via `@include`. For x86, `x86.slaspec` is minimal -- it includes `ia.sinc` (the core) and then all extension sets.

### SLEIGH Language Constructs

From examining `ia.sinc` (the x86 core specification):

**1. Preprocessor directives:**
```
@ifdef IA64           # Conditional compilation for 64-bit vs 32-bit
@define SIZE "8"      # Preprocessor variable
@endif
```

**2. Space definitions:**
```
define endian=little;
define space ram type=ram_space size=$(SIZE) default;
define space register type=register_space size=4;
```
Spaces model the processor's address spaces. `ram` is the default data space. `register` is the register file.

**3. Register definitions:**
```
define register offset=0 size=8 [ RAX RCX RDX RBX RSP RBP RSI RDI ];
define register offset=0 size=4 [ EAX _ ECX _ EDX _ EBX _ ESP _ EBP _ ESI _ EDI ];
define register offset=0 size=2 [ AX _ _ _ CX _ _ _ ... ];
define register offset=0 size=1 [ AL AH _ _ _ _ _ _ CL CH ... ];
```
Overlapping register definitions at the same offset model sub-register access (e.g., AL/AH/AX/EAX/RAX all overlap at offset 0). The `_` placeholder skips bytes.

**4. Token and bitfield definitions** define how instruction bytes are parsed into fields.

**5. Constructor tables** map bit patterns to assembly display and p-code semantics:
```
:ADD reg, imm  is opcode=0x81 & reg & imm {
    reg = reg + imm;    # This becomes INT_ADD p-code
}
```

**6. Macros** factor out common p-code patterns:
```
macro resultflags(result) {
    ZF = (result == 0);
    SF = (result s< 0);
}
```

### Supported Processors

The repository includes SLEIGH specifications for 38 processor families:

`6502`, `68000`, `8048`, `8051`, `8085`, `AARCH64`, `ARM`, `Atmel`, `BPF`, `CP1600`, `CR16`, `DATA`, `Dalvik`, `HCS08`, `HCS12`, `JVM`, `Loongarch`, `M16C`, `M8C`, `MC6800`, `MCS96`, `MIPS`, `NDS32`, `PA-RISC`, `PIC`, `PowerPC`, `RISCV`, `Sparc`, `SuperH`, `SuperH4`, `TI_MSP430`, `Toy`, `V850`, `Xtensa`, `Z80`, `eBPF`, `tricore`, `x86`

### Compilation Pipeline

The pipeline is: `.slaspec` + `.sinc` includes --> SLEIGH compiler --> `.sla` binary.

The SLEIGH compiler implementation lives in both Java and C++:
- Java side: `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/` -- includes `SleighInstructionPrototype.java`, `Constructor.java`, `ParserWalker.java`, the symbol table (`symbol/SymbolTable.java`), and template classes (`template/ConstructTpl.java`, `OpTpl.java`, `VarnodeTpl.java`).
- C++ side: The decompiler's `cpp/` directory includes the SLEIGH translator (`sleigh.hh/cc`, `sleighbase.hh/cc`).

At runtime, the compiled `.sla` file is loaded by `SleighLanguage` which uses the symbol table and constructor trees to decode instructions and emit p-code.

### Adding New Processor Support

To add a new processor:
1. Create `Ghidra/Processors/<NewArch>/data/languages/<newarch>.slaspec`
2. Define spaces, registers, tokens, and constructors
3. Create a `.ldefs` (language definition) file specifying endianness, size, compiler specs
4. Create a `.cspec` (compiler spec) for calling conventions
5. Compile with the SLEIGH compiler (integrated into the build)
6. Optionally add a `.pspec` (processor spec) for context and tracked registers

---

## Decompiler Native Engine

### Architecture

Ghidra's decompiler is a native C++ process (~115 `.cc` files, ~114 `.hh` files in `Ghidra/Features/Decompiler/src/decompile/cpp/`). It runs as a separate process that communicates with the Java GUI via stdin/stdout using a custom marshaling protocol.

### Key C++ Classes and Files

**Core architecture:**
- **`architecture.hh/cc`** -- `Architecture` base class: the central manager that ties together LoadImage, Translate (SLEIGH), Database (scope/symbol), TypeFactory, ContextDatabase, CommentDatabase, PcodeInjectLibrary, and ActionDatabase.

- **`ghidra_arch.hh/cc`** -- `ArchitectureGhidra`: Ghidra-specific subclass of Architecture. This is the bridge between the C++ decompiler and the Java front-end. It overrides all `build*` methods to create components backed by Ghidra client communication. Key query methods include:
  - `getPcode()` -- fetch raw p-code for an instruction
  - `getBytes()` -- read binary bytes from the Java LoadImage
  - `getMappedSymbolsXML()` -- retrieve symbols at an address
  - `getDataType()` -- fetch type information
  - `getTrackedRegisters()` -- get context at an address
  - `getComments()` -- retrieve user/auto comments

- **`ghidra_process.hh/cc`** -- `GhidraCommand` / `GhidraCapability`: The command dispatch system. The Java side sends named commands via stdin; `GhidraCapability::readCommand()` dispatches to the correct `GhidraCommand` subclass. Key commands include:
  - `DecompileAt` -- decompile a function at an address
  - `StructureGraph` -- emit the data/control-flow graph
  - `SetAction` -- configure decompilation actions
  - `SetOptions` -- set decompilation options

**Analysis pipeline:**
- **`funcdata.hh/cc`** -- `Funcdata`: The central object for a single function being decompiled. Contains the p-code syntax tree, basic blocks, local scope, and all intermediate state.

- **`action.hh/cc`** -- `Action`: Base class for decompilation transformations. The decompiler applies a sequence of Actions (rule-based transformations) to Funcdata.

- **`coreaction.hh/cc`** -- Registers the standard set of decompilation actions including constant propagation, dead code elimination, type propagation, and structure recovery.

- **`op.hh/cc`** -- `PcodeOp` (C++ side): The native p-code operation, with richer state than the Java counterpart (basic block membership, traversal iterators, flags for dead/boolean/call/branch etc.).

- **`varnode.hh/cc`** -- `Varnode` (C++ side): Rich SSA Varnode with cover sets, def/use chains, type information, and flags.

**Block/structure recovery:**
- **`block.hh/cc`** -- `BlockBasic`, `BlockGraph`, and structured block types (`BlockCondition`, `BlockWhileDo`, `BlockDoWhile`, `BlockIfElse`, `BlockSwitch`, etc.) used for control-flow structuring.

- **`blockaction.hh/cc`** -- Algorithms for collapsing the control-flow graph into structured blocks (if/else, loops, switches).

**Type system:**
- **`type.hh/cc`** -- `Datatype` and its subtypes: `TypeBase`, `TypePointer`, `TypeArray`, `TypeStruct`, `TypeUnion`, `TypeEnum`, `TypeCode` (function types), etc.
- **`cast.hh/cc`** -- Cast generation for the output C code.

**Output generation:**
- **`printc.hh/cc`** -- C language printer: converts the decompiled function tree into C source with markup tokens.

### Java-Native Interface

The decompiler process (`DecompileProcess`) is launched from Java as a separate native process. Communication uses a custom protocol over stdin/stdout:

1. Java side (`Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/`):
   - `DecompInterface.java` -- Main API for requesting decompilation
   - `DecompileProcess.java` -- Manages the native process lifecycle
   - `DecompileCallback.java` -- Handles queries FROM the decompiler (bytes, symbols, types)

2. Protocol: The decompiler sends queries to Java (e.g., "give me bytes at address X", "what's the data type for ID Y?"), Java responds, and the decompiler continues its analysis. Results are sent back as encoded XML/binary.

3. The `GhidraCommand` system on the C++ side receives top-level commands from Java, while `ArchitectureGhidra` methods handle sub-queries during decompilation.

### Decompilation Pipeline

The decompiler transforms a function through these stages:
1. **Instruction decoding** -- SLEIGH translates bytes to raw p-code
2. **P-code normalization** -- Basic block construction, dead code trimming
3. **SSA construction** -- Heritage algorithm converts to SSA (MULTIEQUAL = phi nodes, INDIRECT = side effects)
4. **Type propagation** -- Lattice-based type inference from known types
5. **Simplification rules** -- Hundreds of rules for constant folding, algebraic simplification, addressing mode recovery
6. **Structure recovery** -- Control flow graph collapsed into if/else, loops, switches
7. **Code generation** -- Emit C with proper casts, variable names, and comments

---

## Debugger / Trace RMI Architecture

### Overview

Ghidra's debugger (introduced in 10.0) uses a "Trace RMI" (Remote Method Invocation) architecture. The debugger does not embed GDB/LLDB directly -- instead, connector agents run alongside the target debugger and communicate with Ghidra's Java front-end via a protobuf-based protocol over TCP sockets.

### Architecture Components

```
  +------------------+          +-------------------+
  |  Ghidra Java UI  |<-------->| Trace RMI Server  |
  |  (Debugger       |  Proto   | (Java, in-process)|
  |   plugin)        |  buf/TCP |                   |
  +------------------+          +-------------------+
                                        ^
                                        | TCP socket
                                        v
                                +-------------------+
                                | Trace RMI Client  |
                                | (Python library:  |
                                |  ghidratrace)     |
                                +-------------------+
                                        ^
                                        | Debugger API
                                        v
                                +-------------------+
                                | Debugger Process  |
                                | (GDB / LLDB /     |
                                |  dbgeng / etc.)   |
                                +-------------------+
```

### The Trace RMI Protocol

Defined in `Ghidra/Debug/Debugger-rmi-trace/src/main/proto/trace-rmi.proto`. The protocol uses length-delimited protobuf messages wrapped in a `RootMessage` oneof.

**Message categories:**

1. **Connection lifecycle:** `RequestNegotiate`/`ReplyNegotiate` -- version handshake and method registration. The client declares its version (currently `VERSION = '12.0'`) and the set of methods it supports.

2. **Trace management:** `RequestCreateTrace`, `RequestSaveTrace`, `RequestCloseTrace` -- lifecycle of trace databases.

3. **Transaction control:** `RequestStartTx`/`RequestEndTx` -- all modifications to a trace must occur within a transaction (supports undo).

4. **Memory operations:** `RequestPutBytes`, `RequestDeleteBytes`, `RequestSetMemoryState`, `RequestPutRegisterValue`, `RequestDeleteRegisterValue` -- write machine state (memory contents, register values) into the trace at specific snapshots.

5. **Object model:** `RequestCreateRootObject`, `RequestCreateObject`, `RequestInsertObject`, `RequestRemoveObject`, `RequestSetValue`, `RequestRetainValues`, `RequestGetObject`, `RequestGetValues`, `RequestGetValuesIntersecting` -- a hierarchical object model that represents the debugger's target structure (processes, threads, frames, registers, breakpoints, memory regions).

6. **Analysis:** `RequestDisassemble` -- trigger disassembly at an address in the trace.

7. **UI:** `RequestActivate` -- set the active/focused object.

8. **Snapshots:** `RequestSnapshot` -- create time snapshots, supporting time-travel navigation.

9. **Method invocation:** `XRequestInvokeMethod`/`XReplyInvokeMethod` -- the server can invoke methods on the client (the debugger agent). This is the mechanism for actions like "step", "continue", "set breakpoint" flowing from the GUI to the debugger.

### Python Client Library

`Ghidra/Debug/Debugger-rmi-trace/src/main/py/src/ghidratrace/client.py` provides the Python-side implementation:

- **`Client`** -- manages the socket connection, message serialization, batch mode, and method dispatch. Supports asynchronous batching via `client.batch()` context manager for high-throughput updates.

- **`Trace`** -- proxy for a trace database on the server. Provides methods for `put_bytes()`, `put_registers()`, `snapshot()`, `create_object()`, etc. Maintains local state (current snap, overlays, transaction IDs).

- **`TraceObject`** -- proxy for an object in the trace's object model. Supports `insert()`, `remove()`, `set_value()`, `retain_values()`, `activate()`.

- **`MethodRegistry`** -- registers Python functions as remotely invocable methods. Uses type annotations to automatically determine parameter schemas (e.g., `Address`, `AddressRange`, `TraceObject`, `bool`, `int`, `str`).

- **`Batch`** -- accumulates `RemoteResult` futures for asynchronous operation. The batch context sends all RMI messages immediately but defers result processing, then joins all futures on exit.

### Connector Agents

Each debugger has a dedicated agent under `Ghidra/Debug/`:

- **`Debugger-agent-gdb`** -- GDB connector via GDB's Python API. Key files:
  - `src/main/py/src/ghidragdb/methods.py` -- registers GDB operations (step, continue, break, read memory/registers) as Trace RMI methods using `MethodRegistry`
  - `src/main/py/src/ghidragdb/commands.py` -- GDB CLI commands for trace synchronization
  - `src/main/py/src/ghidragdb/hooks.py` -- GDB event hooks (stop, new thread, exit) that trigger trace updates

- **`Debugger-agent-lldb`** -- LLDB connector (similar structure)
- **`Debugger-agent-dbgeng`** -- Windows Debug Engine connector
- **`Debugger-agent-drgn`** -- Linux kernel debugging via drgn
- **`Debugger-agent-x64dbg`** -- x64dbg connector
- **`Debugger-jpda`** -- Java debugger via JPDA

The agent pattern: agents use their debugger's native API to read target state, then push it to Ghidra's trace database via the Trace RMI protocol. The hierarchical object model (`Inferiors[N].Threads[N].Stack[N].Registers`) maps debugger concepts to a browsable tree in Ghidra's UI.

### Trace Database (Framework-TraceModeling)

`Ghidra/Debug/Framework-TraceModeling/` implements the trace database schema on the Java side:

- **`DBTrace*`** classes implement the trace storage: `DBTraceMemoryManager`, `DBTraceMemorySpace`, `DBTraceMemoryRegion`, `DBTraceBookmarkManager`, `DBTraceRegisterContextManager`, etc.
- Traces extend Ghidra's standard `DBHandle`-based storage (see Database Framework section).
- The trace records machine state at discrete **snapshots** (points in time). Each snapshot captures memory, registers, and object tree state. The UI can navigate between snapshots to provide time-travel analysis.
- **Lifespan** (min/max snap range) tracks when values are valid, enabling efficient queries like "what was register RAX at snap 5?"

---

## Extension Points and Plugin Model

### Analyzer Interface

See `Ghidra/Features/Base/src/main/java/ghidra/app/services/Analyzer.java`.

The `Analyzer` interface extends `ExtensionPoint` (Ghidra's classpath-based discovery mechanism). **All analyzer class names must end in "Analyzer"** for the `ClassSearcher` to find them.

Key interface methods:
- `getName()` / `getDescription()` -- identification
- `getAnalysisType()` -- what triggers the analyzer (e.g., bytes added, functions added, instructions added)
- `getPriority()` -- execution ordering (via `AnalysisPriority`)
- `canAnalyze(Program)` -- compatibility check (e.g., only run on ELF, only on ARM)
- `getDefaultEnablement(Program)` -- whether enabled by default
- `added(Program, AddressSetView, TaskMonitor, MessageLog)` -- **the main analysis method**, called when relevant data is added
- `removed(...)` -- called when data is removed
- `registerOptions(Options, Program)` / `optionsChanged(...)` -- configuration
- `analysisEnded(Program)` -- cleanup

The `AbstractAnalyzer` base class provides default implementations. Analyzers are discovered, instantiated, and scheduled by the Auto Analysis Manager based on their type and priority.

Example analyzers in the codebase: `DWARFAnalyzer`, `NoReturnFunctionAnalyzer`, `OperandReferenceAnalyzer`, `ExternalSymbolResolverAnalyzer`, `GolangStringAnalyzer`, `SwiftTypeMetadataAnalyzer`, `RustDemanglerAnalyzer`, `MachoFunctionStartsAnalyzer`.

### Plugin / Component Model

See `Ghidra/Framework/Project/src/main/java/ghidra/framework/plugintool/Plugin.java`.

Plugins are Ghidra's primary UI extension mechanism. Requirements for a well-formed plugin:
1. Derives from `Plugin`
2. Class name ends with "Plugin"
3. Has a `@PluginInfo` annotation declaring services consumed/provided
4. Has a constructor taking exactly one `PluginTool` parameter

Plugin lifecycle:
1. Constructor called (services registered, actions created, options registered)
2. `init()` called after all plugins in the tool are constructed
3. Plugin receives events via `processEvent(PluginEvent)` and option changes
4. `dispose()` called on tool closure

Plugins interact through **services** (interfaces registered/consumed via `@PluginInfo` annotations) and **events** (broadcast via the `PluginTool` event bus). This allows loose coupling -- a plugin can consume the `DecompilerService` without knowing which specific plugin provides it.

### Script Manager and Scripting APIs

Ghidra supports scripts in Java and Python (via Jython for Python 2.7, or via extensions like PyGhidra/Ghidrathon for Python 3):

- **GhidraScript** (`Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScript.java`) -- base class providing convenient methods (`currentProgram`, `currentAddress`, `getFunctionAt()`, `createData()`, etc.)
- Scripts are discovered from `ghidra_scripts/` directories
- Scripts can be run interactively, from the headless analyzer, or programmatically

### Headless Mode (analyzeHeadless)

`Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/`:

- **`AnalyzeHeadless.java`** -- entry point for command-line batch processing
- **`HeadlessAnalyzer.java`** -- orchestrates import, analysis, and script execution without a GUI
- **`HeadlessOptions.java`** -- command-line option parsing
- **`HeadlessScript.java`** -- base class for scripts that need headless-specific behavior (e.g., controlling analysis settings, setting post-analysis scripts)

Usage pattern:
```
analyzeHeadless <project_dir> <project_name> \
  -import <binary> \
  -postScript MyAnalysis.java \
  -scriptPath /path/to/scripts
```

The headless analyzer imports binaries, runs auto-analysis (all registered Analyzers), then executes pre/post scripts. This is the primary API for CI/CD integration and batch processing pipelines.

### Function ID System

`Ghidra/Features/FunctionID/`:

Function ID (FID) identifies library functions by computing hash signatures:

- **`FidHasher`** (`hash/FidHasher.java`) -- interface for computing function hashes
- **`FidHashQuad`** (`hash/FidHashQuad.java`) -- a "quad" of hashes: full hash, specific hash, and code unit counts, providing varying levels of specificity
- **`MessageDigestFidHasher`** -- SHA-256 based implementation
- **`FunctionExtentGenerator`** -- determines what bytes constitute a function body for hashing
- **`.fidb` databases** -- SQLite-based databases mapping hash signatures to function names/libraries
- **`FidPlugin`** -- UI integration for applying and managing FID databases
- **`ApplyFidEntriesCommand`** -- applies matched FID entries to a program

### BSim (Binary Similarity)

`Ghidra/Features/BSim/`:

BSim is Ghidra's binary similarity search system, more sophisticated than FID:

- Generates **feature vectors** from decompiled function p-code (not just byte hashes)
- Stores vectors in a database backend (PostgreSQL, Elasticsearch, or H2 file-based)
- Supports **cross-architecture similarity** because features are derived from p-code (architecture-neutral)
- Key classes: `BSimControlLaunchable`, `VectorStore`, `H2FileFunctionDatabase`, `ElasticDatabase`
- Scripts: `GenerateSignatures.java`, `QueryFunction.java`, `CompareBSimSignaturesScript.java`, `CompareExecutablesScript.java`

### P-code Emulation Framework

`Ghidra/Framework/Emulation/`:

- **`PcodeMachine`** / **`AbstractPcodeMachine`** -- generic p-code emulator that can execute any SLEIGH-defined ISA
- **`PcodeThread`** -- thread of execution within the emulator
- **`EmulatorHelper`** -- convenience wrapper for common emulation tasks
- **JIT compiler** (`ghidra/pcode/emu/jit/JitCompiler.java`) -- compiles p-code to JVM bytecode for faster emulation
- Used by the SystemEmulation feature (`Ghidra/Features/SystemEmulation/`) for full-system emulation with library stubs

---

## Database Framework

### Overview

Ghidra uses a custom object database framework (`Ghidra/Framework/DB/`) rather than an off-the-shelf database. This framework provides versioned, transactional storage for Programs, Traces, and other domain objects.

### Key Classes

See `Ghidra/Framework/DB/src/main/java/db/`:

- **`DBHandle`** (`DBHandle.java`) -- the primary database handle. Manages a `BufferMgr`, a `MasterTable` of all tables, and transaction lifecycle. Each Program or Trace has its own DBHandle.

- **`BufferMgr`** (`buffers/BufferMgr.java`) -- manages a page-oriented buffer cache. Data is stored in fixed-size buffer pages. Provides checkpoint/recovery support.

- **`Table`** -- a B-tree indexed table of records. Tables are created/accessed by name through the DBHandle.

- **`DBRecord`** -- a single record (row) in a table, with typed fields.

- **`Schema`** -- defines the column types for a table.

- **Buffer file hierarchy:**
  - `BufferFile` -- interface for reading/writing buffer pages
  - `LocalBufferFile` -- file-backed buffer storage
  - `ManagedBufferFile` -- adds versioning/change tracking
  - `LocalManagedBufferFile` -- managed file on local disk
  - `RecoveryFile` / `RecoveryMgr` -- crash recovery support

### How Programs Are Stored

A Ghidra Program (`.gzf` file) is a single managed buffer file containing:
- Memory blocks and their contents
- Symbol table (functions, labels, namespaces)
- Data types (archived and program-specific)
- Listing data (instructions, data, comments, references)
- Properties, bookmarks, equates
- Analysis state and options

Each major subsystem (memory, symbols, data types, etc.) has its own set of DB tables within the same DBHandle.

### Versioning and Merge Model

For shared projects (Ghidra Server):

1. **Check-out / Check-in model:** Users check out a program from the shared repository, make changes locally, and check in. The server maintains a version history.

2. **Version files:** `ManagedBufferFile` tracks changes via `ChangeMap` and `VersionFile`. Each version stores only the changed buffer pages (delta storage).

3. **Merge:** When two users modify the same program, Ghidra's merge facility (see `Ghidra/Features/ProgramDiff/`) identifies conflicts at multiple levels:
   - Byte-level conflicts in memory
   - Symbol naming conflicts
   - Data type conflicts
   - Listing conflicts (instructions, data, comments)

   Users resolve conflicts interactively through a merge wizard.

4. **Recovery:** `RecoveryMgr` provides crash recovery by maintaining checkpoint snapshots and a recovery file with uncommitted changes.

### Program Merge Framework

When two users modify the same program in a shared Ghidra Server project, the merge framework (`Ghidra/Features/Base/src/main/java/ghidra/app/merge/`) resolves conflicts across all program subsystems.

**Four-way merge model:**

The merge operates on four versions of the program simultaneously:
- **RESULT** -- the target program being built (starts as a copy of LATEST)
- **LATEST** -- the most recently checked-in version on the server
- **MY** -- the user's local modifications
- **ORIGINAL** -- the common ancestor (the version both users checked out from)

These are defined in `MergeConstants.java` and accessed via `ProgramMultiUserMergeManager.getProgram(int version)`.

**Merge resolver pipeline:**

`ProgramMultiUserMergeManager.createMergeResolvers()` instantiates eight `MergeResolver` implementations that run in sequence:

1. **`MemoryMergeManager`** -- resolves memory block additions, removals, and byte-level changes
2. **`ProgramTreeMergeManager`** -- resolves program tree (folder structure) conflicts using `ProgramChangeSet` data
3. **`DataTypeMergeManager`** -- resolves data type conflicts (added/modified/removed types across both change sets)
4. **`ProgramContextMergeManager`** -- resolves processor context register value conflicts
5. **`FunctionTagMerger`** -- resolves function tag (categorization) conflicts
6. **`ListingMergeManager`** -- the most complex resolver, handles code units, symbols, comments, references, equates, functions, bookmarks, properties, and source map entries
7. **`ExternalProgramMerger`** -- resolves conflicts in external symbols and references
8. **`PropertyListMergeManager`** -- resolves program property list conflicts

Each resolver implements the `MergeResolver` interface:
- `getName()` / `getDescription()` -- identification
- `merge(TaskMonitor)` -- performs the actual merge, presenting UI for user decisions on conflicts
- `apply()` -- notification that the user has resolved a conflict
- `cancel()` -- notification that the merge was cancelled
- `getPhases()` -- returns hierarchical phase identifiers for progress tracking

**Conflict detection and resolution strategies:**

The `ProgramMergeFilter` (`Ghidra/Features/Base/src/main/java/ghidra/program/util/ProgramMergeFilter.java`) defines 18 primary difference types that can be merged independently:

| Category | Types | Merge Strategy |
|---|---|---|
| **Memory** | `BYTES`, `PROGRAM_CONTEXT` | Replace only (no merge) |
| **Code units** | `INSTRUCTIONS`, `DATA` | Replace only |
| **Comments** | `PLATE_COMMENTS`, `PRE_COMMENTS`, `EOL_COMMENTS`, `REPEATABLE_COMMENTS`, `POST_COMMENTS` | Supports MERGE (combine from both) |
| **Symbols** | `SYMBOLS`, `PRIMARY_SYMBOL` | SYMBOLS supports MERGE, PRIMARY_SYMBOL is replace-only |
| **References** | `REFERENCES` | Replace only |
| **Functions** | `FUNCTIONS`, `FUNCTION_TAGS` | FUNCTIONS is replace-only, FUNCTION_TAGS supports MERGE |
| **Other** | `BOOKMARKS`, `PROPERTIES`, `EQUATES`, `SOURCE_MAP` | Replace only |

Each type can be set to `IGNORE` (skip), `REPLACE` (overwrite with source), or `MERGE` (combine both) where supported. Types like comments and symbols support true merging because multiple values can coexist, while types like bytes and instructions are inherently single-valued.

**Merge wizard architecture:**

The `ProgramMergeManagerPlugin` provides the UI framework. When a merge resolver encounters a conflict that requires user input, it calls `showComponent()` or `showListingMergePanel()` on the `ProgramMultiUserMergeManager`. The `ListingMergePanel` displays four synchronized listing views (Result, Latest, My, Original) side by side, allowing the user to see all versions and choose which changes to keep. The merge tool blocks on user input via `waitForInput()` and resumes when the user clicks Apply.

---

## Auto Analysis Manager

### Overview

The `AutoAnalysisManager` (`Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java`) is the central orchestrator for Ghidra's automated analysis pipeline. It manages the discovery, scheduling, and execution of all registered `Analyzer` implementations for a given `Program`.

### Manager Lifecycle

There is exactly one `AutoAnalysisManager` per `Program`, maintained in a static `WeakHashMap<Program, AutoAnalysisManager>`. Instances are obtained via the static factory method `getAnalysisManager(Program)`. When a program is closed, the manager disposes itself and removes its entry from the map.

### Analyzer Discovery and Registration

On construction, `initializeAnalyzers()` performs the following:

1. Creates six `AnalysisTaskList` instances, one per `AnalyzerType`:
   - `byteTasks` -- `BYTE_ANALYZER`: triggered when memory blocks are added
   - `instructionTasks` -- `INSTRUCTION_ANALYZER`: triggered when instructions are created
   - `functionTasks` -- `FUNCTION_ANALYZER`: triggered when functions are created
   - `functionModifierChangedTasks` -- `FUNCTION_MODIFIERS_ANALYZER`: triggered when function modifiers change (thunk, inline, noreturn, call-fixup, purge)
   - `functionSignatureChangedTasks` -- `FUNCTION_SIGNATURES_ANALYZER`: triggered when function parameters or return types change
   - `dataTasks` -- `DATA_ANALYZER`: triggered when data is created

2. Uses `ClassSearcher.getInstances(Analyzer.class)` to discover all `Analyzer` implementations on the classpath. For each analyzer:
   - Calls `canAnalyze(program)` to check compatibility (e.g., architecture, format)
   - Routes it to the appropriate `AnalysisTaskList` based on `getAnalysisType()`
   - Each task list wraps each analyzer in an `AnalysisScheduler`

3. Registers and initializes all analyzer options from the program's stored analysis properties.

### The AnalysisScheduler

Each analyzer is wrapped in an `AnalysisScheduler` (`AnalysisScheduler.java`) that manages its state:

- Maintains an `addSet` and `removeSet` of addresses that need processing
- Tracks enabled/disabled state (from user options and `.pspec` overrides)
- On `added(address)` or `removed(address)`, accumulates addresses into the sets
- When addresses are pending, calls `schedule()` which places an `AnalysisTask` onto the manager's priority queue at the analyzer's priority level
- `runAnalyzer()` atomically swaps out the accumulated address sets and calls `analyzer.added()` / `analyzer.removed()`

Language-level `.pspec` files can override analyzer enablement via `DisableAllAnalyzers` and `Analyzers.<name>` properties.

### Priority System

`AnalysisPriority` defines a tiered priority system where lower numeric values mean higher priority. The standard priority tiers (each separated by 100) are:

| Priority | Name | Value | Purpose |
|---|---|---|---|
| 1 | FORMAT | 100 | Full-format analysis (ELF headers, PE parsing) |
| 2 | BLOCK | 200 | Block-level analysis, initial entry point disassembly |
| 3 | DISASSEMBLY | 300 | Flow-based code disassembly |
| 4 | CODE | 400 | Instruction-level analysis, non-returning function detection |
| 5 | FUNCTION | 500 | Function creation and analysis |
| 6 | REFERENCE | 600 | Reference recovery |
| 7 | DATA | 700 | Data creation (strings, pointers) |
| 8 | FUNCTION_ID | 800 | Function identification (FID, library matching) |
| 9 | DATA_TYPE_PROPAGATION | 900 | Data type propagation (should run last) |

Each priority supports `.before()` and `.after()` to create fine-grained ordering within a tier. `HIGHEST_PRIORITY` is 1 and `LOW_PRIORITY` is 10000.

### The Analysis Trigger System

The `AutoAnalysisManager` listens for program change events via a `DomainObjectListener` created by `createDomainObjectListener()`. The listener uses a builder pattern to route events:

| Event | Handler | Task List Notified |
|---|---|---|
| `CODE_ADDED` (when Data) | `handleCodeAdded()` | `dataTasks` |
| `FUNCTION_ADDED`, `FUNCTION_BODY_CHANGED` | `handleFunctionAddedOrBodyChanged()` | `functionTasks` |
| `FUNCTION_CHANGED` (signature) | `handleFunctionChanged()` | `functionSignatureChangedTasks` |
| `FUNCTION_CHANGED` (modifiers) | `handleFunctionChanged()` | `functionModifierChangedTasks` |
| `FUNCTION_REMOVED` | direct | `functionTasks` (removed) |
| `FALLTHROUGH_CHANGED`, `FLOW_OVERRIDE_CHANGED`, `LENGTH_OVERRIDE_CHANGED` | `handleOverrides()` | `instructionTasks` |
| `LANGUAGE_CHANGED` | `initializeAnalyzers()` | (re-discovers all analyzers) |

Additionally, explicit API calls trigger analysis:
- `blockAdded(set)` -> `byteTasks`
- `codeDefined(addr/set)` -> `instructionTasks`
- `dataDefined(set)` -> `dataTasks`
- `functionDefined(addr/set)` -> `functionTasks`
- `externalAdded(addr)` -> `byteTasks`

### Analyzer Chaining and the Yield Mechanism

Analyzers chain naturally through the event system. When one analyzer creates new artifacts, the resulting program change events trigger other analyzers:

```
Import binary
  -> blockAdded() -> BYTE_ANALYZER triggers (e.g., format analyzers find entry points)
    -> disassemble() -> codeDefined() -> INSTRUCTION_ANALYZER triggers
      -> createFunction() -> functionDefined() -> FUNCTION_ANALYZER triggers
        -> type/reference changes -> FUNCTION_SIGNATURES_ANALYZER, etc.
```

The **yield mechanism** prevents higher-priority tasks from being starved. When an analyzer calls `disassemble()` or `createFunction()`, the manager schedules those commands at a priority just above the current task's priority. The `startAnalysis()` method checks if the current thread is the analysis thread; if so, it calls `yield()` which processes all queued tasks with priority higher (lower numeric value) than the current task before returning control to the current analyzer.

### One-shot vs. Recurring Analyzers

- **Recurring analyzers** are the standard pattern: registered once, triggered repeatedly as their event type fires. They accumulate addresses in their `AnalysisScheduler` and process them in batches.

- **One-shot analyzers** are scheduled via `scheduleOneTimeAnalysis(Analyzer, AddressSetView)`. This wraps the analyzer in a `OneShotAnalysisCommand` and schedules it at the analyzer's priority. The analyzer is not registered in any task list; it runs exactly once on the specified address set. This is useful for user-initiated analysis of specific regions.

### Thread Pool and Parallel Analysis

The `AutoAnalysisManager` provides a shared thread pool via `getSharedAnalsysThreadPool()` (sic). This `GThreadPool` is statically shared across all tools and programs, with a configurable maximum thread count (default: system CPU count). Individual analyzers can use this pool for internal parallelism, but only one analyzer runs at a time in the analysis pipeline itself.

---

## DataTypeManager API Deep Dive

### Overview

The `DataTypeManager` interface (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataTypeManager.java`) is the central API for managing all data types in Ghidra. It provides methods for creating, resolving, searching, and organizing types within categories.

### Implementation Hierarchy

```
DataTypeManager (interface)
  └── DataTypeManagerDB (abstract, DB-backed)
       ├── StandAloneDataTypeManager
       │    └── FileDataTypeManager (.gdt archives)
       └── ProgramBasedDataTypeManagerDB (abstract)
            └── ProgramDataTypeManager (lives inside a Program)
```

- **`ProgramDataTypeManager`** (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/data/ProgramDataTypeManager.java`): The data type manager embedded in every `ProgramDB`. It is created as part of the program's database and shares the program's transaction system. It has full access to the program's architecture (language, compiler spec, data organization). Changes to types fire `ProgramEvent.DATA_TYPE_SETTING_CHANGED` events.

- **`FileDataTypeManager`** (`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/FileDataTypeManager.java`): The standalone data type manager for `.gdt` (Ghidra Data Type) archive files. Extends `StandAloneDataTypeManager` and uses a `PackedDatabase` for file-backed storage. Archives can optionally be associated with a specific program architecture.

- **`StandAloneDataTypeManager`**: A data type manager not tied to any program. Used for in-memory type manipulation and as the base for file archives.

### Creating Types Programmatically

All type creation goes through the `DataTypeManager` interface. The general pattern is:

1. Create a type object (in-memory, not yet persisted)
2. Call `addDataType()` or `resolve()` to add it to the manager with conflict handling
3. The returned type is the manager-owned instance (may differ from input if conflicts were resolved)

**Structures:**
```java
StructureDataType myStruct = new StructureDataType("MyStruct", 0); // 0 = auto-size
myStruct.add(IntegerDataType.dataType, "field1", "first field");
myStruct.add(PointerDataType.dataType, "ptr", "a pointer");
DataType resolved = dtm.addDataType(myStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
```

**Enums:**
```java
EnumDataType myEnum = new EnumDataType("ErrorCode", 4); // 4-byte enum
myEnum.add("SUCCESS", 0);
myEnum.add("FAILURE", 1);
myEnum.add("TIMEOUT", 2);
DataType resolved = dtm.addDataType(myEnum, DataTypeConflictHandler.DEFAULT_HANDLER);
```

**Function signatures:**
```java
FunctionDefinitionDataType sig = new FunctionDefinitionDataType("my_callback");
sig.setReturnType(IntegerDataType.dataType);
sig.setArguments(new ParameterDefinition[] {
    new ParameterDefinitionImpl("ctx", PointerDataType.dataType, "context"),
    new ParameterDefinitionImpl("size", UnsignedIntegerDataType.dataType, "buffer size")
});
DataType resolved = dtm.addDataType(sig, DataTypeConflictHandler.DEFAULT_HANDLER);
```

**Typedefs:**
```java
TypedefDataType handle = new TypedefDataType("HANDLE", PointerDataType.dataType);
DataType resolved = dtm.addDataType(handle, DataTypeConflictHandler.DEFAULT_HANDLER);
```

**Unions:**
```java
UnionDataType u = new UnionDataType("ValueUnion");
u.add(IntegerDataType.dataType, "asInt", null);
u.add(FloatDataType.dataType, "asFloat", null);
DataType resolved = dtm.addDataType(u, DataTypeConflictHandler.DEFAULT_HANDLER);
```

### Type Resolution and Conflict Handling

When adding a type to a manager that already contains a type with the same name and category path, the `DataTypeConflictHandler` determines the outcome:

- **`DEFAULT_HANDLER`** -- renames the new type with a `.conflict` suffix if a conflict exists
- **`REPLACE_HANDLER`** -- replaces the existing type with the new one
- **`KEEP_HANDLER`** -- keeps the existing type, discards the new one
- **`REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER`** -- replaces if the existing type is an empty structure, otherwise renames

The `resolve()` method is similar to `addDataType()` but performs equivalence checking: if the manager already contains an equivalent type, it returns the existing one. This is critical for avoiding duplicate types when importing from archives or applying analyzer results.

The `addDataTypes(Collection, handler, monitor)` method provides batch addition with equivalence caching for improved performance, though it holds the manager lock for extended periods.

### Categories

Types are organized in a hierarchical category tree (like a filesystem). The root category is accessed via `getRootCategory()`. New categories are created with `createCategory(CategoryPath)`:

```java
Category myCategory = dtm.createCategory(new CategoryPath("/MyProject/Structs"));
```

Types can be looked up by category path and name:
```java
DataType dt = dtm.getDataType(new CategoryPath("/MyProject/Structs"), "MyStruct");
```

### Data Type Archives (.gdt files)

`.gdt` files are standalone type databases created with `FileDataTypeManager`. They serve as reusable type libraries.

**How archives work:**
- Archives use `PackedDatabase` (a single-file DB format) for portable storage
- They can be opened in `CREATE`, `READ_ONLY`, or `UPDATE` mode
- Archives can optionally store a program architecture (`ProgramArchitecture`) to associate types with a specific platform's data organization (sizes, alignment, endianness)
- The `FileDataTypeManager.EXTENSION` is `"gdt"` and the suffix is `".gdt"`

**Syncing types between programs and archives:**

Types can be associated with a source archive via `associateDataTypeWithArchive(datatype, archive)`. This creates a link between the program's type and the archive type using `UniversalID`s. When an archive is updated, the program can detect out-of-date types and offer to sync them.

The `disassociate(datatype)` method breaks the link, making the type local to the program.

`SourceArchive` objects track the relationship:
- `getSourceArchives()` returns all archives linked to this manager
- `getDataTypes(SourceArchive)` returns types originating from a specific archive
- `resolveSourceArchive(SourceArchive)` persists an archive reference

### Transaction Model

All modifications to a `DataTypeManager` must occur within a transaction:

```java
// Modern try-with-resources pattern:
try (Transaction tx = dtm.openTransaction("Add types")) {
    dtm.addDataType(myStruct, handler);
    dtm.addDataType(myEnum, handler);
}

// Lambda pattern:
dtm.withTransaction("Add types", () -> {
    dtm.addDataType(myStruct, handler);
});
```

For `ProgramDataTypeManager`, transactions are shared with the parent `Program`'s transaction system. Nested transactions are supported; the full transaction is not committed until all nested transactions complete.

---

## P-code Emulator JIT Details

### Overview

The JIT (Just-in-Time) compiler (`Ghidra/Framework/Emulation/src/main/java/ghidra/pcode/emu/jit/JitCompiler.java`) translates decoded p-code passages into JVM bytecode for dramatically faster emulation compared to interpretation. This is a sophisticated multi-phase translation engine.

### Architecture

The JIT system consists of three main components:

- **`JitPcodeEmulator`** (`JitPcodeEmulator.java`): Near drop-in replacement for `PcodeEmulator`. Manages a cache of compiled passages, decoding and compiling them on demand. Uses `JitPassageDecoder` to decode instruction sequences into passages at requested entry points.

- **`JitCompiler`** (`JitCompiler.java`): The translation engine that converts a decoded passage (a collection of connected instruction strides) into a JVM classfile.

- **`JitCompiledPassage`** / **`JitCompiledPassageClass`**: The compiled output. Each passage becomes a Java class with a `run(int)` method. The class is loaded as a JVM hidden class via `MethodHandles.Lookup`.

### Translation Pipeline

The compiler performs seven analysis phases before generating bytecode:

1. **Control Flow Analysis** (`JitControlFlowModel`): Breaks instruction strides into p-code basic blocks. This is finer-grained than instruction-level blocks because a single machine instruction can contain internal p-code branches. Branches leaving an instruction preclude execution of remaining p-code ops.

2. **Data Flow Analysis** (`JitDataFlowModel`): Interprets each basic block abstractly to produce a use-def graph. Missing variables (reads before writes) become phi nodes. Handles aliasing, partial register accesses, and overlapping accesses by synthesizing operations for those effects.

3. **Variable Scope Analysis** (`JitVarScopeModel`): Determines which variables are alive in which basic blocks. This enables scope-based optimization: register and unique-space variables can be allocated as JVM locals instead of reading/writing the emulator state for every access. Variables are "born" (read from state) when entering scope and "retired" (written back) when leaving scope.

4. **Type Assignment** (`JitTypeModel`): Assigns JVM types to variables. The JVM has four relevant primitives: `int`, `float`, `long`, `double`. The JVM does not permit type confusion (e.g., float-add on int variables), so when the emulation target intentionally reinterprets bits (like the classic "fast inverse square root" trick with `0x5f759df`), explicit bit-cast calls like `Float.floatToRawIntBits()` are inserted.

5. **Variable Allocation** (`JitAllocationModel`): Allocates JVM local variable slots. Variables are allocated by varnode. Partial/overlapping accesses are coalesced to the containing varnode with int type (for shifting/masking). Types are assigned by majority vote among use-def nodes sharing a varnode.

6. **Operation Elimination** (`JitOpUseModel`): Removes dead p-code operations whose outputs are never consumed. This is particularly important for flag computations (common in most ISAs) which the JVM has no native support for -- computing flags requires expensive bit-banging operations. This phase is togglable via `JitConfiguration.removeUnusedOperations()` because eliminated operations may confuse users inspecting interrupted execution state.

7. **Code Generation** (`JitCodeGenerator`): Emits JVM bytecode using the ASM library (`org.objectweb.asm`). Generates the classfile in p-code op order with optimizations from all preceding phases. Handles variable birth/retirement on control flow edges, entry point dispatch, and type conversions.

### Performance Characteristics

- **Compilation cost**: The seven-phase analysis plus bytecode generation has a one-time cost per passage. Passages are cached by the `JitPcodeEmulator`, so recompilation only occurs if the emulation target code changes.

- **Execution speed**: JIT-compiled passages run at near-native JVM speed. Register and unique-space variables become JVM locals (register-allocated by the JVM's own JIT), eliminating the overhead of hash-map lookups in `PcodeExecutorState`. Memory accesses still go through the state object.

- **Passage sizing**: A passage is a collection of connected instruction strides (decoded starting from a seed address, following direct branches). Large passages may exceed JVM method size limits (`MethodTooLargeException`), in which case the emulator falls back to smaller passages or interpretation.

### Diagnostics and Debugging

The `JitCompiler.Diag` enum provides diagnostic toggles for development:
- `PRINT_PASSAGE` -- dump decoded passage before translation
- `PRINT_CFM` / `PRINT_DFM` / `PRINT_VSM` -- dump control flow, data flow, and scope analysis
- `PRINT_SYNTH` -- dump synthesized operations (phi nodes, partial accesses)
- `PRINT_OUM` -- dump eliminated operations
- `TRACE_CLASS` -- enable ASM's bytecode trace for generated classfiles
- `DUMP_CLASS` -- save `.class` files to disk for offline examination (e.g., with `javap`)

### Extension Points for Custom Emulation

- **Custom userop libraries**: `PcodeUseropLibrary` implementations are automatically available to JIT-compiled passages via the `MethodHandles.Lookup` passed to `compilePassage()`.
- **State customization**: `JitBytesPcodeExecutorState` handles memory reads/writes during JIT execution. Custom state implementations can intercept memory operations for instrumentation or symbolic execution.
- **Configuration**: `JitConfiguration` controls behavior like operation elimination and passage sizing.

---

## Headless API Patterns for CI/CD

### Overview

The headless analyzer (`Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/HeadlessAnalyzer.java`) provides a programmatic API for running Ghidra's full analysis pipeline without a GUI. It is the primary integration point for CI/CD pipelines, batch processing, and automated reverse engineering workflows.

### Core Architecture

`HeadlessAnalyzer` is a singleton obtained via `getInstance()` or `getLoggableInstance()`. It enforces single-instance semantics because Ghidra's global state (application initialization, classpath scanning, etc.) cannot support concurrent instances within a single JVM.

Key classes:
- **`HeadlessAnalyzer`** -- orchestrates the entire headless workflow
- **`HeadlessOptions`** -- all configurable options (scripts, analysis settings, timeouts, import parameters)
- **`AnalyzeHeadless`** -- command-line entry point that parses arguments into `HeadlessOptions`
- **`HeadlessScript`** -- base class for scripts that need headless-specific behavior (e.g., controlling whether analysis continues or aborts)

### Processing Modes

The headless analyzer operates in two primary modes:

**Import mode** (`processLocal` / `processURL` without `-process` flag):
1. Creates or opens a Ghidra project
2. Imports files using the configured loader (auto-detected or specified via `-loader`)
3. Runs pre-scripts
4. Runs auto-analysis (all registered Analyzers via `AutoAnalysisManager`)
5. Runs post-scripts
6. Re-analyzes if post-scripts made changes
7. Saves the program to the project
8. Optionally commits to a shared repository

**Process mode** (`-process` flag):
1. Opens an existing Ghidra project
2. Iterates over existing program files (optionally filtered by name/pattern)
3. For each file: runs pre-scripts -> analysis -> post-scripts
4. Saves changes

### Practical Patterns

**Batch import with analysis:**
```bash
analyzeHeadless /projects MyProject \
  -import /binaries/*.exe \
  -recursive \
  -postScript ExportDecompilation.java \
  -scriptPath /my/scripts
```

**Scripted analysis on existing project:**
```bash
analyzeHeadless /projects MyProject \
  -process "target.exe" \
  -preScript ApplyTypes.java \
  -postScript ExtractResults.java \
  -noanalysis  # skip auto-analysis, just run scripts
```

**Programmatic API usage (as a library):**
```java
HeadlessAnalyzer analyzer = HeadlessAnalyzer.getInstance();
HeadlessOptions options = analyzer.getOptions();
options.setAnalyze(true);
options.setPerFileTimeout(300); // 5-minute timeout per file

// Add scripts
options.addPreScript("PrepareAnalysis.java");
options.addPostScript("ExtractResults.java");

// Process
analyzer.processLocal("/projects", "MyProject", "/", filesToImport);
```

### Script Chaining and Control Flow

Scripts communicate state through the `GhidraState` object, which is shared across all pre/post scripts for a given file:

```java
// In PreScript.java:
state.setEnvironmentVar("ANALYSIS_MODE", "deep");

// In PostScript.java:
String mode = (String) state.getEnvironmentVar("ANALYSIS_MODE");
```

`HeadlessScript` extends `GhidraScript` with headless-specific control:
- `setHeadlessContinuationOption(CONTINUE)` -- proceed normally
- `setHeadlessContinuationOption(ABORT)` -- stop processing this file
- `setHeadlessContinuationOption(ABORT_AND_DELETE)` -- stop and delete the file from the project
- `setHeadlessContinuationOption(CONTINUE_THEN_DELETE)` -- finish scripts, then delete

The headless analyzer also supports:
- **Per-file timeouts** via `options.perFileTimeout` -- analysis is cancelled if it exceeds the timeout
- **Storage** -- scripts can share key-value data across files via `headlessInstance.addVariableToStorage()`
- **Save folder redirection** -- scripts can change where the program is saved via `headlessInstance.setSaveFolder()`

### Analysis Pipeline Integration

The `analyzeProgram()` method in `HeadlessAnalyzer` orchestrates the analysis for each file:

1. Gets the `AutoAnalysisManager` for the program
2. Initializes analyzer options
3. Runs pre-scripts (each can abort or modify analysis)
4. Calls `mgr.reAnalyzeAll(null)` to queue all analyzers for the entire program
5. Calls `mgr.startAnalysis(monitor)` to execute the analysis queue
6. Optionally enforces a per-file timeout via `HeadlessTimedTaskMonitor`
7. Runs post-scripts
8. If post-scripts made changes and analysis is enabled, runs `startAnalysis()` again to process those changes

### Integration with PyGhidra

PyGhidra (`Ghidra/Features/PyGhidra/`) provides Python 3 access to Ghidra's Java APIs via JPype. For headless workflows:

- **`PyGhidraProject`** extends `DefaultProject` for Python-driven project access
- **`PyGhidraScriptProvider`** enables running Python 3 scripts through the headless analyzer
- Python scripts have full access to the Ghidra API, including `currentProgram`, `FlatProgramAPI`, and all manager interfaces

A typical PyGhidra headless workflow:
```python
import pyghidra
pyghidra.start()

from ghidra.app.util.headless import HeadlessAnalyzer
from java.io import File

analyzer = HeadlessAnalyzer.getInstance()
analyzer.processLocal("/projects", "MyProject", "/", [File("/path/to/binary")])
```

This enables Python-based CI/CD pipelines to leverage Ghidra's full analysis capabilities programmatically, combining Python's ecosystem (ML libraries, data processing) with Ghidra's reverse engineering engine.

---

## Key Extension Points for Roadmap Items

This section maps Ghidra's internal architecture to the roadmap features identified in the deep research report.

### Semantic Search / Binary Similarity at Scale
- **Extension point:** BSim feature vector system (`Ghidra/Features/BSim/`) -- already generates p-code-based feature vectors
- **Integration path:** Replace/augment BSim's hash-based vectors with neural embeddings (transformer models operating on p-code). The `FidHasher` interface and `VectorStore` backend provide the integration surface.
- **Key files:** `Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/`, `GenerateSignatures.java`

### Type Recovery and Type Workflows
- **Extension point:** The decompiler's type propagation system (C++ side: `type.hh/cc`, `typeop.hh/cc`; Java side: `HighFunction`, `HighVariable`, `PcodeDataTypeManager`)
- **Integration path:** External ML type recovery models can be integrated as Analyzers that post-process decompiler output and apply inferred types. The `DataTypeManager` API allows programmatic type creation and application.
- **Key files:** `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataTypeManager.java`

### Improved Diffing / Version Tracking
- **Extension point:** Version Tracking correlators (`Ghidra/Features/VersionTracking/`)
- **Integration path:** New correlators can be registered as plugins. Correlators that use neural embeddings or semantic features can be added alongside existing hash/instruction-based correlators.
- **Key files:** `Ghidra/Features/VersionTracking/src/main/java/ghidra/feature/vt/api/correlator/`

### Dynamic-Static Fusion
- **Extension point:** Trace RMI protocol and connector agents
- **Integration path:** New debugger connectors follow the agent pattern (Python script using `ghidratrace.client` library). Custom connectors for emulators (Unicorn, QEMU), fuzzers, or symbolic execution engines can push state into Ghidra's trace database.
- **Key files:** `Ghidra/Debug/Debugger-rmi-trace/src/main/proto/trace-rmi.proto`, `ghidratrace/client.py`

### ML/LLM Integration
- **Extension point:** Analyzer interface (for automated suggestions), Script API (for interactive copilot), Plugin model (for UI integration)
- **Integration path:** An LLM integration can be an Analyzer that processes functions after decompilation (using `DecompInterface` API), or a Plugin providing a chat/suggestion panel. The headless API supports batch ML-assisted analysis.
- **Key files:** `Ghidra/Features/Base/src/main/java/ghidra/app/services/Analyzer.java`, `Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/HeadlessAnalyzer.java`

### New Processor Support
- **Extension point:** SLEIGH specification language
- **Integration path:** Write `.slaspec`/`.sinc` files, `.ldefs`, `.cspec`, `.pspec`. No Java/C++ code required for basic support.
- **Key files:** `Ghidra/Processors/<arch>/data/languages/`

### P-code Emulation and Symbolic Execution
- **Extension point:** Emulation framework (`Ghidra/Framework/Emulation/`), particularly `PcodeMachine` and `PcodeThread`
- **Integration path:** Custom `PcodeStateInitializer` and `PcodeEmulationCallbacks` can inject symbolic state or custom memory models. The JIT compiler (`JitCompiler.java`) can be extended for performance-critical emulation.
- **Key files:** `Ghidra/Framework/Emulation/src/main/java/ghidra/pcode/emu/`

### Collaboration and Knowledge Reuse
- **Extension point:** Ghidra Server shared project model (check-out/check-in with merge), Function ID databases, BSim databases
- **Integration path:** The database versioning system (`ManagedBufferFile`, `VersionFile`) and merge framework can be extended. A "knowledge service" could be built as a server-side component that aggregates FID/BSim data across users.
- **Key files:** `Ghidra/Framework/DB/src/main/java/db/buffers/ManagedBufferFile.java`, `Ghidra/Features/GhidraServer/`
