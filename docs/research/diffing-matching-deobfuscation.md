# Binary Diffing, Function Matching, and Deobfuscation

Research survey covering binary diffing tools, function identification technologies, interchange formats, patch diffing workflows, and deobfuscation techniques. Focused on the state of the art as of early 2026 with emphasis on Ghidra integration opportunities.

Verification note (as of 2026-02-19): tool support matrices (plugins, version compatibility, maintenance status) are high-churn and should be revalidated before use in production workflows.

---

## Binary Diffing Tools

### BinDiff

**Origin:** Developed by Halvar Flake and Thomas Dullien at zynamics GmbH (est. ~2004). Google acquired zynamics in 2011. BinDiff was made free in 2016 and fully open-sourced under Apache 2.0 in 2023.

**How it works:** BinDiff uses graph-based matching algorithms to compare two disassembled binaries. It operates on exported call graphs and control flow graphs, applying a cascade of heuristics -- instruction-level matching, basic block matching via graph isomorphism, and call graph structural similarity -- to identify corresponding functions across versions. The algorithm propagates confident matches outward through the call graph to resolve ambiguous cases.

**Current status:** Open source on GitHub (google/bindiff). Ships with plugins for IDA Pro, Binary Ninja, and Ghidra. Remains the most widely-used binary diffing tool in vulnerability research and malware analysis. Licensed Apache 2.0.

**Ghidra integration:** BinDiff includes an official Ghidra export plugin. The third-party BinDiffHelper extension (ubfx/BinDiffHelper) adds workflow automation: it runs BinDiff on Ghidra projects and renames matched functions automatically. Supports BinDiff 6, 7, and 8.

### Diaphora

**Origin:** Created by Joxean Koret. The most advanced free and open-source program diffing tool, primarily targeting IDA Pro.

**Capabilities:**
- Assembler and control flow graph diffing
- Pseudo-code diffing with syntax highlighting (requires Hex-Rays decompiler)
- Pseudo-code patch generation
- Porting of symbol names, comments, structs, enums, and typedefs
- Parallel diffing for large binaries
- Call graph matching
- Batch automation and scripting support for export/diff processes
- Experimental Ridge classifier for learning good matches per binary pair
- Local diffing mode (comparing functions within a single binary)

**Platform:** Supports IDA 7.4+ (Python 3.x). Main branch requires IDA >= 7.4; legacy branch supports IDA 6.9+.

**Relevance:** Diaphora's decompiler-driven heuristics produce high-quality matches that go beyond what pure graph-based approaches achieve. Its ability to port structs and typedefs is particularly valuable for cross-version analysis.

### Ghidra Version Tracking

**Overview:** Ghidra's built-in Version Tracking system was designed for two primary purposes: (1) porting previous reverse engineering work (comments, labels, data types -- collectively called "markup") to new binary versions, and (2) determining whether code in an old binary exists in a new one and vice versa.

**Correlators:** Any algorithm that determines relationships between program versions is called a "correlator" in Ghidra's terminology. The system includes several built-in correlators and supports an Automatic Version Tracking mode that runs correlators in a predetermined order, automatically creating and accepting high-confidence matches and applying markup.

**Markup porting:** For any matched function pair, analysts can selectively apply markup items (comments, labels, data types, variable names) so that annotations appear at corresponding locations in the new binary.

**PatchDiff Correlator (third-party):** The ghidra-patchdiff-correlator project (threatrack) adds correlators that produce similarity scores below 1.0, enabling detection of *modified* (not just identical) functions. This is essential for patch diffing where the goal is finding what changed, not just what stayed the same.

**BSim (Behavior Similarity):** Introduced in Ghidra 11.0 (2023). BSim generates function signatures from the decompiler's high p-code representation, meaning it works across all architectures Ghidra supports. It uses a PostgreSQL or H2 backend for similarity search at scale. The BSim Program Correlator integrates with Version Tracking, using decompiler-derived confidence scores and call graph structure to boost and disambiguate matches.

### ghidriff

**Origin:** Created by clearbluejar (2023). A Python command-line tool for binary diffing built on Ghidra's headless analysis via PyGhidra/JPype.

**Key features:**
- Single-command patch diffing
- Markdown and side-by-side HTML output (promotes "social diffing" -- easy to paste into writeups/gists)
- JSON result storage
- Extensible base class (GhidraDiffEngine) for custom diffing implementations
- BSim correlation toggle
- Headless automation-friendly

**Significance:** Bridges the gap between Ghidra's powerful analysis and CI/CD-style automation. The markdown output format is well-suited for integration with LLM-based report generation.

### Historical Diffing Tools

| Tool | Era | Notes |
|------|-----|-------|
| **Turbodiff** | ~2011 | IDA plugin (GPLv2). Worked with free IDA 5.0. Last release v1.01b_r2 (Dec 2011). |
| **Patchdiff2** | ~2010s | IDA 6.1+ plugin. Specialized for security patch/hotfix analysis using call graph checksums. |
| **DarunGrim** | ~2009-2015 | Created by Jeong Wook Oh. Strong IDA integration and patch archiving. One of the few tools maintained for several years. |
| **DiffRays** | 2024 | Modern research-oriented tool using IDA's domain API. Stores results in SQLite. Built-in web interface. AutoDiff mode fetches vulnerable/patched binaries by CVE. |

---

## Function Matching and Identification

### IDA FLIRT (Fast Library Identification and Recognition Technology)

**How it works:** FLIRT scans disassembled code to locate, rename, and highlight known library subroutines. Signatures encode major byte-level features of each function, with wildcards for relocatable portions. During analysis, IDA matches function prologues and bodies against signature databases (.sig files).

**Creating custom signatures:**
1. Use FLAIR utilities (pelf, plb, pcf, etc.) to generate a .pat pattern file from a static library
2. Run sigmake to compile .pat into a .sig binary signature file
3. Handle collisions by editing the .exc exclusion file sigmake generates
4. Alternative: use idb2pat.py (IDAPython script) to generate patterns from existing IDB files without needing original libraries

**Community resources:** FLIRTDB (Maktm/FLIRTDB) provides community-contributed signature files. Mandiant's FLARE team published IDAPython scripts for pattern generation. JPCERT's AutoYara4FLIRT generates YARA rules that serve as FLIRT-like signatures for ELF malware.

### Binary Ninja WARP

**How it works:** WARP (introduced in Binary Ninja 5.1, 2025) creates a deterministic function GUID based on function byte contents. Specifically, the function GUID is a UUIDv5 of the sorted basic block GUIDs. Because it is byte-content-based, WARP expects exact matches (modulo variant instructions like relocations).

**Enterprise private libraries:** Binary Ninja Enterprise 2.0 (Jan 2026) deploys a private on-premises WARP server with OAuth2 integration. Enterprise users can push libraries to a shared collection, generate signatures in bulk with automatic deduplication, and match against proprietary codebases without exposing signatures externally.

**Cross-tool potential:** WARP is also available as an open-source format (Vector35/warp) for transferring function information across binary analysis tools, suggesting potential interoperability beyond Binary Ninja.

### Ghidra Function ID (FID)

**How it works:** Function ID databases (.fidb) store metadata describing functions in software libraries, searchable via a hash computed over function bodies. Analogous to IDA's FLIRT. Ghidra ships with FID databases for common libraries and allows users to build custom ones.

**Building custom FID databases:**
1. Import and analyze target libraries in a Ghidra project (headless analysis via analyzeHeadless works well for bulk processing)
2. All functions for a single FID library must share the same processor/Language ID
3. Use Ghidra's FunctionID plugin to create a read/write .fidb database
4. Optionally convert to read-only .fidbf format for efficient deployment
5. Third-party tools: ghidra-fid-generator (threatrack) automates FID generation from deb packages

**Limitations:** Functions must come from the same processor model (Language ID). Ideally, all functions in a library should be compiled with the same compiler and settings for reliable matching.

### YARA and Sigma Rules

**YARA** is a pattern-matching framework ("the Swiss knife for malware researchers") that identifies textual or binary patterns within files. Rules consist of a strings section (hex patterns, text strings, regexes) and a condition section (matching logic). Widely used for malware classification, threat hunting, and forensic triage.

**Sigma** rules target log-based detection (SIEM/EDR systems) rather than binary content. They complement YARA by detecting malicious behavior at the system level rather than at the file level.

**Relevance to function matching:** YARA rules can encode function-level byte patterns (similar to FLIRT but more flexible in matching logic). VirusTotal supports converting between Sigma and YARA for cross-domain threat hunting. For binary analysis pipelines, YARA provides a lingua franca for describing byte-level signatures that multiple tools can consume.

---

## Interchange Formats and Interoperability

### BinExport (Protocol Buffers)

**Format:** BinExport2 is a Protocol Buffer-based format for serializing disassembly data. It uses extensive deduplication tables for compactness. The .BinExport file captures:
- Functions, basic blocks, instructions, and operands
- Control flow graphs and call graphs
- Cross-references and data references
- Mnemonics and expression trees

**Tool support:** Plugins for IDA Pro, Binary Ninja, and Ghidra. BinDiff consumes BinExport files as its primary input. Research tools (Quarkslab's comparative study) have explored translating BinExport protobufs to FlatBuffers and Cap'n Proto schemas.

**Significance:** BinExport is the de facto standard for cross-tool disassembly interchange. Any tool that reads/writes BinExport can interoperate with BinDiff's matching engine and with the broader ecosystem of tools built on the format.

### GTIRB (GrammaTech Intermediate Representation for Binaries)

**Design philosophy:** GTIRB aims to be "LLVM-IR for binaries" -- a common intermediate representation that facilitates composition and interoperability between binary analysis and rewriting tools. Published as an academic paper (2019) and open-sourced by GrammaTech.

**Structure:**
- Multiple modules (executables or libraries)
- Inter-procedural control flow graph (IPCFG)
- AuxData tables for arbitrary analysis results in user-defined formats
- Every element (modules, symbols, blocks) has a UUID for cross-referencing
- Serialized via Protocol Buffers
- APIs in C++, Python, and Common Lisp

**Ecosystem:**
- **DDisasm**: Disassembler that produces GTIRB from raw binaries
- **GTIRB-PPrinter**: Pretty-prints GTIRB as assembly or reassembles to executable
- **gtirb-rewriting**: API for programmatic modification of GTIRB instances
- Used as the foundation for binary hardening, optimization, and debloating transforms

**Comparison with BinExport:** BinExport is optimized for *diffing* (compact, read-mostly). GTIRB is designed for *analysis and rewriting* (rich, mutable, round-trippable to executable). They serve complementary purposes.

### Standardized Export Patterns

The general trend is toward protobuf-based serialization with rich structural metadata. Key patterns:
- **Deduplication tables** (BinExport) for compact representation
- **UUID-based referencing** (GTIRB) for flexible cross-element links
- **AuxData extensibility** (GTIRB) for tool-specific annotations without format changes
- **Round-trip fidelity** (GTIRB) for binary rewriting workflows

---

## Patch Diffing Workflows

### Patch Tuesday Analysis

Patch Tuesday (Microsoft's monthly security update cycle) drives significant demand for binary diffing. The typical workflow:

1. **Acquire binaries:** Download pre-patch and post-patch versions of affected binaries (DLLs, drivers, executables)
2. **Disassemble/decompile:** Import both versions into a disassembler (IDA, Ghidra, Binary Ninja)
3. **Run diff:** Use BinDiff, Diaphora, ghidriff, or Ghidra Version Tracking to identify changed functions
4. **Triage changes:** Focus on functions with small, targeted modifications (likely security fixes) vs. large refactors
5. **Root cause analysis:** Determine the vulnerability class, attack vector, and triggering conditions from the diff

### Automation and AI-Driven Pipelines

**ghidriff** enables single-command headless diffing with markdown output, suitable for CI/CD integration.

**DiffRays** provides AutoDiff mode that fetches vulnerable/patched binaries by CVE number and runs end-to-end diffing with SQLite storage and web-based result browsing.

**PatchDiff-AI (Akamai, 2024):** A multi-agent AI system that automates Patch Tuesday root-cause analysis:
- **Windows internals agent**: RAG-backed by a vector store of Windows binary documentation
- **Reverse engineering agent**: Performs diffing of relevant files
- **Vulnerability research agent**: Orchestrates analysis and generates consistent narrative reports
- Achieves >80% success rate in fully automated report generation

**LLM-powered patch diffing (Bishop Fox):** Uses large language models to accelerate the traditionally expert-intensive process of understanding complex diffs, reducing analysis time from days/weeks to hours.

### Narrative Report Generation

Modern diffing workflows increasingly emphasize human-readable output:
- ghidriff produces markdown diffs suitable for blog posts and team communication
- AI agents generate structured vulnerability reports from diff results
- Integration of LLMs into the diff-to-report pipeline is an active area of development

---

## Deobfuscation

### Control-Flow Flattening (CFF)

**What it is:** CFF transforms a function's control flow into a dispatcher-based state machine. All original basic blocks are placed at the same nesting level, with a central dispatcher selecting the next block based on a state variable. This destroys the hierarchical structure that decompilers rely on for readable output.

**Recovery techniques:**
- **Symbolic backward slicing** (Google/Mandiant): Traces the state variable backward to determine the true successor of each block, then rebuilds the original CFG
- **D-810 (IDA plugin):** Uses IDA microcode-level transformations (UnflattenerFakeJump, FixPredecessorOfConditionalJumpBlock) to recover structure during decompilation
- **CaDeCFF:** Compiler-agnostic deobfuscator that uses data flow analysis of the state variable and selective symbolic execution to recover the original CFG
- **Binary Ninja CFF remover:** Deterministic, rule-based approach with theoretical guarantees of semantic equivalence
- **OLLVM unflattener:** Targeted at OLLVM-specific flattening patterns

### VM-Based Obfuscation

**Major tools:**
- **VMProtect:** Transforms x86/x64 code into custom bytecode executed by an embedded virtual machine. Industry standard for commercial software protection.
- **Themida/Code Virtualizer (Oreans):** Similar VM-based approach with additional anti-debug and anti-tamper features.
- **OLLVM (Obfuscator-LLVM):** Open-source LLVM pass that applies control flow flattening, bogus control flow, and instruction substitution at compile time. Often combined with VM protection (xVMP+OLLVM).

**Devirtualization approaches:**
- **LLVM-based lifting** (2025): Lift VM bytecode handlers to LLVM IR, apply standard compiler optimizations, and recover readable code. Research shows that VM protection "is just flattening" at a fundamental level -- the dispatcher pattern is structurally similar to CFF.
- **VMProtect-devirtualization (Jonathan Salwan):** Uses symbolic execution with Triton to automatically deobfuscate pure functions, lifting them to LLVM IR for optimization.
- **xVMP:** Research framework demonstrating LLVM-based code virtualization and its vulnerabilities to optimization-based attacks.
- **Trace-based analysis:** Record execution traces and use them to reconstruct the mapping between VM opcodes and native instructions.

### Trace-Informed Program Synthesis

**OOPSLA 2024 paper: "Control-Flow Deobfuscation using Trace-Informed Compositional Program Synthesis"**

Key contribution: Uses dynamic program traces as hints to decompose the synthesis problem. Rather than attempting to synthesize the entire deobfuscated program at once, the technique:
1. Collects execution traces of the obfuscated program
2. Uses trace information to identify compositional boundaries
3. Synthesizes individual components guided by observed I/O behavior
4. Handles a broad class of control flow obfuscations (not just CFF)

This approach significantly outperforms prior synthesis-based techniques on complex obfuscations.

### Chosen-Instruction Attacks

**NDSS 2022: "Chosen-Instruction Attack Against Commercial Code Virtualization Obfuscators"**

Inspired by chosen-plaintext attacks in cryptography, this technique:
1. Feeds carefully crafted instruction sequences to the obfuscator
2. Observes how the VM encodes them
3. Automatically extracts the mapping between native instructions and VM bytecode
4. Enables systematic devirtualization of arbitrarily protected code

Demonstrates that commercial VM obfuscators (VMProtect, Themida, Code Virtualizer) are fundamentally vulnerable to this class of attack.

### MBA (Mixed Boolean-Arithmetic) Simplification

MBA expressions combine Boolean operations (AND, OR, XOR, NOT) with arithmetic operations (+, -, *) to create expressions that are semantically simple but syntactically complex. They are widely used in obfuscation to obscure constants and simple computations.

**gooMBA (Hex-Rays, IDA 8.3+):**
- Integrated directly into the Hex-Rays decompiler
- Combines algebraic simplification, program synthesis, and smart heuristics
- Uses SMT solver (Z3) to formally verify that simplifications preserve semantics
- Translates IDA's internal IR to SMT-LIB for verification
- Outperforms state-of-the-art linear MBA solvers (faster than SiMBA on 1000+ benchmarks)
- Ships with IDA Pro and IDA Teams starting v8.3

**D-810:**
- IDA Pro plugin operating at the microcode level
- Extensible rule-based framework for deobfuscation during decompilation
- Handles CFF unflattening, MBA simplification, and dead code elimination
- Z3-based microcode optimization
- D-810-ng (Next Generation) fork adds IDA v9+ and Python 3.10+ support

**SSPAM (Symbolic Simplification with Pattern Matching):**
- Early Python tool using SymPy for arithmetic and Z3 for expression matching
- Successfully simplified basic MBA-obfuscated operators
- Limited by pattern-matching approach; crashes or returns incorrect results on complex MBAs
- Superseded by more advanced techniques but historically important

**msynth:**
- Code deobfuscation framework by Tim Blazytko (synthesis.to)
- Supports stochastic program synthesis as an alternative to lookup tables
- Built on Miasm symbolic execution engine
- Learns shorter equivalent expressions from I/O behavior
- Inspired by Syntia and QSynth

**Syntia (USENIX Security 2017):**
- Program synthesis guided by Monte Carlo Tree Search (MCTS)
- Uses execution traces as a blackbox oracle
- Successfully synthesized semantics of 489/500 MBA-obfuscated expressions
- >94% success rate on VMProtect and Themida arithmetic handlers
- Foundational work that inspired msynth, QSynth, and subsequent synthesis-based approaches

**MBA-Blast (USENIX Security 2021):**
- Unveils the mathematical structure underlying linear MBA expressions
- Achieves fast simplification by exploiting algebraic properties
- Complementary to synthesis-based approaches

**Other notable tools:**
- **QSynth:** Program synthesis approach for binary code deobfuscation
- **SiMBA:** MBA simplification tool (benchmarked against gooMBA)
- **Arybo:** Symbolic computation framework for MBA analysis
- **Equality saturation approaches** (secret.club, 2022): Uses e-graphs for MBA simplification

### Hardening and Counter-Deobfuscation

**LOKI (USENIX Security 2022):** Proposes obfuscation techniques designed to be resilient against all known automated deobfuscation attacks, including synthesis-based approaches. Represents the ongoing arms race between obfuscation and deobfuscation.

---

## Key Takeaways for Ghidra Integration

1. **BSim is Ghidra's strongest differentiator.** Its p-code-based signatures work across all supported architectures, unlike byte-pattern approaches (FLIRT, WARP) that are architecture-specific. A Ghidra-native diffing/matching pipeline should build on BSim's foundation.

2. **BinExport is the interoperability bridge.** Any Ghidra-based tooling that exports to BinExport format gains automatic interoperability with BinDiff, and with the broader ecosystem of tools consuming the format. Ghidra already has a BinExport plugin.

3. **ghidriff provides the automation template.** Its headless, command-line, markdown-output approach is the right pattern for CI/CD-integrated diffing. Building on PyGhidra/JPype for Java interop is proven and practical.

4. **Version Tracking + PatchDiff Correlator covers patch analysis.** The combination of Ghidra's built-in Version Tracking with threatrack's PatchDiff Correlator handles similarity scoring. Adding BSim correlation (as ghidriff does) strengthens matching quality.

5. **Function ID databases need community investment.** Ghidra's FID system is less mature than IDA's FLIRT ecosystem in terms of available signature databases. Automated FID generation from package repositories (similar to ghidra-fid-generator) could close this gap.

6. **Deobfuscation is the hardest integration challenge.** Ghidra lacks equivalents to IDA's microcode-level deobfuscation plugins (D-810, gooMBA). Potential approaches:
   - Implement MBA simplification at the p-code or decompiler IR level
   - Use Ghidra's analyzer framework to add CFF recovery as a pre-decompilation pass
   - Integrate with external synthesis tools (msynth/Syntia) via Ghidra scripts
   - Leverage Ghidra's emulator for trace-informed deobfuscation

7. **LLM integration is the emerging frontier.** PatchDiff-AI's multi-agent architecture (diffing agent + domain expert agent + report writer) suggests a template for Ghidra-based automated vulnerability analysis pipelines. ghidriff's markdown output is already LLM-friendly.

8. **GTIRB represents an alternative IR path.** For binary rewriting and hardening workflows, GTIRB's round-trip capability offers something Ghidra's native format does not. Bridging Ghidra analysis with GTIRB output could enable new transformation workflows.
