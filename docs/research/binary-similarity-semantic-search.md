# Binary Function Similarity Detection & Semantic Search

Research survey covering models, commercial knowledge-reuse systems, benchmarks,
and practical integration patterns for binary function similarity detection (BFSD)
in reverse engineering tooling.

Verification note (as of 2026-02-19): benchmark standings, tool integrations, and vendor feature claims should be validated against current primary sources before making implementation decisions.

---

## Models and Approaches for Binary Similarity

### Foundational Approaches (2017--2021)

#### Gemini (CCS 2017)
- **Key contribution**: First neural network-based graph embedding for cross-platform binary code similarity detection.
- Uses the Structure2Vec model on control flow graphs (CFGs) to produce function-level embeddings. Similarity is measured by distance between embeddings.
- Speeds up embedding generation by 3--4 orders of magnitude over prior art; reduces training time from >1 week to 30 min--10 hours.
- Reference: Xu et al., "Neural Network-based Graph Embedding for Cross-Platform Binary Code Similarity Detection," CCS 2017.

#### Asm2Vec (IEEE S&P 2019)
- **Key contribution**: PV-DM-inspired representation learning directly on assembly, robust against obfuscation and compiler optimization.
- Learns latent lexical-semantic relationships among assembly tokens without manual feature engineering. Represents a function as a weighted mixture of collective semantics.
- Requires only assembly code input -- no prior knowledge of function mappings needed.
- Integrated into the Kam1n0 assembly analysis platform.
- Reference: Ding, Fung & Charland, "Asm2Vec: Boosting Static Representation Robustness for Binary Clone Search against Code Obfuscation and Compiler Optimization," IEEE S&P 2019, pp. 472--489.

#### SAFE (DIMVA 2019)
- **Key contribution**: Self-attentive neural architecture that works directly on disassembled functions without manual feature extraction.
- Produces function embeddings using self-attention over instruction sequences. Architecture-agnostic (works on stripped binaries, multiple ISAs).
- More computationally efficient than graph-based methods like Gemini while achieving better accuracy.
- Reference: Massarelli et al., "SAFE: Self-Attentive Function Embeddings for Binary Similarity," DIMVA 2019.

#### PalmTree (CCS 2021)
- **Key contribution**: Pre-trained assembly language model for general-purpose instruction embeddings.
- Based on BERT with three custom pre-training objectives tailored for assembly: Masked Language Model (MLM), Context Window Prediction (CWP) for control-flow, and Def-Use Prediction (DUP) for data dependencies.
- Pre-trained on 3,266 binaries containing 2.25 billion instructions (x86-64, GCC/Clang, multiple optimization levels).
- Produces instruction-level embeddings that can be composed for downstream tasks including similarity detection, function type signatures, and value set analysis.
- Reference: Li, Qu & Yin, "PalmTree: Learning an Assembly Language Model for Instruction Embedding," CCS 2021.

#### Trex (arXiv 2020, IEEE TSE 2022)
- **Key contribution**: Transfer-learning framework that captures execution semantics from micro-traces.
- Pre-trains a Transformer on functions' micro-traces (instruction sequences + dynamic register/memory values), then fine-tunes for similarity.
- Outperforms prior SOTA by 7.8% (cross-architecture), 7.2% (cross-optimization), 14.3% (cross-obfuscation) on 1.47M function binaries from 13 projects.
- The micro-trace approach explicitly captures runtime behavior, complementing purely static methods.
- Reference: Pei et al., "Trex: Learning Execution Semantics from Micro-Traces for Binary Similarity," arXiv:2012.08680 (2020); IEEE TSE 2022.

### Transformer-Era Models (2022--2024)

#### jTrans (ISSTA 2022)
- **Key contribution**: First Transformer to embed control-flow information into token/position representations via jump-aware encoding.
- Shares parameters between token embeddings and position embeddings for jump source/target pairs, maintaining contextual connections through training.
- Released BinaryCorp, the most diverse binary similarity dataset at the time.
- Achieves 62.5% recall@1 on BinaryCorp (10K function pools), vs. 32.0% for prior SOTA -- a 30.5% absolute improvement. 2X higher recall in real-world vulnerability search.
- Reference: Wang et al., "jTrans: Jump-Aware Transformer for Binary Code Similarity Detection," ISSTA 2022.

#### CRABS-former (Internetware 2024)
- **Key contribution**: Cross-architecture binary similarity with a unified Transformer that processes multiple ISAs via normalized assembly.
- Designs normalization strategies to preprocess assembly across ISAs and builds a multi-ISA tokenizer, then trains a Transformer-based similarity model.
- Improves recall by 10.85% (cross-ISA), 18.02% (cross-compiler), 3.33% (cross-optimization) over baselines including SAFE, Trex, jTrans.
- Reference: "CRABS-former: CRoss-Architecture Binary Code Similarity Detection based on Transformer," Internetware 2024 (Macau, July 2024).

#### BinaryAI (ICSE 2024)
- **Key contribution**: Binary-to-source software composition analysis (SCA) via Transformer embedding.
- Trains a Transformer model (initialized from Pythia LLM family) with contrastive learning to embed binary and source functions into a shared vector space.
- Uses link-time locality to match binary functions to source libraries, detecting third-party library (TPL) reuse.
- Achieves 22.54% recall@1 (vs. 10.75% for CodeCMR); raises SCA precision from 73.36% to 85.84% and recall from 59.81% to 64.98% over commercial tools.
- Reference: Zhang et al., "BinaryAI: Binary Software Composition Analysis via Intelligent Binary Source Code Matching," ICSE 2024.

### Architecture-Neutral / IR-Based Approaches

#### VexIR2Vec (TOSEM 2024, FSE 2025 Journal-First)
- **Key contribution**: Architecture-neutral embeddings via VEX intermediate representation.
- Three components: (1) peephole extractor (random walks on CFG yield basic-block sequences), (2) VexINE normalization engine (compiler-optimization-inspired transforms on VEX-IR to reduce architectural/compiler variance), (3) VexNet embedding model (unsupervised knowledge-graph-embedding learning at the IR entity level).
- Because embeddings operate on VEX-IR (the Valgrind IR, also used by angr), the approach is inherently cross-architecture without ISA-specific training.
- Outperforms nearest baselines: +40% cross-optimization, +18% cross-compilation, +21% cross-architecture, +60% obfuscation. Mean average precision of 0.76 for search (+46% over nearest baseline).
- Reference: VenkataKeerthy et al., "VEXIR2Vec: An Architecture-Neutral Embedding Framework for Binary Similarity," TOSEM 2024; FSE 2025 Journal-First.

### GNN-Based Approaches

Graph Neural Networks have been applied to binary similarity by encoding control-flow graphs (CFGs), data-flow graphs (DFGs), and call graphs as graph structures:

- **Gemini** (CCS 2017, above) pioneered GNN-style embeddings with Structure2Vec on attributed CFGs (ACFGs).
- **GMN (Graph Matching Network)** extended this with cross-graph attention for pairwise function comparison.
- **Codeformer** (Electronics 2023) nests GNN layers inside a Transformer to capture both sequential and structural information, addressing limitations of pure-Transformer or pure-GNN architectures.
- **FSPS-GNN** (2024) classifies code features into outer/inner graph types, achieving 87.57% precision via four-stage pipeline (feature embedding, enhancement, fusion, similarity prediction).
- **Hybrid GNN+Transformer** architectures (2024--2025) combine CFG/DFG/call-graph structural information with sequential Transformer attention, representing the current frontier.

GNNs are particularly valuable for binary similarity because control-flow structure is a compiler-invariant semantic signal -- two compilations of the same function produce different instruction sequences but similar graph topologies.

---

## Knowledge Reuse Systems in Commercial Tools

### IDA Lumina (Hex-Rays)

**How it works:**
- Hash-based metadata lookup. For each function, IDA computes an MD5 hash over "cleaned" function bytes (a bitmask zeroes out relocatable operands, relative/absolute addresses, and NOPs).
- Hash+metadata pairs are pushed to / pulled from a Lumina server. Only cryptographic digests are transmitted -- raw bytes never leave the client.
- Metadata includes function names, types, comments, and other annotations.
- When multiple users push metadata for the same hash, the server scores metadata quality and keeps the higher-scoring version.

**Deployment options:**
- **Public Lumina**: Maintained by Hex-Rays, serves the entire IDA community. Free with IDA license.
- **Private Lumina**: Self-hosted server for organizations wanting to keep metadata internal.

**Strengths:**
- Very fast lookup (hash table).
- Zero false positives on exact matches.
- Crowd-sourced metadata accumulates value over time.
- Privacy-preserving (only hashes are transmitted).

**Limitations:**
- Exact-match only -- any change in function bytes (different compiler, optimization, or architecture) breaks the hash.
- No cross-architecture or cross-compiler matching.
- Struct and enum type information not supported in the current Lumina specification.
- ~85% accuracy in cross-disassembler scenarios (analysis discrepancies between tools).
- No semantic or fuzzy matching capability.

### Binary Ninja WARP (Vector 35)

**How it works:**
- Deterministic function GUID based on byte content, with normalization for variant instructions.
- **Basic block GUID**: UUIDv5 of the byte sequence of instructions in execution order, after: zeroing relocatable instruction operands, excluding NOP instructions, excluding register-self-set instructions (effective NOPs), and removing register groups with no implicit extension.
- **Function GUID**: UUIDv5 of all basic block GUIDs, sorted highest-to-lowest start address.
- Disambiguation via constraints: when multiple functions share the same GUID, additional consistent metadata (calling convention, argument count, etc.) disambiguates.

**Deployment options:**
- **Public WARP server**: Community-shared function database.
- **Enterprise on-premises**: Binary Ninja Enterprise 2.0 deploys a WARP server with OAuth2 integration by default.
- The WARP format is open-source (GitHub: Vector35/warp), enabling cross-tool interoperability.

**Strengths:**
- Deterministic and fast (UUID lookup).
- Handles common binary variations (NOPs, relocations) via normalization.
- Open format enables third-party tool integration.
- Enterprise deployment with access control.

**Limitations:**
- Still fundamentally exact-match (modulo variant normalization) -- does not handle different compilers, optimization levels, or architectures.
- Fuzzy matching is listed as a future enhancement but not yet available.
- Requires Binary Ninja's lifting pipeline for GUID computation.

#### WARP Format Specification Details

The WARP format is [fully open-source](https://github.com/Vector35/warp) and uses FlatBuffers for serialization. The specification is defined across multiple `.fbs` schema files: `warp.fbs` (core format), `signature.fbs` (function signature data), `symbol.fbs` (symbol information), `type.fbs` (type definitions), and `target.fbs` (target architecture specifications).

**UUIDv5 computation in detail:**

The WARP GUID system uses two fixed UUIDv5 namespaces:

- **Basic block namespace**: `0192a178-7a5f-7936-8653-3cbaa7d6afe7`
- **Function namespace**: `0192a179-61ac-7cef-88ed-012296e9492f`

*Basic block GUID computation:*
1. Collect all instructions in the basic block, sorted in execution order.
2. Filter out: NOP instructions, register-self-set instructions that are effectively NOPs (architecture-dependent -- see below), and instructions in blacklisted categories.
3. For remaining instructions, zero out bytes corresponding to relocatable operands (operands that reference constant pointers to mapped memory regions).
4. Concatenate the processed instruction byte sequences.
5. Compute SHA-1 over (basic block namespace bytes + concatenated instruction bytes).
6. Truncate to 16 bytes and format as UUIDv5.

*Function GUID computation:*
1. Collect all basic block GUIDs for the function.
2. Sort them by highest-to-lowest start address.
3. Concatenate their 16-byte UUID representations.
4. Compute SHA-1 over (function namespace bytes + concatenated block GUIDs).
5. Truncate to 16 bytes and format as UUIDv5.

**Variant instruction handling specifics:**

WARP's visualization layer categorizes instructions into three types based on their impact on GUID computation:
- **Variant instructions** (rendered red): Instructions with relocatable operands that are zeroed before hashing. Example: `call 0x15bba` on x86 -- the relative offset `0x15bba` is zeroed because it changes based on link-time layout.
- **Computed variant instructions** (rendered yellow): Instructions whose operands are indirectly relocatable. Example: on aarch64, `add x1, x1, #0xf10` where `x1` enters as a pointer to a mapped region -- the constant `#0xf10` is zeroed.
- **Blacklisted instructions** (rendered black): Instructions excluded entirely from the GUID. NOPs and register-self-set instructions fall here.

*Architecture-dependent register-self-set handling:*
- On **x86** (32-bit): `mov edi, edi` is excluded from the GUID because it has no semantic effect -- it exists as hot-patch padding.
- On **x86-64**: `mov edi, edi` is **not** excluded because on x86-64, writing to a 32-bit register implicitly zero-extends to 64 bits, making it semantically meaningful.
- The general rule: a register-self-set instruction is excluded only when the architecture has no implicit extension behavior for that register group.

**Constraint system for disambiguation:**

When multiple functions produce the same GUID (common for small/trivial functions), WARP uses a constraint system to disambiguate:
- Constraints are GUID + optional offset pairs (namespace: `019701f3-e89c-7afa-9181-371a5e98a576`).
- Examples of constraints: GUIDs of called functions, GUIDs of caller functions, GUIDs of adjacent functions in the binary.
- Negative offsets indicate predecessors; positive offsets indicate successors in the binary's linear layout.
- Constraints without offsets may be consolidated if their GUIDs match.

**Writing a third-party WARP consumer:**

To implement WARP support in a non-Binary Ninja tool, a consumer must provide:
1. **Disassembly capability** for the target ISA, with instruction boundary and basic block identification.
2. **Relocation detection** to identify which instruction operands reference mapped memory regions.
3. **Architecture-specific register metadata** to determine which register-self-set instructions are semantic NOPs vs. meaningful operations.
4. **Deterministic UUID computation** matching the specification exactly -- even minor deviations (e.g., different basic block boundary identification) will produce different GUIDs, breaking matching.
5. **FlatBuffers deserialization** for reading `.warp` signature files.

The reference implementation is in Rust (crate: `warp` at [Vector35/warp](https://github.com/Vector35/warp)), and the core data structures are:
```
Function { guid: UUID, symbol: Symbol, constraints: [Constraint], basic_blocks: [BasicBlock] }
BasicBlock { guid: UUID, instructions: [Instruction] }
Constraint { guid: UUID, offset: Option<i64> }
```

Vector 35 has stated an interoperability goal for WARP across multiple RE tools. As of early 2026, Binary Ninja includes first-party WARP integration; non-BN integrations should be treated as ecosystem-dependent and revalidated against current project status.

**Applied metadata on match:** When a function matches, WARP transfers: symbol names and demangled types, calling conventions and parameter/return types, user-defined variable names and types, and comments. This makes WARP not just a matching system but a full metadata transfer format.

### Ghidra Function ID (.fidb)

**How it works:**
- Hash-based function identification similar in spirit to IDA FLIRT signatures.
- Computes hashes over masked function bytes (relocatable operands masked out) and compares against a database of known function hashes.
- Two database formats: `.fidb` (compressed/packed) and `.fidbf` (uncompressed, used directly by the analyzer).

**Building FID databases:**
- Import known libraries into a Ghidra project, run the FID database population tool.
- Must specify exact Processor Language ID + Compiler Spec ID; mismatches cause silent skips.
- Community-maintained repositories exist (e.g., threatrack/ghidra-fidb-repo).

**Strengths:**
- Ships with Ghidra (free, open-source).
- Self-contained `.fidb` files are easy to share.
- Effective for identifying statically-linked standard libraries.

**Limitations:**
- **False positives on small functions**: Short functions (few instructions) hash-collide frequently.
- **Common function ambiguity**: Identical byte sequences can correspond to different named functions in different libraries.
- **Database population fragility**: If any program in the project folder needs a Ghidra version upgrade, the entire population task terminates without saving.
- **Strict language/compiler matching**: Both Language ID and Compiler Spec ID must match exactly; no cross-architecture support.
- **No semantic matching**: Pure byte-hash, no tolerance for compiler variations beyond what masking covers.

### Comparative Summary

| Feature | IDA Lumina | Binary Ninja WARP | Ghidra FID |
|---|---|---|---|
| Method | MD5 of masked bytes | UUIDv5 of normalized BBs | Hash of masked bytes |
| Cross-architecture | No | No | No |
| Cross-compiler | No | No | No |
| Fuzzy/semantic match | No | Planned | No |
| Open format | No | Yes (open-source) | Yes (open-source) |
| Crowd-sourced | Yes (public server) | Yes (public server) | Community repos |
| Enterprise/private | Yes (paid) | Yes (Enterprise 2.0) | Self-built |
| Type metadata | Partial (no structs/enums) | Yes | Function names only |

All three systems are **deterministic fingerprinting** approaches. None provides semantic or learned similarity -- they match functions that are byte-identical (after normalization). This is both their strength (zero false positives, fast) and limitation (brittle to any compilation variation).

---

## Ghidra BSim Internals Deep Dive

BSim is the only production-grade fuzzy/semantic function matching system built into a major RE framework. Unlike the deterministic fingerprinting systems above (FID, Lumina, WARP), BSim uses decompiler-derived feature vectors compared via cosine similarity, enabling cross-architecture and cross-compiler matching. Understanding its internals is essential for building on or extending its capabilities.

### Feature Vector Generation: The GenerateSignatures Pipeline

BSim's core operation is transforming each function in a binary into a fixed-dimensional feature vector derived from Ghidra's p-code intermediate representation.

**Pipeline stages:**

1. **Decompilation to high p-code.** Ghidra's decompiler lifts machine code through raw p-code (direct ISA translation) to high p-code (after data-flow analysis, dead code elimination, and normalization). BSim operates on the high p-code representation, which abstracts away architecture-specific details.

2. **Feature extraction from control-flow and data-flow.** The decompiler extracts individual features from the normalized p-code, where each feature represents a small piece of data-flow and/or control-flow. Crucially, certain attributes are intentionally excluded from features: values of constants, names of registers, and data types. This exclusion is what enables cross-architecture and cross-compiler matching -- two compilations of the same source produce different register assignments and constant encodings but similar data-flow patterns.

3. **Vector assembly.** Individual features are assembled into a feature vector for each function. The vector is a sparse representation in a high-dimensional feature space.

4. **Signature serialization.** The `GenerateSignatures.java` script (or the `bsim generatesigs` command-line tool) serializes feature vectors and metadata into XML signature files. These files contain the BSim signatures plus metadata (function names, addresses, executable info) needed by the BSim server.

**The normalization process** is key to BSim's cross-compilation tolerance. The decompiler uses the `"normalize"` simplification style, which omits type recovery and final cleanup steps that would introduce architecture-specific artifacts. This produces a normalized p-code syntax tree where:
- Register allocations are abstracted away (data-flow edges replace register names)
- Constant values used as addresses are masked
- Compiler-specific idioms (e.g., strength-reduced multiplications) are partially normalized through decompiler optimization rules
- Stack frame layouts are abstracted into symbolic offsets

**Scripting signature generation:**

```java
// GenerateSignatures.java pattern -- headless or GUI
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.BSimClientFactory;

// The bsim command-line tool wraps this:
// bsim generatesigs ghidra://<project> --bsimurl <database_url>
```

For batch processing, the `bsim` command-line utility is preferred over GUI scripts:
```bash
# Generate signatures for all programs in a Ghidra project
bsim generatesigs ghidra://<project_path> \
    --bsimurl postgresql://<host>/<dbname>

# Import from a directory of binaries first
analyzeHeadless <project_path> <project_name> \
    -import <binary_directory> -recursive \
    -postScript GenerateSignatures.java <database_url>
```

### Similarity and Significance Scores

BSim produces two scores when comparing function vectors:

- **Similarity**: The cosine of the angle between two feature vectors, always between 0.0 and 1.0. A value of 1.0 indicates identical feature vectors (exact functional match). Values above ~0.7 typically indicate the same function compiled with different options; values above ~0.5 suggest related functionality.

- **Significance (confidence)**: A measure of how meaningful a high similarity score is, accounting for function complexity. A trivial function (e.g., a getter that returns a single field) may achieve similarity 1.0 with many unrelated trivial functions. Significance down-weights these matches by considering the information content of the vectors. Higher significance means the match is less likely to be coincidental.

**Call-graph boosting:** Beyond vector similarity, BSim uses function call-graph structure to boost scores and disambiguate conflicting matches. If two candidate matches have similar vector similarity but one has callers/callees that also match, that candidate is preferred. This is particularly important for distinguishing structurally similar utility functions.

### Database Backends: PostgreSQL vs H2 vs Elasticsearch

BSim supports three storage backends, each suited to different scales and deployment scenarios:

**H2 (file-based, local):**
- Zero-dependency embedded database stored as a single file on disk.
- Best for: Individual analysts, small-to-medium corpora (thousands of binaries), quick experiments, tutorials.
- Limitations: No multi-user access, no clustering, limited query performance at scale.
- Creation: `bsim createdatabase file://<path> [medium_nosize|large_nosize]`

**PostgreSQL (server-based, team):**
- Requires a PostgreSQL server with BSim's custom extension (the Ghidra distribution includes PostgreSQL source and a build script for the `lsh` plugin).
- Best for: Team/organization deployments, corpora up to tens of millions of functions, concurrent multi-user access.
- Limitations: Server not supported on Windows (clients are cross-platform). Requires compilation of the custom PostgreSQL extension.
- The custom extension implements locality-sensitive hashing (LSH) index operations directly in the database engine, enabling efficient approximate nearest-neighbor queries without transferring full vectors to the client.
- Creation: `bsim createdatabase postgresql://<host>/<dbname> [medium|large]`

**Elasticsearch (distributed, enterprise):**
- Requires an Elasticsearch cluster with the `BSimElasticPlugin` installed (provided as `lsh.zip` in the Ghidra distribution).
- Best for: Very large corpora (hundreds of millions of functions), high-availability requirements, organizations already running Elasticsearch infrastructure.
- Authentication is managed by Elasticsearch's native security features (user/password or API keys), not by BSim itself.
- Supports horizontal scaling via Elasticsearch's built-in sharding and replication.
- Creation: `bsim createdatabase elastic://<host>/<dbname> [medium|large]`

**Database templates** control index parameters:
- `medium` / `medium_nosize`: Optimized for up to ~10 million vectors. Good default for most deployments.
- `large` / `large_nosize`: Optimized for up to ~100 million vectors. Uses more memory for larger LSH index structures.
- The `_nosize` variants (H2 only) omit executable size tracking.

**LSH indexing:** All three backends use locality-sensitive hashing to maintain vector indices. LSH maps similar vectors to the same hash buckets with high probability, drastically reducing the number of cosine-similarity comparisons needed during a query. This is what makes BSim scale to millions of functions -- a query does not compute similarity against every stored vector, only against those in nearby hash buckets.

### BSim Program Correlator and Version Tracking Integration

BSim integrates with Ghidra's Version Tracking framework through the **BSim Program Correlator**, which uses decompiler-derived feature vectors to find matching functions between two program versions.

**How it works within Version Tracking:**
1. The correlator decompiles all functions in both the source and destination programs.
2. For each function pair, it computes BSim feature vectors and measures cosine similarity.
3. Call-graph structure is used to boost scores and resolve ambiguous matches -- if function A calls functions B and C, and all three have matches in the other binary, the combined evidence strengthens confidence.
4. Results are presented as candidate matches with similarity and confidence scores in the Version Tracking UI, where the analyst can accept, reject, or refine matches.

**Advantages over other Version Tracking correlators:**
- Works across compiler versions and optimization levels (unlike exact-match correlators).
- Works across architectures (e.g., comparing an x86 build to an ARM build of the same firmware).
- Provides quantitative confidence scores rather than binary match/no-match.

**Complementary correlators:** The BSim correlator works alongside other Version Tracking correlators (exact byte match, exact mnemonic match, data reference correlator, combined function/data reference correlator). A typical workflow runs exact-match correlators first, then uses BSim for remaining unmatched functions -- mirroring the layered architecture recommended in the practical integration section below.

**Third-party extensions:** The [ghidra-patchdiff-correlator](https://github.com/threatrack/ghidra-patchdiff-correlator) project adds additional correlators suitable for patch diffing, and [ghidriff](https://clearbluejar.github.io/ghidriff/) leverages BSim for automated binary diffing.

### BSim Query API and Scripting

BSim provides both GUI-based and scriptable query interfaces. The scripting API lives in the `ghidra.features.bsim.query` package.

**Key classes:**

- `BSimClientFactory` -- Creates connections to BSim database servers. Accepts URLs in the form `postgresql://`, `elastic://`, or `file://` for H2.
- `GenSignatures` -- Generates BSim feature vectors for functions in a program.
- `QueryNearest` -- Performs nearest-neighbor queries against a BSim database for a given function's feature vector.
- `BulkSignatures` -- Handles batch signature generation and ingestion from the command line.
- `SimilarFunctionQueryService` -- Higher-level service for querying similar functions from within the Ghidra GUI.

**Example: Querying BSim from a Ghidra script (Python):**

```python
# QueryFunction.py -- ships with Ghidra in the BSim script category
# Demonstrates querying BSim for a single function
from ghidra.features.bsim.query import BSimClientFactory, GenSignatures

# Connect to BSim database
client = BSimClientFactory.buildClient("postgresql://localhost/mydb", False)
client.connect()

# Generate signature for current function
gensig = GenSignatures(False)
gensig.openProgram(currentProgram, None, None, None, None, None)
gensig.scanFunction(currentFunction)

# Query for similar functions
# ... QueryNearest usage pattern
client.close()
```

**Example: Batch query via command line:**
```bash
# Query all functions in a program against a BSim database
bsim search ghidra://<project>/<program> \
    --bsimurl postgresql://<host>/<dbname> \
    --similarity 0.7 --confidence 0.0
```

**Programmatic application of results** is a noted gap in the current API (see [GitHub issue #6622](https://github.com/NationalSecurityAgency/ghidra/issues/6622)). The example scripts demonstrate searching but not automatically applying matched names/types to the current program. Custom scripts must use the standard Ghidra API (`function.setName()`, `function.setReturnType()`, etc.) to apply results from BSim queries.

### Cross-Architecture Matching via P-Code Normalization

BSim's cross-architecture capability is a direct consequence of operating on p-code rather than native assembly:

1. **P-code is architecture-neutral.** Ghidra's SLEIGH processor specifications translate every supported ISA into the same p-code operations (COPY, INT_ADD, INT_SUB, LOAD, STORE, BRANCH, CBRANCH, CALL, RETURN, etc.). An `ADD` on x86 and an `ADD` on ARM both become `INT_ADD` in p-code.

2. **High p-code abstracts register allocation.** After the decompiler's normalization pass, specific register assignments are replaced by data-flow edges between varnodes. Two compilations that use different registers for the same computation produce identical high p-code data-flow graphs.

3. **Calling convention differences are normalized.** The decompiler resolves calling conventions (how arguments are passed -- registers vs. stack, which registers) into abstract parameter/return varnodes.

4. **Feature extraction ignores ISA-specific artifacts.** Constants, register names, and data types are excluded from BSim features, removing the remaining architecture-specific signals.

**Practical limitations of cross-architecture matching:**
- Functions must be semantically equivalent, not just similar. BSim does not handle algorithmic differences introduced by architecture-specific optimizations (e.g., SIMD vectorization on x86 that has no equivalent on the ARM build).
- Very short functions (1--3 p-code operations) produce sparse feature vectors with low significance, leading to high false-positive rates regardless of architecture.
- Inlined functions may differ across architectures if the compiler's inlining heuristics diverge.

**References:**
- [BSim Tutorial Introduction](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)
- [BSim Scripting Tutorial](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial_Scripting.html)
- [BSim overview (malware.re blog)](https://blog.malware.re/2023/12/26/ghidra-bsim/index.html)
- [BSim guide (Max Kersten)](https://maxkersten.nl/2024/03/31/ghidra-tip-0x02-bsim/)
- [BSim guide (Pen Test Partners)](https://www.pentestpartners.com/security-blog/fuzzy-matching-with-ghidra-bsim-a-guide/)
- [Ghidra BSim Elasticsearch helper (ckane)](https://github.com/ckane/ghidra-bsim-elastic)
- [BSim in Ghidra: Newer Always Better? (NDSS BAR 2025)](https://www.ndss-symposium.org/wp-content/uploads/bar2025-final3.pdf)

---

## Benchmarks for Binary Similarity

### REFuSe-Bench (NeurIPS 2024, Datasets & Benchmarks Track)

- **Key contribution**: First benchmark to seriously address data quality issues (duplication, labeling accuracy) and real-world evaluation scenarios.
- Includes experiments with real malware and is the first serious evaluation of ML BFSD models on Windows binaries (most prior work focused on Linux/ELF).
- Introduces REFuSe (Reverse Engineering Function Search), a deliberately simple baseline using only raw-byte features with a basic CNN -- no disassembly required.
- **Provocative finding**: This simple baseline achieves state-of-the-art performance in multiple settings, challenging the assumption that complex feature engineering is necessary.
- Improves over older benchmarks by addressing data leakage, cross-dataset contamination, and evaluation on realistic (not just synthetic) binaries.
- Reference: "Is Function Similarity Over-Engineered? Building a Benchmark," NeurIPS 2024.

### BinBench (PeerJ Computer Science 2023)

- **Key contribution**: First multi-task benchmark for evaluating ML models on low-level assembly functions, inspired by NLP benchmarking practices (e.g., GLUE).
- Provides binary data plus structured JSON representations (assembly, bytecode, arguments) for each function, eliminating the need for a disassembler.
- Includes multiple tasks beyond similarity: function boundary detection, compiler identification, optimization level prediction, etc.
- Publicly available dataset with baseline model evaluations.
- Significance: Standardizes evaluation across tasks, enabling fairer comparison of embedding quality across different downstream applications.
- Reference: "BinBench: A Benchmark for x64 POSIX Binary Function Representations," PeerJ CS, 2023.

### BinCodex (BenchCouncil Transactions, May 2024)

- **Key contribution**: Comprehensive multi-level dataset that systematically varies all compilation change-points.
- Organizes variation into 4 groups: different platforms (x86/ARM), different compilers (GCC/Clang), different compiler options (default and non-default), and different obfuscation techniques.
- Evaluated with 8 SOTA BFSD methods, providing apples-to-apples comparison.
- Addresses a key weakness of earlier benchmarks: many prior datasets tested only a subset of variation axes (e.g., cross-compiler but not cross-obfuscation).
- Reference: "BinCodex: A Comprehensive and Multi-Level Dataset for Evaluating Binary Code Similarity Detection Techniques," BenchCouncil Trans. on Benchmarks, Standards and Evaluations, May 2024.

### BinMetric (IJCAI 2025)

- **Key contribution**: First comprehensive benchmark for evaluating LLMs on binary analysis tasks (not just similarity).
- 1,000 questions from 20 real-world open-source projects across 6 tasks: call-site reconstruction, decompilation, signature recovery, binary code summarization, algorithm classification, and assembly instruction generation.
- Finding: GPT-4 and WizardCoder-34B show strong capability in algorithm classification and summarization, but challenges remain in precise binary lifting and assembly synthesis.
- Relevant to BFSD because LLM-generated summaries/embeddings may become a future similarity signal.
- Reference: "BinMetric: A Comprehensive Binary Code Analysis Benchmark for Large Language Models," IJCAI 2025.

### How These Benchmarks Improve Over Older Evaluation

Older BFSD evaluations (pre-2023) suffered from several systematic issues:

1. **Dataset contamination**: Training and test sets drawn from the same binaries, inflating accuracy.
2. **Synthetic-only evaluation**: Testing only on recompiled open-source code, missing real-world complexity (stripped binaries, malware, proprietary code).
3. **Single-axis variation**: Testing cross-compiler OR cross-optimization, but rarely both simultaneously.
4. **Linux/ELF bias**: Almost no evaluation on Windows PE binaries.
5. **No standard baselines**: Each paper used different datasets, making comparison impossible.

The newer benchmarks address these by providing curated datasets with controlled variation, real-world binaries (including malware), multi-platform coverage, and standardized evaluation protocols.

---

## Practical Integration Patterns

### How Embedding-Based Similarity Could Be Integrated into a Ghidra-Like Tool

#### Existing Integration Examples

**RevEng.AI Ghidra Plugin**: A production example of embedding-based similarity integrated into Ghidra. Users upload binaries to RevEng.AI's cloud API, which computes function embeddings and returns similarity matches. Features include per-function matching (right-click a function, get top-10 similar functions from the database) and batch "auto-unstrip" (rename all functions based on similarity matches). Available for Ghidra 11.2+ on Java 21.

**BinaryAI Plugins**: Ghidra and IDA Pro plugins that query the binaryai.net service for function similarity results, enabling SCA workflows within the disassembler.

**Ghidriff**: Open-source Ghidra binary diffing engine using fuzzy matching and function similarity scoring for version comparison, bridging gaps in Ghidra's built-in Version Tracking.

#### Architecture for a Ghidra Similarity Plugin

A practical integration would layer as follows:

```
+------------------------------------------+
|          Ghidra UI / Script API           |
|  (function context menu, batch actions)   |
+------------------------------------------+
|         Plugin Orchestration Layer        |
|  - deterministic FID/hash check first     |
|  - fallback to embedding similarity       |
+------------------------------------------+
|        Embedding Computation              |
|  - lift to p-code / IR                    |
|  - run through model (local or remote)    |
|  - produce fixed-dim vector per function  |
+------------------------------------------+
|        Vector Index / Search              |
|  - local: SQLite + brute-force / HNSW     |
|  - corpus: vector DB (Milvus, Qdrant)     |
+------------------------------------------+
|           Corpus / Knowledge Base         |
|  - pre-computed embeddings for known libs |
|  - user's own analyzed binaries           |
+------------------------------------------+
```

### Ghidra API Patterns for Embedding-Based Similarity

The following patterns demonstrate how to use Ghidra's internal APIs to extract function representations suitable for ML model input. These are the building blocks for integrating learned similarity models into a Ghidra plugin.

#### Using DecompInterface for Batch Function Embedding

The `DecompInterface` class provides programmatic access to the decompiler, enabling extraction of both decompiled C code and high p-code for every function in a program. It is self-contained, caches initialization data, and automatically respawns the decompiler process if it crashes.

**Basic pattern for batch decompilation:**

```java
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;

DecompInterface decompIfc = new DecompInterface();
decompIfc.openProgram(currentProgram);

// Use "normalize" for ML features -- omits type recovery artifacts
decompIfc.setSimplificationStyle("normalize");

FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
for (Function func : functions) {
    DecompileResults results = decompIfc.decompileFunction(func, 30, monitor);
    if (!results.decompileCompleted()) continue;

    // Get high p-code for ML feature extraction
    HighFunction hf = results.getHighFunction();

    // Get decompiled C for LLM-based approaches
    String cCode = results.getDecompiledFunction().getC();

    // Process hf or cCode for your embedding model...
}
decompIfc.dispose();
```

**Simplification styles and their uses:**

| Style | Description | Use for ML |
|---|---|---|
| `"decompile"` | Full analysis including type recovery, produces C output | LLM-based embeddings on decompiled C |
| `"normalize"` | Omits type recovery and final cleanup, produces normalized p-code trees | BSim-style feature extraction, p-code ML models |
| `"register"` | One pass on registers, no stack variable analysis | Raw data-flow extraction |
| `"firstpass"` | No analysis, raw syntax tree | Studying raw p-code before transforms |
| `"paramid"` | Just enough to recover function parameters | Signature extraction |

For ML-based similarity, `"normalize"` is generally the right choice: it strips architecture-specific artifacts from the p-code while preserving the data-flow and control-flow structure that encodes function semantics. The `"decompile"` style is appropriate when the embedding model consumes decompiled C text (as in LLM-based approaches).

#### P-Code Extraction Patterns for ML Model Input

High p-code from the `HighFunction` object can be traversed to extract structured features:

**Extracting p-code operation sequences:**

```java
HighFunction hf = results.getHighFunction();
Iterator<PcodeOpAST> ops = hf.getPcodeOps();
List<int[]> features = new ArrayList<>();

while (ops.hasNext()) {
    PcodeOpAST op = ops.next();
    int opcode = op.getOpcode();        // e.g., PcodeOp.INT_ADD, PcodeOp.LOAD
    int numInputs = op.getNumInputs();

    // Extract opcode + operand structure as feature tuple
    int[] feature = new int[numInputs + 1];
    feature[0] = opcode;
    for (int i = 0; i < numInputs; i++) {
        Varnode vn = op.getInput(i);
        feature[i + 1] = vn.isConstant() ? 0 :
                          vn.isRegister() ? 1 :
                          vn.isUnique() ? 2 :
                          vn.getAddress().isStackAddress() ? 3 : 4;
    }
    features.add(feature);
}
```

**Extracting the control-flow graph structure:**

```java
// Get basic blocks and their connections for GNN input
Iterator<PcodeBlockBasic> blocks = hf.getBasicBlocks().iterator();
while (blocks.hasNext()) {
    PcodeBlockBasic block = blocks.next();
    int blockIndex = block.getIndex();

    // Outgoing edges
    for (int i = 0; i < block.getOutSize(); i++) {
        PcodeBlock target = block.getOut(i);
        // Record edge: blockIndex -> target.getIndex()
    }

    // P-code ops within this block
    Iterator<PcodeOp> blockOps = block.getIterator();
    // ... extract per-block features
}
```

**Key consideration for ML pipelines:** The `DecompInterface` is not thread-safe for a single program -- each thread needs its own instance. For parallel batch embedding, create one `DecompInterface` per thread, each calling `openProgram()` independently. The decompiler process will be spawned per instance.

#### Working with Ghidra's FID Hasher Interface for Custom Fingerprinting

Ghidra's Function ID system uses the `FidHasher` interface to compute deterministic hashes over masked function bytes. While FID's built-in hashing is fixed, understanding the interface enables building custom fingerprinting schemes that integrate with Ghidra's existing infrastructure.

**Core FID components:**

- `FidService` (`ghidra.feature.fid.service.FidService`) -- The main service providing FID database access, function lookup, and population operations.
- `FidHasher` -- Computes hash quads (`FidHashQuad`) over masked function bytes. The hasher masks out relocatable operands before hashing.
- `FidHashQuad` -- A tuple of four hashes used for function identification: full hash, specific hash, and two additional disambiguation hashes.
- `FidProgramSeeker` -- Uses the hasher and query service together to identify functions in a program against a FID database.

**Building a custom FID database programmatically:**

```java
import ghidra.feature.fid.service.FidService;

FidService fidService = new FidService();

// Create a new FID database
FidDB fidDb = fidService.createNewFidDatabase(new File("/path/to/custom.fidb"));

// Open a program and populate the database
// Every function must have a non-default name assigned
// (imported from debug info, or assigned by script/analyst)
fidService.populateFidDatabase(fidDb, programList, languageId, monitor);

fidDb.close();
```

**Custom fingerprinting beyond FID:** For ML-augmented fingerprinting, a practical pattern is to compute FID hashes as the fast deterministic layer, then fall back to a learned model for unmatched functions. The FID hash can serve as a cache key -- if two functions have the same FID hash, skip the expensive embedding computation.

#### EmulatorHelper for Dynamic Feature Extraction

Ghidra's `EmulatorHelper` class enables p-code-level emulation for dynamic feature extraction. This is valuable for similarity models that benefit from runtime behavior signals (as in the Trex approach).

**Basic emulation pattern:**

```java
import ghidra.app.emulator.EmulatorHelper;

EmulatorHelper emu = new EmulatorHelper(currentProgram);

// Set up initial state
emu.writeRegister("RSP", 0x7fff0000L);
emu.writeRegister("RBP", 0x7fff0000L);

// Set entry point
emu.setBreakpoint(functionEndAddress);
emu.run(functionStartAddress, monitor);

// Read results
long returnValue = emu.readRegister("RAX");
byte[] memoryRegion = emu.readMemory(address, length);

emu.dispose();
```

**Applications for similarity:**
- **De-obfuscation before embedding:** Emulate obfuscated functions to resolve dynamic string construction, constant unfolding, or control-flow flattening before computing embeddings. The [EmuX86DeobfuscateExampleScript.java](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/Base/ghidra_scripts) demonstrates this pattern.
- **Micro-trace extraction:** Capture instruction-level register and memory state during emulation, producing micro-traces suitable for Trex-style models.
- **Dynamic feature extraction:** Record memory access patterns, system call sequences, or cryptographic constant usage during emulation as auxiliary similarity signals.

**Limitations:** The `EmulatorHelper` operates at the p-code level, not at the hardware level. It does not model OS interactions (system calls, threading), peripheral I/O, or timing. For functions with side effects beyond pure computation, emulation must be carefully scaffolded with mocked system call handlers.

**References:**
- [DecompInterface API docs](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html)
- [Exploring Ghidra Decompiler Internals for P-Code (NCC Group)](https://www.nccgroup.com/research-blog/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/)
- [Ghidra Scripting for Analysis and ML Applications (malware.re)](https://class.malware.re/2021/03/21/ghidra-scripting-feature-extraction.html)
- [Machine Emulation with Ghidra (Syscall7)](https://syscall7.com/machine-emulation-with-ghidra/)
- [PCode Emulation (VoidStar Security)](https://voidstarsec.com/blog/ghidra-pcode)
- [EmulatorHelper API docs](https://ghidra.re/ghidra_docs/api/ghidra/app/emulator/EmulatorHelper.html)
- [FidService source](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/service/FidService.java)
- [FID documentation (ghidra-data)](https://github.com/NationalSecurityAgency/ghidra-data/blob/master/FunctionID/FID.md)

### Local-First vs. Corpus-Scale Deployment

#### Local-First (Single Analyst)

- **Use case**: Analyst comparing functions within a single binary or small set of binaries. No network required.
- **Vector storage**: SQLite with a vector extension (sqlite-vss) or flat numpy arrays. For <100K functions, brute-force cosine similarity is fast enough.
- **Model inference**: ONNX Runtime or similar for local model execution. Small models (SAFE, Asm2Vec) run in seconds per function on CPU.
- **Advantages**: Privacy (no data leaves the machine), no infrastructure, works offline, zero latency.
- **Limitations**: Limited corpus size, no crowd-sourced knowledge.

#### Corpus-Scale (Team / Organization)

- **Use case**: Searching across millions of pre-analyzed functions (firmware images, malware corpora, library versions).
- **Vector storage**: Purpose-built vector databases (Milvus, Qdrant, Weaviate) with approximate nearest-neighbor (ANN) indices (HNSW, IVF).
- **Model inference**: GPU-accelerated batch embedding pipeline, possibly as a microservice.
- **Advantages**: Massive recall, team collaboration, amortized embedding cost.
- **Limitations**: Infrastructure overhead, latency, privacy concerns (mitigated by on-premises deployment).

#### Hybrid Approach

The most practical deployment layers both:
1. **Local cache**: Recently computed embeddings stored in a lightweight local index.
2. **Remote corpus**: Organization-wide vector DB queried on cache miss.
3. **Progressive refinement**: Start with deterministic fingerprint (fast, exact), then use embedding similarity for unmatched functions.

### Deterministic Fingerprinting as Baseline + Learned Models as Optional Backends

The strongest practical architecture combines deterministic and learned approaches:

**Layer 1 -- Deterministic fingerprinting (always-on):**
- Hash-based matching (a la Ghidra FID, IDA Lumina, WARP).
- Zero false positives, sub-millisecond lookup.
- Handles the easy cases: statically linked libraries, exact function reuse.
- Should cover 30--60% of functions in a typical binary (standard library, compiler runtime, common frameworks).

**Layer 2 -- Learned embedding similarity (optional backend):**
- Activated for functions not matched by Layer 1.
- Produces a ranked list of candidate matches with confidence scores.
- Can use different backends depending on the task:
  - Cross-architecture comparison: VexIR2Vec (operates on VEX-IR, architecture-neutral).
  - Same-architecture, cross-compiler: jTrans or CRABS-former.
  - Binary-to-source matching: BinaryAI.
  - General-purpose: SAFE or fine-tuned Transformer.
- Results are presented to the analyst with confidence scores for human validation.

**Layer 3 -- LLM-assisted analysis (experimental):**
- For functions where embedding similarity is inconclusive, use LLM-based decompilation summaries as an additional similarity signal.
- BinMetric (IJCAI 2025) results suggest LLMs are capable at algorithm classification and code summarization, which could complement embedding-based similarity.

**Benefits of layered approach:**
- Deterministic layer provides a trusted baseline that never produces false positives.
- Embedding layer extends coverage to cross-compilation and cross-architecture scenarios.
- Each layer is independently testable and deployable.
- Organizations can start with deterministic-only and add ML backends incrementally.
- The embedding backend can be swapped (local model vs. cloud API) without changing the plugin interface.

---

## Emerging Approaches (2025--2026)

The binary similarity field is undergoing a rapid shift driven by large language models, multi-modal learning, and graph foundation models. These emerging approaches are not yet as mature as the established methods above, but they represent the trajectory of the field and are likely to define the next generation of practical tools.

### LLM-Generated Function Summaries as Similarity Signals

A breakthrough direction is using LLMs to generate natural-language summaries of binary functions, then comparing summaries (or their embeddings) rather than raw code representations. This converts the binary similarity problem into a text similarity problem, leveraging the massive pre-training of general-purpose language models.

#### EBM: Uptraining Generic LLMs for Binary Code Embedding (NeurIPS 2025)

- **Key contribution**: Multi-phase framework that transforms a generic coder LLM into a binary code embedding and matching expert.
- **Method**: Applies a sequence of uptraining phases -- data augmentation (generating diverse compilations of the same source), translation-style causal learning (binary-to-source alignment), LLM2Vec adaptation (converting causal LLMs to bidirectional encoders), and cumulative GTE loss (contrastive fine-tuning for embedding quality).
- **Results**: Increases mean reciprocal rank (MRR) by 10--70% depending on the task (cross-optimization, cross-architecture, cross-obfuscation), significantly outperforming prior SOTA on standard benchmarks.
- **Significance for integration**: Demonstrates that a single LLM-based model can serve as a universal binary embedding backend, potentially replacing the multiple specialized models (jTrans for same-arch, VexIR2Vec for cross-arch, etc.) recommended in the layered architecture above.
- Reference: "Transforming Generic Coder LLMs to Effective Binary Code Embedding Models for Similarity Detection," NeurIPS 2025.

#### FoC: LLM-Based Cryptographic Function Identification (TOSEM 2025)

- **Key contribution**: Two-component framework for identifying cryptographic functions in stripped binaries using LLM-generated semantic summaries.
- **FoC-BinLLM**: Encoder-decoder Transformer trained with multi-task and frozen-decoder strategies to summarize binary function semantics in natural language. Outperforms ChatGPT by 14.61% on ROUGE-L for cryptographic function summarization.
- **FoC-Sim**: Binary code similarity model built on top of FoC-BinLLM embeddings, using multi-feature fusion. Achieves 52% higher Recall@1 than prior methods for retrieving similar cryptographic implementations.
- **Practical utility**: Demonstrated in real-world cryptographic virus analysis and 1-day vulnerability detection scenarios.
- **Significance for integration**: Shows that domain-specific fine-tuning of LLMs for binary summarization can dramatically outperform both general LLMs and traditional embedding models in specialized domains. This suggests that a practical system might use domain-specific LLM summarizers (crypto, networking, filesystem, etc.) as specialized similarity backends.
- Reference: Chen et al., "FoC: Figure out the Cryptographic Functions in Stripped Binaries with LLMs," ACM TOSEM 2025.

#### KEENHash: Program-Level Similarity via LLM Function Embeddings (ISSTA 2025)

- **Key contribution**: Scales binary similarity from function-level to program-level by hashing entire binaries into compact program embeddings using LLM-generated function embeddings.
- **Method**: Uses K-Means and Feature Hashing to condense all function embeddings in a binary into a single fixed-length bit-vector. This enables program-level clone search without pairwise function matching.
- **Performance**: 215x faster than SOTA function-matching tools while maintaining effectiveness. In a large-scale scenario with 5.3 billion similarity evaluations, KEENHash takes 395 seconds vs. an estimated 56 days for function-level tools.
- **Evaluation**: Outperforms 4 SOTA methods by at least 23.16% on program clone search across 202,305 binaries.
- **Significance for integration**: Program-level similarity enables rapid triage of binary corpora (e.g., "find all binaries in this firmware dump that are variants of this known program") without the cost of function-by-function comparison.
- Reference: Liu et al., "KEENHash: Hashing Programs into Function-aware Embeddings for Large-scale Binary Code Similarity Analysis," ISSTA 2025.

### Multi-Modal Embeddings: Combining Multiple Representation Channels

Rather than relying on a single representation (assembly, p-code, decompiled C, or CFG), multi-modal approaches fuse information from multiple channels to produce richer embeddings.

#### IRBinDiff: LLVM-IR + GNN + Contrastive Learning (arXiv 2024)

- **Key contribution**: Lifts binaries to LLVM-IR (via RetDec or similar) and combines a pre-trained language model with a graph neural network to capture both semantic and structural information.
- The language model processes LLVM-IR token sequences (semantic channel), while the GNN processes the IR's control-flow and data-flow graph structure (structural channel).
- Uses momentum contrastive learning to enhance sensitivity to subtle differences in large candidate pools.
- LLVM-IR provides architecture-independent representation, making the approach inherently cross-platform. Effective for IoT firmware analysis where binaries target heterogeneous architectures (ARM, MIPS, x86, RISC-V).
- Reference: "Binary Code Similarity Detection via Graph Contrastive Learning on Intermediate Representations," arXiv:2410.18561 (2024).

#### Binary2vec: GNN with Global Attention on A-PROGRAML Graphs (2025)

- **Key contribution**: Constructs cross-architecture binary embeddings using a novel graph representation called A-PROGRAML, fed into a GPS (General, Powerful, Scalable) graph neural network with global attention.
- A-PROGRAML extends the PROGRAML graph representation (which unifies control flow, data flow, and call graphs) to work with binary-lifted LLVM-IR, adding architecture-specific annotations.
- The GPS architecture with global attention enables the model to capture long-range dependencies in the program graph, important for functions with complex control flow.
- Reference: "Binary2vec: Cross-architecture binary embeddings with global attention-enhanced graph neural networks," 2025.

#### Fus: Pseudo-C + AST Fusion (Electronics 2025)

- **Key contribution**: Combines semantic information from decompiler pseudo-C output with structural features from the Abstract Syntax Tree (AST).
- The pseudo-C channel is processed by a pre-trained code model; the AST channel is processed by a tree-based neural network.
- Both pseudo-C and AST representations are robust against compilation and architectural changes, providing complementary views of function semantics.
- Reference: "Fus: Combining Semantic and Structural Graph Information for Binary Code Similarity Detection," Electronics 2025.

**Multi-modal design principles emerging from these works:**
1. **Semantic + structural fusion outperforms either alone.** Language models capture token-level semantics; GNNs capture graph topology. Combining both consistently improves accuracy.
2. **IR-level representations reduce architecture dependence.** Lifting to LLVM-IR, VEX-IR, or Ghidra p-code before embedding enables cross-architecture matching without architecture-specific training.
3. **Contrastive learning is the dominant training paradigm.** All recent multi-modal approaches use some form of contrastive learning (triplet loss, InfoNCE, momentum contrast) to learn embeddings where similar functions cluster together.

### Graph Foundation Models for Binary Analysis

Graph foundation models (GFMs) -- large pre-trained models operating on graph-structured data -- are an emerging frontier with potential to transform binary similarity detection. While no binary-specific GFM exists yet, the building blocks are converging.

**Current state of graph foundation models:**
- GFMs are being developed for molecular graphs, social networks, and knowledge graphs, with architectures like Graph Transformers and GPS (General, Powerful, Scalable) networks.
- Key capability: Transfer learning across graph domains, similar to how BERT transferred across NLP tasks. A GFM pre-trained on diverse program graphs could potentially be fine-tuned for binary similarity without task-specific training data.

**Application to binary analysis:**

- **GBsim (2025)**: Hybrid GCN-BERT architecture that combines graph convolutional networks (for CFG structure) with BERT (for instruction semantics) to achieve cross-architecture binary similarity. Demonstrates the power of combining graph foundation model concepts with language model pre-training for binary analysis.
- **REVDECODE (USENIX 2025)**: Uses context-aware graph representations to enhance binary function matching, incorporating inter-procedural context (callers, callees, shared data references) into per-function representations.
- **MSSA (2025)**: Multi-stage semantic-aware neural network that processes binary functions through multiple analysis stages, each extracting progressively more abstract semantic features, inspired by the layered feature extraction approach of large foundation models.

**Why GFMs matter for binary similarity:**
1. **Programs are inherently graphs.** Control-flow graphs, data-flow graphs, call graphs, and abstract syntax trees are all natural graph structures. A foundation model that understands graph structure at a deep level could capture program semantics more effectively than sequence-based models.
2. **Transfer learning across binary analysis tasks.** A GFM pre-trained on diverse binary program graphs could be fine-tuned not just for similarity but also for vulnerability detection, malware classification, function boundary identification, and type recovery.
3. **Scaling laws.** As with language models, graph foundation models are expected to improve with scale (more pre-training data, larger models), potentially achieving performance that task-specific smaller models cannot reach.

**Open challenges:**
- No standard large-scale binary program graph dataset exists for pre-training a GFM.
- Graph Transformers are computationally expensive and struggle with the scale of real-world binary CFGs (functions with hundreds of basic blocks, programs with tens of thousands of functions).
- Cross-domain transfer (e.g., from source code graphs to binary code graphs) remains poorly understood.

**References for emerging approaches:**
- [EBM (NeurIPS 2025)](https://openreview.net/forum?id=qwwPhjDea0)
- [FoC (TOSEM 2025)](https://dl.acm.org/doi/10.1145/3731449)
- [KEENHash (ISSTA 2025)](https://dl.acm.org/doi/10.1145/3728911)
- [IRBinDiff (arXiv 2024)](https://arxiv.org/abs/2410.18561)
- [Binary2vec (2025)](https://www.sciencedirect.com/science/article/pii/S2590005625001183)
- [GBsim (Entropy 2025)](https://www.mdpi.com/1099-4300/27/4/392)
- [Fus (Electronics 2025)](https://www.mdpi.com/2079-9292/14/19/3781)
- [Awesome Binary Similarity (curated list)](https://github.com/SystemSecurityStorm/Awesome-Binary-Similarity)
- [Graph Foundation Models survey (IEEE TPAMI 2025)](https://dl.acm.org/doi/10.1109/TPAMI.2025.3548729)

---

## Key Takeaways for Ghidra Integration

1. **Deterministic FID is a solid foundation but insufficient alone.** Ghidra's existing Function ID covers exact byte-match scenarios well. The gap is cross-compiler, cross-optimization, and cross-architecture matching -- exactly where learned models excel.

2. **VexIR2Vec is the most natural fit for Ghidra's architecture.** It operates on VEX-IR (architecture-neutral), aligns with Ghidra's philosophy of lifting to p-code/IR before analysis, and achieves strong cross-architecture results. A Ghidra adaptation could lift to p-code instead of VEX-IR and apply similar normalization + embedding techniques.

3. **jTrans represents the current practical SOTA for same-architecture similarity.** Its jump-aware Transformer encoding captures control-flow semantics that pure sequence models miss. The BinaryCorp dataset provides a realistic evaluation baseline.

4. **A layered architecture (FID -> embeddings -> LLM) is the right design.** Fast deterministic matching handles the bulk of identifications; learned models handle the long tail; LLM analysis assists the analyst on truly novel code.

5. **New benchmarks (REFuSe-Bench, BinCodex) should guide model selection.** REFuSe-Bench's finding that a simple raw-byte CNN can match complex models is a useful calibration point -- it suggests that for practical deployment, simpler models may suffice and should be tried first.

6. **Local-first deployment is viable and preferred for RE workflows.** Models like SAFE and Asm2Vec are small enough to run locally. SQLite-based vector storage handles analyst-scale corpora. Cloud/team-scale infrastructure should be optional, not required.

7. **The WARP open format is worth adopting.** Binary Ninja's decision to open-source the WARP signature format creates an opportunity for cross-tool interoperability. A Ghidra plugin could consume WARP signatures alongside FID databases.

8. **Binary-to-source matching (BinaryAI) enables SCA workflows.** Identifying which open-source libraries are compiled into a binary is a high-value use case that complements function-level similarity. This could be a dedicated plugin mode.

9. **Embedding quality should be evaluated on REFuSe-Bench and BinCodex** before deployment, as these provide the most realistic and comprehensive evaluation settings currently available.

10. **The field is converging on Transformer + IR-based approaches.** The trajectory from Gemini (GNN on CFG, 2017) through jTrans (Transformer + control-flow, 2022) to VexIR2Vec (Transformer on normalized IR, 2024) shows a clear trend toward architecture-neutral, semantics-aware representations -- which is exactly what Ghidra's p-code framework was designed to enable.
