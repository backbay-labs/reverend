# Decompilation and Type Recovery: Research Landscape

> Compiled: 2026-02-19 | Scope: Neural/LLM-assisted decompilation, type recovery, benchmarks, and Ghidra integration context
>
> Verification note: reported benchmark metrics are paper-reported values and were not independently reproduced in this repository.

---

## 1. Neural and LLM-Assisted Decompilation

### 1.1 Foundation Models for Assembly Code

**Nova** (ICLR 2025) -- Jiang, Wang et al.
A generative foundation LLM for assembly code. Introduces *hierarchical attention* with three granularity levels (intra-instruction, preceding-instruction, inter-instruction) plus *contrastive learning* objectives (functionality contrastive + optimization contrastive). Addresses the low information density and diverse optimization patterns that make assembly hard for standard LLMs. Outperforms prior SOTA on binary decompilation by 14.8--21.6% higher Pass@1 and on binary similarity detection by up to 6.17% Recall@1. Models are publicly available on Hugging Face.

**SLaDe** (CGO 2024) -- Armengol-Estape et al., University of Edinburgh
A 200M-parameter small language model decompiler. Introduces a novel code tokenizer and type inference-augmented neural decompilation with dropout-free training. Up to 6x more accurate than Ghidra and 4x more accurate than ChatGPT on semantic accuracy benchmarks. Demonstrates that small, specialized models can be competitive with much larger general-purpose LLMs for decompilation tasks.

### 1.2 Beyond C: Retargetable Neural Decompilation

**BTC -- Beyond The C** (NDSS BAR Workshop 2022) -- Hosseini, Dolan-Gavitt
Explores decompilation as a text-to-text NMT problem, treating both assembly and source as plain token sequences with no AST parsing, no CPU instruction awareness, and no source-language-specific tokenization. Evaluated on Go, Fortran, OCaml, and C with comparable results to prior work that required language-specific tooling. Key contribution: shows that retargetable decompilation (supporting new languages without rebuilding the pipeline) is feasible via NMT.

### 1.3 Joint Code and Type Prediction

**IDIOMS** (arXiv, February 2025) -- Dramko, Le Goues, Schwartz (CMU)
A training process to fine-tune any LLM into a neural decompiler that jointly predicts decompiled code *and* user-defined types (UDTs). Key innovations:
- Uses deterministic decompiler output (e.g., Ghidra) as model input, predicting refined code alongside type definitions
- Neighbor-context windows (interprocedural callers/callees) yield a 63% increase in UDT composition accuracy
- Introduces **Realtype**, a benchmark with substantially more complex/realistic types than prior datasets
- Achieves 54.4% accuracy vs. 46.3% for LLM4Decompile and 37.5% for Nova on ExeBench; 95%+ improvement on Realtype
- Important insight: type recovery and code decompilation are tightly coupled and benefit from joint modeling

### 1.4 LLM-Based Decompilation Refinement

**LLM4Decompile** (EMNLP 2024) -- Tan et al.
The first and largest open-source LLM series (1.3B to 33B parameters) trained to decompile binary code. Two strategies:
- **End-to-End (End)**: Decompiles binary directly. Outperforms GPT-4o and Ghidra by over 100% in re-executability rate on HumanEval and ExeBench
- **Refinement (Ref)**: Refines Ghidra pseudo-code output. Achieves a further 16.2% improvement over the End approach
- Open-source models and data on HuggingFace/GitHub

**DeGPT** (NDSS 2024) -- Hu, Liang, Chen
End-to-end framework for optimizing decompiler output readability using LLMs. Three-role mechanism:
- *Referee*: provides optimization scheme
- *Advisor*: gives rectification measures
- *Operator*: verifies semantics are preserved
Achieves 24.4% reduction in cognitive burden on Ghidra output; 62.9% of generated comments provide practical semantics. Open-source on GitHub.

**DecLLM** (ISSTA 2025) -- Wang et al.
LLM-augmented *recompilable* decompilation. Uses an iterative repair loop with static recompilation feedback (compiler errors) and dynamic runtime feedback (ASAN + test cases). Achieves ~70% recompilation success rate on previously non-recompilable outputs. Enables downstream programmatic analysis (e.g., CodeQL) on decompiled code.

**SK2Decompile** (arXiv, September 2025) -- Tan, Li et al.
Two-phase approach: (1) Structure Recovery model translates binary to IR "skeleton" with control flow preserved but identifiers obfuscated; (2) Identifier Naming model produces meaningful names as the "skin." Both phases use reinforcement learning. Outperforms SOTA baselines: 21.6% average re-executability gain over GPT-5-mini on HumanEval, 29.4% R2I improvement over IDIOMS on GitHub2025.

### 1.5 AI-Assisted Decompilation Trends (2024 Survey)

Per mahaloz's "Decompiling 2024" survey, 2024 publications made up nearly 30% of all top publications ever in decompilation research. Four works utilized AI (symbol prediction, type prediction, code simplification). LLMs debuted in decompilation via DeGPT and ReSym (variable names, structures, types). VarBERT (BERT for variable names) and TyGr (GNN for structure/type prediction) also emerged. Notably, all but one 2024 paper shipped open-source implementations.

---

## 2. Decompilation Benchmarks and Evaluation

### 2.1 Decompile-Bench

**Decompile-Bench** (NeurIPS 2025) -- Tan et al.
The first open-source million-scale dataset: 2M binary-source function pairs condensed from 100M collected pairs (450 GB of binaries compiled from permissively licensed GitHub projects). Key features:
- **CTF framework**: Automated pipeline that compiles projects, traces each binary function to source, and rigorously filters low-quality examples
- **Decompile-Bench-Eval**: Manually crafted binaries from HumanEval/MBPP + GitHub repos published after 2025 (preventing data leakage)
- Fine-tuning with Decompile-Bench yields 20% improvement in re-executability rate over prior benchmarks

### 2.2 ExeBench

**ExeBench** -- Armengol-Estape et al.
5,000 real-world C functions from GitHub with IO examples. Used as a standard evaluation benchmark across multiple decompilation papers. Evaluates re-executability: whether decompiled code can compile and pass provided test cases.

### 2.3 DecompileBench (Comprehensive Evaluation)

**DecompileBench** (ACL 2025)
A comprehensive benchmark for evaluating decompilers in real-world scenarios, going beyond prior function-level benchmarks.
This is a distinct benchmark name from **Decompile-Bench** above; keep sources separated to avoid citation mix-ups.

### 2.4 Evaluation Methodologies

Modern decompilation evaluation has moved well beyond string matching. Key metrics:
- **Re-executability Rate (ESR)**: Can decompiled code compile and pass all functional tests?
- **Recompile Success Rate (RSR)**: Can decompiled code compile at all?
- **Coverage Equivalence Rate (CER)**: Runtime behavioral equivalence
- **Readability metrics**: R2I (readability index), edit similarity, CodeBLEU, AST similarity
- **Novel automated random testing**: Evaluates semantic consistency without requiring recompilation, addressing the fact that most decompilers do not produce recompilable output

### 2.5 Data Leakage Concerns

A significant concern in neural decompilation research. Decompile-Bench-Eval addresses this by including only GitHub repos published after 2025 and manually crafted challenge binaries. Prior benchmarks (HumanEval, ExeBench) risk overlap with LLM training data. The Realtype benchmark (from IDIOMS) similarly aims for realistic complexity absent from standard training corpora.

---

## 3. Type Recovery

### 3.1 Learning-Based Approaches

**StateFormer** (ESEC/FSE 2021) -- Pei et al., Columbia University
Fine-grained type recovery using a two-step transfer learning paradigm:
1. Pretraining with *Generative State Modeling (GSM)*: teaches the model to statically approximate execution effects of assembly instructions in forward and backward directions
2. Fine-tuning: uses learned operational semantics knowledge to infer types
Key contribution: a neural architecture purpose-built for type inference that models how instructions transform program state. Addresses the inherent uncertainty of type recovery from stripped binaries.

**DIRTY -- DecompIled variable ReTYper** (USENIX Security 2022) -- Chen et al., CMU
Transformer-based model for post-processing decompiled code to predict variable names and types. Trained on code scraped from GitHub:
- Recovers original developer-written names 66.4% of the time
- Recovers original types 75.8% of the time
- Released DIRT dataset: 75K+ programs, 1M+ human-written C functions paired with decompiler outputs
- Operates as a post-hoc augmentation layer on top of existing decompilers

**SnowWhite / "Finding the Dwarf"** (PLDI 2022) -- Lehmann et al.
Learning-based type recovery for WebAssembly binaries. Converts type recovery from classification to *sequence prediction* using neural seq2seq models with an expressive type language (not a fixed vocabulary). Dataset: 6.3M types from 300K+ Wasm object files compiled from 4,000+ C/C++ Ubuntu packages. Achieves 44.5% (75.2% top-5) exact match on parameter types, 57.7% (80.5% top-5) on return types.

**TyGr** (2024)
GNN-based approach for predicting structures and variable types. Part of the 2024 resurgence in learning-based decompilation research.

**VarBERT** (2024)
BERT-based model for variable name prediction in decompiled code.

### 3.2 Deductive and Constraint-Based Approaches

**RETYPD** -- GrammaTech
Polymorphic type inference for binaries using subtyping. Key innovation: treats pointer uses as either covariant or contravariant, enabling much more precise inference than unification-based algorithms. Designed with a simple front-end schema so it can work with any disassembler (Ghidra, IDA, etc.). Uses lattice-based/push-down typing algorithms to infer complex types (recursive structs, pointers, polymorphic references). Open-source on GitHub.

**OSPREY** (IEEE S&P 2021) -- Zhang, Ye et al.
Probabilistic technique for variable and structure recovery. Introduces random variables for the likelihood of abstract memory locations having various types and structural properties, connected via probabilistic constraints from program analysis. Achieves >88% recall and >90% precision, outperforming Ghidra (~77% recall, ~70% precision).

**BinSub** (SAS 2024) -- Smith, Trail of Bits
Connects algebraic subtyping to binary type inference. Achieves simple, precise, and efficient polymorphic type inference for machine code. Maintains similar precision to prior work (RETYPD) while achieving a **63x improvement** in average runtime across 1,568 functions. Implemented in the angr binary analysis framework. Key insight: recent advances in traditional type theory (algebraic subtyping) can be directly applied to binary type inference.

**TRex** (USENIX Security 2025) -- Bosamiya, Woo, Parno (CMU/Microsoft)
Practical *deductive* type reconstruction. Shifts focus from recovering lost source types to constructing accurate *behavior-capturing* types. Outperforms Ghidra on 124 of 125 binaries tested, with an average score 24.83% higher than Ghidra. Works on arbitrary disassembly from any architecture liftable to its IR. Key philosophical contribution: acknowledges the impossibility of fully recovering source types and instead optimizes for types that accurately describe binary behavior.

### 3.3 Hybrid Approaches

**HyRES** (ACM TOSEM 2025)
Hybrid reasoning for structure recovery combining static analysis, LLMs, and heuristic methods. Analyzes structure layout, infers semantics via LLM, then performs semantic-enhanced structure aggregation. Represents an emerging trend of combining classical analysis with neural methods.

**ReSym** (2024)
Uses LLMs to recover variable names, structures, and types. Part of the first wave of LLM-integrated type recovery tools.

### 3.4 Learning vs. Deductive: Comparative Summary

| Aspect | Learning-Based | Deductive/Constraint | Hybrid |
|--------|---------------|---------------------|--------|
| **Strengths** | Handles ambiguity, recovers names, tolerates noise | Sound reasoning, scales to complex types, predictable | Best of both worlds |
| **Weaknesses** | Training data bias, hallucination, hard to verify | Incomplete type lattices, requires precise analysis | System complexity |
| **Examples** | StateFormer, DIRTY, SnowWhite | RETYPD, BinSub, TRex | HyRES, OSPREY, IDIOMS |
| **Type Granularity** | Primitive + some UDTs | Primitives + structs + pointers | Full spectrum |
| **Best For** | Variable naming + primitive types | Struct layout + pointer analysis | Real-world RE workflows |

---

## 4. Type Benchmarking

### 4.1 Dedicated Benchmarks for Binary Type Inference

**"Benchmarking Binary Type Inference Techniques in Decompilers"** (SURE 2025) -- Soni
Establishes metrics to evaluate type inference in decompilers. Benchmarks Ghidra, angr, and Binary Ninja, along with Retypd (Ghidra plugin). First dedicated benchmark focused specifically on type inference quality across multiple tools.

**BinMetric** (IJCAI 2025)
Comprehensive binary code analysis benchmark evaluating LLMs and baselines including IDA Pro Hex-Rays and LLM4Decompile models. Covers type inference as part of broader binary understanding evaluation.

**Realtype** (from IDIOMS, 2025)
Benchmark with substantially more complicated and realistic user-defined types than existing neural decompilation benchmarks. Specifically designed to stress-test UDT recovery.

**DIRT Dataset** (from DIRTY, 2022)
75K+ programs, 1M+ C functions paired with decompiler outputs. Standard training/eval corpus for variable name and type prediction.

### 4.2 Evaluation Gaps

Current type benchmarks primarily focus on:
- Exact match accuracy for primitive types
- Struct field recovery precision/recall
- Variable name recovery rates

Still lacking:
- Standardized metrics for complex type recovery (unions, nested structs, function pointers)
- Cross-architecture type recovery evaluation
- Evaluation of type recovery impact on downstream RE tasks (vulnerability finding, patch diffing)

---

## 5. Ghidra Decompiler Context

### 5.1 P-Code to Decompiler Pipeline

Ghidra's decompilation pipeline follows a multi-stage architecture:

1. **SLEIGH Translation**: Machine code instructions are translated to low-level P-Code via SLEIGH processor specifications. SLEIGH is Ghidra's domain-specific language for describing instruction sets.

2. **Raw P-Code Generation**: The "firstpass" analysis style produces an unmodified syntax tree of dataflow from raw P-Code (150+ ops for typical functions).

3. **SSA Construction**: Phi-node placement using control flow dominator tree and dominance frontier, with standard renaming algorithm for linking variable defs and uses.

4. **Term Rewriting / Simplification**: Formal Methods-style term rewriting applies a long list of rules to the syntax tree. Each rule matches a configuration and specifies edit operations. Includes: copy propagation, constant propagation, algebraic simplifications, undoing compiler multiplication/division optimizations, commuting operators. The "decompile" style produces ~24 ops (vs 150+ in firstpass).

5. **Type Propagation**: Information gathered from instruction usage (e.g., floating-point ops), header files, and user annotations is propagated through syntax trees to determine related variable types.

6. **C Code Emission**: Final clean-up and C code generation. The "normalize" analysis style omits type recovery and final clean-up, producing normalized P-Code syntax trees suitable for automated analysis.

### 5.2 Analysis Styles

| Style | Type Recovery | Simplification | Use Case |
|-------|:---:|:---:|------|
| `firstpass` | No | No | Raw P-Code dataflow |
| `register` | No | Partial | Register-level analysis |
| `normalize` | No | Yes | Normalized P-Code for scripts |
| `decompile` | Yes | Yes | Full C output (default) |

### 5.3 Where Type Recovery Hooks In

Type recovery occurs *after* simplification and *before* final C emission. This means:
- It operates on already-simplified P-Code (SSA form, propagated constants, reduced ops)
- Type information from function signatures, data types defined in the program database, and DWARF/PDB debug info feeds into the propagation phase
- Custom type information can be injected via Ghidra's API (`DataTypeManager`, `DecompInterface.setSimplificationStyle`)
- The `DecompInterface` Java API provides programmatic access to all analysis styles, enabling plugins to access pre-type-recovery or post-type-recovery representations

### 5.4 Current Limitations Relative to Hex-Rays

| Capability | Ghidra | Hex-Rays (IDA Pro) |
|-----------|--------|-------------------|
| **C++ class recovery** | Good (improving) | Excellent (MSVC++ specialization) |
| **Name demangling** | Adequate | Superior (especially MSVC++) |
| **Struct inference** | Good | Good |
| **Local variable types** | Types inferred but limited | More precise with Hex-Rays plugin |
| **RTTI parsing** | Basic | Mature |
| **User type annotation** | Full API support | Mature UI/API |
| **Extensibility** | Excellent (Java/Python API, P-Code access) | Plugin SDK (more limited) |
| **Multi-arch support** | Excellent (SLEIGH) | Excellent (but per-license) |
| **Cost** | Free/open-source | Commercial ($$$) |

Key Ghidra advantages for ML integration:
- Open-source C++ decompiler engine with full source access
- Java API for programmatic decompilation at scale
- Access to intermediate representations (raw P-Code, normalized P-Code) that can serve as ML model inputs
- SLEIGH provides a clean abstraction over ISA-specific details
- Active community developing analysis plugins

Key Ghidra limitations:
- Type propagation is less aggressive than Hex-Rays for C++ code
- No built-in ML-based type/name recovery (must be added via plugins)
- Decompiler output is sometimes less readable than Hex-Rays for complex optimized code

### 5.5 Decompiler Action System

The Ghidra decompiler's transformation pipeline is organized through a hierarchical **Action/Rule system** defined in `coreaction.cc`, `ruleaction.cc`, and `ruleaction.hh` in `Ghidra/Features/Decompiler/src/decompile/cpp/`. This system is the engine that transforms raw P-Code into readable C output.

#### Action Hierarchy

The core abstraction is the `Action` base class. Actions compose into groups:

- **`Action`**: Base class for all transformation steps. Each action has a name, a group membership, and an `apply()` method operating on a `Funcdata` object (the decompiler's representation of a function).
- **`ActionGroup`**: An ordered sequence of child actions executed in series. Used to define pipeline stages (e.g., "all simplification steps").
- **`ActionPool`**: A *repeated* group -- child actions (typically `Rule` instances) are applied in a loop until none of them produce further changes (a fixpoint). This implements the term-rewriting fixpoint loop.
- **`ActionRestartGroup`**: Like `ActionGroup` but restarts from the beginning if any child action succeeds. Used for phases where earlier simplifications may re-enable later ones.

#### The Full Action Pipeline

`ActionDatabase::universalAction(Architecture *conf)` in `coreaction.cc` constructs the master action tree. The six root actions (analysis styles) select different subsets of ~220 individual actions organized into "base groups":

| Root Action | Base Groups Included | Purpose |
|-------------|---------------------|---------|
| `firstpass` | (none) | Raw P-Code syntax tree, no transformation |
| `register` | stackvars (partial) | Register-level analysis, no stack promotion |
| `normalize` | stackvars, deadcode, propagate, protorecovery | Simplified P-Code without types |
| `decompile` | All groups including typerecovery, cleanup | Full C output (default) |
| `paramid` | Enough for parameter identification | Function prototype extraction |
| `jumptable` | Enough for switch recovery | Jump table resolution |

The `decompile` pipeline executes roughly in this order:

1. **`ActionStart`** -- Initialize the Funcdata, set up address spaces
2. **`ActionHeritage`** -- Build SSA form (phi-node placement, def-use linking via dominator tree)
3. **`ActionNormalizeSetup`** -- Prepare for the main simplification loop
4. **Main simplification `ActionPool`** (`actprop`) -- The core fixpoint loop containing ~170 Rule instances. Rules are applied repeatedly until no rule produces a change:
   - Copy propagation, constant folding, dead code elimination
   - Algebraic simplifications (arithmetic, boolean, bitwise, shift)
   - Compiler-idiom recovery (optimized division/modulo, conditional moves)
   - Sub-variable flow analysis, concatenation simplification
   - Pointer arithmetic normalization
5. **`ActionActiveParam`** / **`ActionDefaultParams`** -- Recover function prototypes and calling conventions
6. **`ActionInferTypes`** -- Type propagation and inference (only in `decompile` style)
7. **`ActionMarkExplicit`** / **`ActionMarkImplied`** -- Determine which varnodes become explicit C variables vs. implicit subexpressions
8. **`ActionNameVars`** -- Assign human-readable variable names
9. **`ActionBlockStructure`** / **`ActionFinalStructure`** -- Recover high-level control flow (if/else, while, for, switch)
10. **C emission** -- Final output generation

#### Key Rule Classes

Rules inherit from the `Rule` base class and implement two methods:
- **`getOpList()`** -- Returns the set of P-Code operation types that trigger this rule (e.g., `CPUI_INT_ADD`, `CPUI_COPY`)
- **`applyOp(PcodeOp *op, Funcdata &data)`** -- Pattern-matches on the op and its inputs/outputs; if the pattern matches, transforms the syntax tree and returns `1` (success) or `0` (no match)

**Constant Propagation and Folding:**
- `RuleCollapseConstants` -- Folds operations on two constants into a single constant (e.g., `3 + 5` becomes `8`)
- `RulePropagateCopy` -- Propagates COPY input to all places reading the output, eliminating unnecessary copies
- `RuleEqual2Constant` -- Simplifies comparisons involving arithmetic with constants

**Dead Code Elimination:**
- `ActionDeadCode` -- Marks P-Code ops whose output has no consumers as dead and removes them. Operates at bit-level precision.
- `RuleEarlyRemoval` -- Removes unused PcodeOps where the output is guaranteed unused based on dataflow analysis

**Algebraic Simplification:**
- `RuleIdentityEl` -- Collapses identity operations: `V + 0 => V`, `V * 1 => V`, `V ^ 0 => V`
- `RuleTrivialArith` -- Simplifies self-canceling operations: `V - V => 0`, `V ^ V => 0`
- `RuleTrivialShift` -- Eliminates zero shifts: `V << 0 => V`
- `Rule2Comp2Sub` -- Converts `INT_ADD(V, INT_2COMP(W))` back to `INT_SUB(V, W)`
- `RuleShift2Mult` -- Converts shifts to multiplications: `V << 2 => V * 4`

**Compiler Idiom Recovery:**
- `RuleDivOpt` -- Recognizes compiler-optimized division patterns (multiply-and-shift) and converts them back to `INT_DIV` / `INT_SDIV`. This is one of the most complex rules, handling the various ways compilers replace division with cheaper multiply-shift sequences.
- `RuleModOpt` -- Similarly recovers modulo operations from optimized forms
- `RuleConditionalMove` -- Detects and simplifies conditional move patterns (`CMOV` on x86) into ternary expressions
- `RuleThreeWayCompare` -- Recovers three-way comparison idioms

**Boolean and Comparison Simplification:**
- `RuleLessNotEqual` -- Simplifies `a <= b && a != b` into `a < b`
- `RuleBoolNegate` -- Applies De Morgan's laws and boolean identities involving negation
- `RuleNotDistribute` -- Distributes `BOOL_NEGATE` through boolean operations
- `RuleTestSign` -- Converts sign-bit extraction (`V >> 31`) into signed comparisons

**Sub-variable Flow:**
- `RuleSubvarAnd` / `RuleSubvarZext` / `RuleSubvarSext` / `RuleSubvarShift` -- Detect when operations use only a portion of a variable's bits and narrow the variable accordingly. These enable recovery of byte/short operations from word-width register operations.

**Pointer and Memory:**
- `RulePtrArith` -- Transforms raw address arithmetic into structured pointer operations
- `RulePtrFlow` -- Marks varnodes and ops that carry or operate on pointer values
- `RuleStructOffset0` -- Converts `LOAD`/`STORE` at offset 0 of a structure into access to the first field
- `RuleLoadVarnode` / `RuleStoreVarnode` -- Convert memory operations with constant offsets into direct varnode copies

#### Adding Custom Simplification Rules

To add a custom rule to the decompiler:

1. **Define the rule class** in `ruleaction.hh` -- inherit from `Rule`, declare `getOpList()` and `applyOp()`
2. **Implement the rule** in `ruleaction.cc` -- write the pattern-matching and transformation logic
3. **Register the rule** in `ActionDatabase::universalAction()` in `coreaction.cc` -- add it to the `actprop` ActionPool (or another appropriate group)
4. **Recompile the decompiler** -- the native decompiler binary must be rebuilt and installed into the Ghidra distribution

The **RuleChef** tool (referenced in Ghidra developer discussions) can generate rule boilerplate from high-level expressions:
```
LessAndNotEqual: BOOL_AND(INT_LESSEQUAL(a, b), INT_NOTEQUAL(a, b)) => INT_LESS(a, b)
```
This generates the C++ class skeleton with `getOpList()` returning `{CPUI_BOOL_AND}` and `applyOp()` implementing the pattern match on the two input sub-trees.

**Important caveat**: Custom rules require recompiling the native C++ decompiler. They cannot be added via the Java/Python plugin API. For transformations that can operate post-decompilation, the Java API (`DecompInterface` + `HighFunction` manipulation) is more practical.

#### Relationship Between Analysis Styles and Actions

Each analysis style corresponds to a root `ActionGroup` that includes or excludes specific base groups:

- **`firstpass`** includes almost nothing -- produces raw P-Code dataflow
- **`register`** adds basic register-level simplification but skips stack variable promotion
- **`normalize`** adds the full simplification pool (`actprop`) and stack analysis but *excludes* the `typerecovery` group, making it ideal for producing clean P-Code without type assumptions
- **`decompile`** includes everything: `actprop` + `typerecovery` + `cleanup` + control flow structuring

This means the `normalize` style runs the same ~170 simplification rules as `decompile` but stops before type inference -- producing a representation where all constant propagation, dead code removal, and algebraic simplification has occurred but types remain as raw sizes. This is the sweet spot for ML model input: simplified enough to be tractable, but without type assumptions that might bias a model's predictions.

---

## 6. Practical Plugin Integration for Type Recovery

### 6.1 DataTypeManager API

Ghidra's `DataTypeManager` (accessible via `currentProgram.getDataTypeManager()`) is the central interface for creating and applying types programmatically. Key operations:

**Creating Types:**
```java
// Get the program's type manager
DataTypeManager dtm = currentProgram.getDataTypeManager();

// Create a new structure
StructureDataType myStruct = new StructureDataType("MyStruct", 0);
myStruct.add(IntegerDataType.dataType, "field_a", "First field");
myStruct.add(PointerDataType.dataType, "field_b", "Pointer field");

// Add to the program's type database (within a transaction)
int txId = dtm.startTransaction("Add inferred types");
try {
    DataType resolved = dtm.addDataType(myStruct, DataTypeConflictHandler.REPLACE_HANDLER);
} finally {
    dtm.endTransaction(txId, true);
}
```

**Applying Types to Variables:**
```java
// Apply a type to a function parameter
Function func = getGlobalFunctions("target_func").get(0);
Parameter param = func.getParameter(0);
param.setDataType(resolvedType, SourceType.USER_DEFINED);

// Apply to a local variable via HighFunction
DecompInterface ifc = new DecompInterface();
ifc.openProgram(currentProgram);
DecompileResults res = ifc.decompileFunction(func, 60, monitor);
HighFunction hf = res.getHighFunction();
HighSymbol sym = hf.getLocalSymbolMap().getSymbols().next();
HighFunctionDBUtil.updateDBVariable(sym, sym.getName(), resolvedType, SourceType.USER_DEFINED);
```

**Batch Type Operations:**
The `DataTypeManager` supports sequential addition of collections with equivalence caching for improved performance. When adding many types (e.g., from an ML model's output), wrap them in a single transaction and use `DataTypeConflictHandler.REPLACE_HANDLER` to update existing types.

### 6.2 DecompInterface Patterns for Batch Type Inference

The `DecompInterface` class provides the bridge between Java plugin code and the native C++ decompiler process. For batch type inference workflows:

**Basic Batch Decompilation:**
```java
DecompInterface ifc = new DecompInterface();
DecompileOptions options = new DecompileOptions();
ifc.setOptions(options);
ifc.openProgram(currentProgram);

// Optional: use "normalize" to get pre-type-recovery P-Code
ifc.setSimplificationStyle("normalize");

FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
while (funcs.hasNext()) {
    Function func = funcs.next();
    DecompileResults res = ifc.decompileFunction(func, 30, monitor);
    if (res.decompileCompleted()) {
        HighFunction hf = res.getHighFunction();
        // Extract features for ML model...
    }
}
ifc.dispose();
```

**Headless Batch Processing:**
For large-scale analysis (training data generation, corpus-wide inference), use the headless analyzer:
```bash
analyzeHeadless /tmp/ghidra_project MyProject \
    -import target_binary \
    -postScript TypeInferenceScript.java output.json \
    -scriptPath /path/to/scripts
```

The script runs after auto-analysis completes, with full access to the `DecompInterface` and `DataTypeManager` APIs.

**Parallel Decompilation:**
For large binaries, Ghidra's `DecompilerParallelConventionAnalysisCmd` demonstrates the pattern for parallelizing decompilation across functions. Each thread needs its own `DecompInterface` instance (the native decompiler process is single-threaded per instance). Create a thread pool with one `DecompInterface` per worker:
```java
// Each worker thread gets its own interface
DecompInterface ifc = new DecompInterface();
ifc.openProgram(program);
// ... decompile assigned functions ...
ifc.dispose();
```

### 6.3 Hooking Into the Decompiler Pipeline Pre/Post Type Recovery

The key to ML-augmented type recovery is controlling *when* in the pipeline your plugin intervenes:

**Pre-Type-Recovery (normalized P-Code):**
```java
ifc.setSimplificationStyle("normalize");
DecompileResults res = ifc.decompileFunction(func, 30, monitor);
HighFunction hf = res.getHighFunction();
// hf contains fully simplified P-Code but NO type inference
// Variables are sized but untyped -- ideal for ML model input
```

**Post-Type-Recovery (full decompilation):**
```java
ifc.setSimplificationStyle("decompile"); // default
DecompileResults res = ifc.decompileFunction(func, 30, monitor);
HighFunction hf = res.getHighFunction();
// hf contains Ghidra's type inferences -- can be compared/overridden
String cCode = res.getDecompiledFunction().getC();
```

**The Override Pattern:**
The practical integration strategy for ML models is:
1. Decompile with `normalize` to get untyped simplified P-Code
2. Feed the P-Code (or the C output from a `decompile` pass) to the ML model
3. Apply model predictions back via `DataTypeManager` and `HighFunctionDBUtil`
4. Re-decompile to verify the effect of applied types

### 6.4 Working with HighFunction and HighVariable

The `HighFunction` is the decompiler's view of a function after analysis. It provides the structured representation needed for ML feature extraction:

**HighFunction** (`ghidra.program.model.pcode.HighFunction`):
- `getLocalSymbolMap()` -- Returns all local variables (as `HighSymbol` instances)
- `getGlobalSymbolMap()` -- Returns global variable references
- `getFunctionPrototype()` -- The inferred function signature
- `getPcodeOps()` -- Iterator over all high-level P-Code operations
- `getBasicBlocks()` -- Control flow graph in terms of PcodeBlockBasic nodes

**HighVariable** (`ghidra.program.model.pcode.HighVariable`):
- A set of Varnodes representing a single high-level variable across its lifetime
- `getDataType()` -- The inferred (or user-set) data type
- `getRepresentative()` -- The primary Varnode representing this variable
- `getInstances()` -- All Varnodes merged into this variable
- Subclasses: `HighLocal` (stack/register locals), `HighGlobal` (global references), `HighParam` (parameters)

**HighSymbol** (`ghidra.program.model.pcode.HighSymbol`):
- The named entity associated with a `HighVariable`
- `getName()` / `getDataType()` -- Name and type as displayed in decompiler output
- Distinct from standard Ghidra `Symbol` objects in the program database -- HighSymbols exist only in the decompiler's view and may differ from database symbols
- Can be updated via `HighFunctionDBUtil.updateDBVariable()` to persist changes

**Feature Extraction for ML Models:**
```java
HighFunction hf = res.getHighFunction();
LocalSymbolMap lsm = hf.getLocalSymbolMap();
Iterator<HighSymbol> symbols = lsm.getSymbols();
while (symbols.hasNext()) {
    HighSymbol sym = symbols.next();
    String name = sym.getName();
    DataType dt = sym.getDataType();
    int size = dt.getLength();
    HighVariable hv = sym.getHighVariable();
    // Extract: storage location, size, data flow neighbors,
    // P-Code ops that read/write this variable, etc.
}
```

### 6.5 Example Workflow: External ML Model to DataTypeManager

A complete pipeline for integrating an external ML model (e.g., DIRTY, IDIOMS, or a custom model) with Ghidra:

**Step 1: Extract features via headless script**
```java
// ExportFeaturesScript.java (runs headless)
DecompInterface ifc = new DecompInterface();
ifc.setSimplificationStyle("normalize");
ifc.openProgram(currentProgram);

JsonArray features = new JsonArray();
for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
    DecompileResults res = ifc.decompileFunction(func, 30, monitor);
    if (!res.decompileCompleted()) continue;
    HighFunction hf = res.getHighFunction();
    // Serialize: function address, P-Code ops, variable storage,
    // cross-references, caller/callee context (neighbor windows)
    features.add(serializeFunction(func, hf));
}
writeJsonToFile(features, scriptArgs[0]);
```

**Step 2: Run ML inference externally**
```bash
python infer_types.py --input features.json --output predictions.json --model idioms-7b
```

**Step 3: Apply predictions back to Ghidra**
```java
// ApplyTypesScript.java (runs headless or in GUI)
JsonArray predictions = readJson(scriptArgs[0]);
DataTypeManager dtm = currentProgram.getDataTypeManager();
int txId = dtm.startTransaction("ML type inference");
try {
    for (JsonElement pred : predictions) {
        Address funcAddr = parseAddress(pred, "function");
        Function func = getFunctionAt(funcAddr);
        // Create struct types predicted by the model
        for (JsonElement typeDef : pred.getAsJsonObject().get("types")) {
            DataType dt = parseDataType(typeDef, dtm);
            dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
        }
        // Apply variable types
        for (JsonElement varPred : pred.getAsJsonObject().get("variables")) {
            applyVariableType(func, varPred, dtm);
        }
    }
} finally {
    dtm.endTransaction(txId, true);
}
```

**Step 4: Validate with re-decompilation**
```java
// Re-decompile with applied types to verify output quality
ifc.setSimplificationStyle("decompile");
DecompileResults refined = ifc.decompileFunction(func, 30, monitor);
String improvedC = refined.getDecompiledFunction().getC();
```

### 6.6 Existing Plugin Ecosystem

**DAILA** -- Decompiler Artificially Intelligent Language Assistant (mahaloz)
A decompiler-agnostic plugin providing a unified interface for AI systems (GPT-4, Claude, local models like VarBERT) across Ghidra, IDA, and Binary Ninja. Supports variable renaming, function explanation, and vulnerability identification. Runs via PyGhidra and communicates with backends through a server architecture. Featured in the NDSS 2026 study on human-LLM teaming in reverse engineering.

**GhidrAssist** -- LLM extension for Ghidra (jtang613)
Enables AI-assisted reverse engineering directly within Ghidra, providing context-aware analysis using decompiler output and program state.

---

## 7. RETYPD Ghidra Plugin Architecture

### 7.1 Plugin Overview

The RETYPD Ghidra plugin (`retypd-ghidra-plugin` by GrammaTech) brings constraint-based polymorphic type inference to Ghidra. It implements a two-component architecture with a Java frontend for constraint extraction and a Python backend for constraint solving.

### 7.2 Architecture

**Frontend (Java, ~77% of codebase):**
The `GhidraRetypd` Java component operates within Ghidra's scripting environment. It:
- Iterates over functions in the current program
- Accesses each function's high-level P-Code via the `DecompInterface`
- Extracts subtyping constraints from P-Code operations (e.g., if a value flows from variable `x` into variable `y`, this generates the constraint `x <= y`)
- Serializes the complete constraint set as JSON, including per-function constraints and a call graph section

**Backend (Python, ~17% of codebase):**
The `ghidra_retypd_provider` Python package:
- Reads the JSON-serialized constraints
- Runs the core RETYPD inference algorithm (the `retypd` Python package)
- Applies lattice-based solving with push-down automata for recursive types
- Writes inferred types back to disk as JSON

**Activation:** Users execute `Retypd.java` via Ghidra's Script Manager, which orchestrates the full pipeline.

### 7.3 Constraint Generation Frontend

The constraint generation follows RETYPD's subtyping framework:

1. **Dataflow Analysis**: For each high-level P-Code operation, the plugin generates constraints based on how data flows between varnodes. An `INT_ADD` with a pointer input constrains the result to also be a pointer type; a `CALL` to a known function constrains actual parameters to be subtypes of formal parameter types.

2. **Covariance/Contravariance**: Pointer loads are covariant (the pointed-to type flows in the same direction), while stores are contravariant (the stored type flows in the opposite direction). This precision is RETYPD's key innovation over unification-based approaches like Ghidra's built-in type inference.

3. **Inter-procedural Propagation**: Constraints are generated per-function and then connected through the call graph. The JSON format includes a `callgraph` section that links caller constraints to callee constraints.

4. **Known Signature Seeding**: Constraints from known function signatures (libc, system calls) act as "seeds" that anchor the type lattice and propagate through the constraint graph.

### 7.4 Performance and Trade-offs

**Strengths:**
- More precise than Ghidra's built-in unification-based type inference, especially for pointer-heavy code
- Handles polymorphic functions (e.g., `memcpy`, `malloc`) without over-constraining callers
- No recompilation of Ghidra required -- runs as a script

**Limitations:**
- The Java-to-JSON-to-Python round-trip adds overhead (disk I/O + Python startup)
- Slower than Ghidra's built-in inference for large binaries (BinSub achieves 63x speedup with similar precision)
- Limited to the type lattice expressible in RETYPD's constraint language (no union types, limited array support)

**SURE 2025 Results:**
In the SURE 2025 benchmark, Ghidra-Retypd achieved only 4.50% accuracy on -O0 binaries and 3.74% on -O2 binaries, significantly below Ghidra's built-in inference (which benefits from heuristics tuned to common patterns). This suggests the constraint-based approach, while theoretically more sound, needs better integration with Ghidra's existing type information and heuristics to be practical.

### 7.5 BTIGhidra (Trail of Bits Alternative)

Trail of Bits released **BTIGhidra**, a Ghidra extension implementing an improved variant of RETYPD-style constraint solving:

- **Inter-procedural analysis**: Independently generates subtyping constraints for each strongly connected component (SCC) of functions in the call graph, enabling efficient modular solving
- **Value-set analysis integration**: Uses flow-sensitive data-flow analyses from FKIE-CAD's `cwe_checker` to track value propagation, providing more precise constraints than P-Code analysis alone
- **Type sketches**: Represents recursively constrained types as directed graphs with labeled edges, supporting lattice join/meet operations
- **Per-call-site type variables**: Generates a type variable per call site rather than per function, preventing unsound over-generalization of polymorphic types
- **BTIEval**: Ships with an evaluation utility that compares recovered types against DWARF debug information, aggregating soundness and precision metrics plus timing data

BTIGhidra's algorithm was developed with permission from GrammaTech under the GPLv3 terms of the original RETYPD implementation.

---

## 8. Evaluation Framework

### 8.1 SURE 2025 Benchmark for Type Inference

The **"Benchmarking Binary Type Inference Techniques in Decompilers"** paper (SURE 2025, Soni) provides the first dedicated benchmark suite for evaluating type inference quality across decompilers.

**Benchmark Design:**
- Targets x86-64 ELF binaries compiled from C programs (the most common target for decompilers)
- Compiles every program at both `-O0` and `-O2` to evaluate inference across optimization levels
- Uses DWARF debug information as ground truth for type comparison
- Two evaluation modes: overall binary type inference evaluation and type-specific analysis (scoring each decompiler on individual type categories)

**Tools Evaluated:**
| Tool | Type Inference Method | -O0 Accuracy | -O2 Accuracy |
|------|----------------------|:---:|:---:|
| Hex-Rays (IDA Pro) | Proprietary heuristic + propagation | Best | 17.08% |
| Ghidra | Unification-based propagation | Good | 14.95% |
| Binary Ninja | Propagation + heuristic | Good | 14.77% |
| angr | RETYPD-variant (improved) | 2.50% | 2.67% |
| Ghidra-Retypd | Original RETYPD algorithm | 4.50% | 3.74% |

**Key Findings:**
- Unification-based approaches (Ghidra, Hex-Rays, Binary Ninja) significantly outperform pure constraint-based approaches (angr, Retypd) on this benchmark, likely because they incorporate domain-specific heuristics and known-signature databases
- Array detection is a weak point across all tools: Hex-Rays and Ghidra identify the most arrays (~43% at -O0, ~36% at -O2) but most have incorrect lengths despite correct base addresses
- Optimization level significantly impacts all tools, with -O2 consistently reducing accuracy
- The benchmark is extensible, allowing researchers to add support for additional decompilers

### 8.2 Metrics for Type Recovery Quality

Beyond exact-match accuracy, meaningful type recovery evaluation requires multi-dimensional metrics:

**Structural Metrics:**
- **Type Soundness**: Does the inferred type capture a *superset* of the actual value's behaviors? A sound type never causes a false-negative (misses valid behavior). BTIEval specifically measures this.
- **Type Precision**: How tight is the inferred type around actual behavior? `int` is sound for a `uint16_t` but imprecise. Measured as the ratio of inferred type's value range to actual value range.
- **Structural Similarity**: For compound types (structs), measure field count accuracy, field offset accuracy, and field type accuracy independently. A struct with 3/4 correct fields at correct offsets is more useful than one with 0/4.

**Semantic Metrics:**
- **Behavioral Equivalence**: Does code using the inferred types behave identically to code using original types? This subsumes soundness and is the gold standard, but is expensive to evaluate (requires recompilation + test execution).
- **Downstream Task Impact**: Measure how inferred types affect practical RE tasks -- vulnerability detection rate, time-to-understanding in analyst studies, false positive rate in static analysis. TRex introduced "behavior-capturing types" as a metric that targets this.

**Practical Metrics:**
- **Coverage**: What fraction of variables/parameters receive non-trivial type assignments? A tool that types 30% of variables precisely may be more useful than one that types 90% as `undefined`.
- **Consistency**: Are inferred types consistent across call sites? If function `f(x)` is called in 10 places, do all callers agree on the type of `x`?
- **Recovery Rate by Type Category**: Break down accuracy by type complexity -- primitives, pointers, single-level structs, nested structs, function pointers, arrays, enums. Most tools do well on primitives but struggle with complex types.

### 8.3 Practical A/B Evaluation Patterns for RE Tool Research

**Pattern 1: Ground-truth Comparison (DWARF-based)**
1. Compile a corpus of C programs with `-g` (debug info) at multiple optimization levels
2. Strip the binaries to create analysis targets
3. Run type inference tools on stripped binaries
4. Compare inferred types against DWARF ground truth using structural similarity metrics
5. This is the approach used by SURE 2025 and BTIEval

**Pattern 2: Recompilation Validation**
1. Decompile a binary with baseline and experimental type recovery
2. Attempt to recompile both outputs
3. Run the original test suite against recompiled binaries
4. Measure: recompile success rate, test pass rate, ASAN error rate (as in DecLLM)

**Pattern 3: Analyst Productivity Study**
1. Present analysts with decompiled code using baseline types vs. enhanced types
2. Measure time-to-answer for specific RE questions (e.g., "What does this function do?", "Is this buffer overflow exploitable?")
3. Measure answer accuracy
4. This is expensive but provides the most practically relevant signal

**Pattern 4: Differential A/B Testing**
1. Run two type recovery approaches on the same binary corpus
2. For functions where they disagree, manually audit a random sample to determine which is more accurate
3. Extrapolate quality differences from the sample
4. Useful for comparing incremental improvements (e.g., "Does adding neighbor context improve IDIOMS?")

**Pattern 5: Automated Semantic Equivalence**
1. Generate random inputs for decompiled functions
2. Execute both the original binary (via emulation) and the recompiled decompiler output on the same inputs
3. Compare outputs without requiring a ground-truth test suite
4. Scales to large corpora but may miss edge cases

### 8.4 Setting Up Evaluation Infrastructure

**Ghidra Headless Evaluation Pipeline:**
```bash
# 1. Import and analyze binary
analyzeHeadless /tmp/eval_project Eval -import target_binary

# 2. Run baseline type export
analyzeHeadless /tmp/eval_project Eval -process target_binary \
    -postScript ExportTypes.java baseline_types.json

# 3. Run experimental type inference plugin
analyzeHeadless /tmp/eval_project Eval -process target_binary \
    -postScript RunRetypd.java -postScript ExportTypes.java experimental_types.json

# 4. Compare against DWARF ground truth
python compare_types.py --ground-truth dwarf_types.json \
    --baseline baseline_types.json \
    --experimental experimental_types.json \
    --output results.csv
```

**Corpus Construction:**
- Use the Decompile-Bench CTF framework or DIRT dataset pipelines to generate binary-source pairs at scale
- Compile with multiple compilers (GCC, Clang) and optimization levels (-O0, -O1, -O2, -O3, -Os)
- Include both simple programs (coreutils-style) and complex ones (with nested structs, function pointers, polymorphic code)
- The SURE 2025 benchmark specifically chose C programs with x86-64 ELF targets, which is a reasonable starting point but should be extended to other architectures for comprehensive evaluation

---

## 9. Key Takeaways for Ghidra Integration

### 9.1 Immediate Opportunities

1. **IDIOMS-style joint prediction as a Ghidra plugin**: Use Ghidra's normalized P-Code or decompiler output as input to a fine-tuned LLM that jointly predicts refined code + UDTs. The neighbor-context window approach (callers/callees) maps naturally to Ghidra's cross-reference database.

2. **DIRTY/ReSym-style post-processing**: Augment Ghidra's decompiler output with learned variable names and types as a lightweight post-processing step. DIRTY's approach is well-suited to integration since it operates on decompiler output directly.

3. **LLM4Decompile-Ref integration**: The refinement approach specifically targets Ghidra output and achieves 16.2% improvement. This could be packaged as a "refine with LLM" action in a Ghidra plugin.

4. **BinSub/RETYPD for improved type inference**: BinSub's 63x speedup over RETYPD makes constraint-based polymorphic type inference practical for interactive use in Ghidra. RETYPD already has a Ghidra plugin.

### 9.2 Architecture Considerations

5. **Leverage P-Code as universal IR**: Ghidra's multi-architecture P-Code is an ideal input representation for neural models. The "normalize" analysis style provides clean, simplified P-Code without type assumptions -- perfect for models that should infer types from scratch.

6. **Multi-level representation access**: Ghidra exposes raw P-Code, normalized P-Code, and decompiled C -- all usable as different input/output modalities for ML models. This enables approaches like SK2Decompile's two-phase (skeleton then skin) methodology.

7. **DecompInterface API for batch processing**: Ghidra's headless analyzer + DecompInterface enables processing entire binaries programmatically -- essential for training data generation (a la Decompile-Bench) and batch inference.

### 9.3 Benchmark and Evaluation

8. **Training data generation at scale**: Ghidra can be used headlessly to generate decompiler output for large corpora. Decompile-Bench's CTF framework and the DIRT dataset both demonstrate pipelines that could be replicated/extended with Ghidra.

9. **Evaluation beyond re-executability**: For a Ghidra plugin, evaluation should emphasize analyst productivity (time-to-understanding, accuracy of recovered types for vulnerability analysis) rather than just re-executability metrics.

10. **Type recovery benchmarking**: The SURE 2025 benchmark already includes Ghidra. Any type recovery plugin should be evaluated against this benchmark and TRex's results (which outperform Ghidra on 124/125 binaries).

### 9.4 Strategic Direction

The field is converging on a pattern where **traditional decompilers provide the structural backbone** (control flow, basic type inference, calling conventions) and **ML models provide the semantic enrichment** (meaningful names, complex types, code simplification). Ghidra's open architecture makes it the ideal platform for this integration:

- Its P-Code IR is a cleaner input signal than raw assembly for ML models
- Its plugin API allows seamless integration of ML predictions back into the analysis database
- Its open-source nature enables training data pipelines at scale
- The active research community is already building Ghidra-specific tools (RETYPD plugin, DAILA, DeGPT)

The most impactful near-term integration would combine **constraint-based type inference** (BinSub/RETYPD for soundness) with **neural type prediction** (IDIOMS/DIRTY for names and UDTs) in a hybrid pipeline, using Ghidra's normalized P-Code as the shared representation layer.

---

## References

### Neural/LLM Decompilation
- Nova: Jiang et al., ICLR 2025 -- [arXiv](https://arxiv.org/abs/2311.13721)
- SLaDe: Armengol-Estape et al., CGO 2024 -- [arXiv](https://arxiv.org/abs/2305.12520)
- BTC: Hosseini & Dolan-Gavitt, NDSS BAR 2022 -- [arXiv](https://arxiv.org/abs/2212.08950)
- IDIOMS: Dramko et al., 2025 -- [arXiv](https://arxiv.org/abs/2502.04536)
- LLM4Decompile: Tan et al., EMNLP 2024 -- [arXiv](https://arxiv.org/abs/2403.05286)
- DeGPT: Hu et al., NDSS 2024 -- [Paper](https://www.ndss-symposium.org/ndss-paper/degpt-optimizing-decompiler-output-with-llm/)
- DecLLM: Wang et al., ISSTA 2025 -- [ACM](https://dl.acm.org/doi/10.1145/3728958)
- SK2Decompile: Tan et al., 2025 -- [arXiv](https://arxiv.org/abs/2509.22114)

### Benchmarks
- Decompile-Bench: Tan et al., NeurIPS 2025 -- [arXiv](https://arxiv.org/abs/2505.12668)
- ExeBench: Armengol-Estape et al. -- [ResearchGate](https://www.researchgate.net/publication/361263162)
- DecompileBench: 2025 -- [arXiv](https://arxiv.org/abs/2505.11340)
- BinMetric: IJCAI 2025 -- [Paper](https://www.ijcai.org/proceedings/2025/0858.pdf)
- Benchmarking Binary Type Inference: Soni, SURE 2025 -- [Paper](https://sure-workshop.org/accepted-papers/2025/sure25-8.pdf)

### Type Recovery
- StateFormer: Pei et al., ESEC/FSE 2021 -- [Paper](https://www.cs.columbia.edu/~suman/docs/stateformer.pdf)
- DIRTY: Chen et al., USENIX Security 2022 -- [Paper](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-qibin)
- SnowWhite: Lehmann et al., PLDI 2022 -- [ACM](https://dl.acm.org/doi/10.1145/3519939.3523449)
- RETYPD: GrammaTech -- [GitHub](https://github.com/GrammaTech/retypd)
- OSPREY: Zhang et al., IEEE S&P 2021 -- [Paper](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- BinSub: Smith, SAS 2024 -- [arXiv](https://arxiv.org/abs/2409.01841)
- TRex: Bosamiya et al., USENIX Security 2025 -- [Paper](https://www.andrew.cmu.edu/user/bparno/papers/trex.pdf)
- HyRES: ACM TOSEM 2025 -- [ACM](https://dl.acm.org/doi/10.1145/3736719)

### Ghidra Internals
- NCC Group P-Code Internals -- [Blog](https://www.nccgroup.com/research-blog/earlyremoval-in-the-conservatory-with-the-wrench-exploring-ghidra-s-decompiler-internals-to-make-automatic-p-code-analysis-scripts/)
- Ghidra Decompiler Analysis Engine -- [Docs](https://lemuellew.github.io/Ghidra-Decompiler-Analysis-Engine-Document/)
- Ghidra DecompInterface API -- [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html)
- Ghidra coreaction.cc (Action/Rule registration) -- [Source](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc)
- Ghidra ruleaction.cc (Rule implementations) -- [Source](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc)
- Adding Simplification Rules Discussion -- [GitHub](https://github.com/NationalSecurityAgency/ghidra/discussions/5433)
- Ghidra HighFunction API -- [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html)
- Ghidra HighVariable API -- [Javadoc](http://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighVariable.html)
- Ghidra HighSymbol API -- [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighSymbol.html)
- Ghidra DataTypeManager API -- [Javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html)
- GhidraSnippets (Python API examples) -- [GitHub](https://github.com/HackOvert/GhidraSnippets)
- Ghidra Decompiler Class List -- [Docs](https://grant-h.github.io/docs/ghidra/decompiler/annotated.html)

### Ghidra Plugins for Type Recovery
- RETYPD Ghidra Plugin -- [GitHub](https://github.com/GrammaTech/retypd-ghidra-plugin)
- BTIGhidra (Trail of Bits) -- [GitHub](https://github.com/trailofbits/BTIGhidra)
- Binary Type Inference in Ghidra (Trail of Bits blog) -- [Blog](https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/)
- DAILA (AI decompiler assistant) -- [GitHub](https://github.com/mahaloz/DAILA)
- GhidrAssist (LLM extension) -- [GitHub](https://github.com/jtang613/GhidrAssist)

### Surveys
- "Decompiling 2024: A Year of Resurgence" -- [mahaloz.re](https://mahaloz.re/dec-progress-2024)
- Decompilation Wiki -- [GitHub](https://github.com/mahaloz/decompilation-wiki)
- Type Inference from Hidden Semantics -- [Binarly](https://www.binarly.io/blog/type-inference-for-decompiled-code-from-hidden-semantics-to-structured-insights)
