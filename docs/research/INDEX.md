# Research & Documentation Index

This index consolidates the deep research conducted on Ghidra's capabilities, the reverse engineering landscape, and a roadmap for building next-generation RE tooling. All documents are rooted in the foundational [deep research report](../deep-research-report.md).

Verification note (as of 2026-02-19): time-sensitive claims (pricing, release status, plugin maintenance) should be treated as point-in-time statements unless otherwise dated. Track verification in [`../claims-ledger.md`](../claims-ledger.md) and canonical references in [`../sources.md`](../sources.md).
Performance numbers and model/tool comparisons in this index are reported from cited papers/blogs and were not independently reproduced in this repository.

---

## Document Map

| Document | Summary |
|---|---|
| [Deep Research Report](../deep-research-report.md) | Foundational document: tool comparison, gap analysis, prioritized roadmap, architecture recommendations |
| [Binary Similarity & Semantic Search](binary-similarity-semantic-search.md) | 10+ BFSD models (Gemini through VexIR2Vec), Lumina/WARP/FID comparison, BSim internals deep dive (feature vectors, DB backends, Program Correlator), REFuSe-Bench/BinBench/BinCodex benchmarks, Ghidra API integration patterns, emerging 2025-2026 approaches |
| [Decompilation & Type Recovery](decompilation-type-recovery.md) | Neural decompilation (Nova, SLaDe, IDIOMS, LLM4Decompile, SK2Decompile), type recovery (StateFormer, DIRTY, TRex, BinSub, RETYPD), Ghidra decompiler action system, plugin integration patterns for type recovery, RETYPD/BTIGhidra plugin architectures, evaluation framework (SURE 2025) |
| [Symbolic Execution, Fuzzing & Dynamic Analysis](symbolic-execution-fuzzing-dynamic.md) | SymCC/SymQEMU/SymFusion, angr/BINSEC/Manticore/KLEE, AFL++ binary modes, harness generation (HarnessAgent, PromeFuzz), emulation (Qiling/Unicorn), dynamic-static fusion patterns |
| [Diffing, Matching & Deobfuscation](diffing-matching-deobfuscation.md) | BinDiff/Diaphora/Version Tracking/ghidriff, FLIRT/WARP/FID, BinExport/GTIRB formats, patch diffing workflows, deobfuscation (CFF, VM-based, MBA simplification, gooMBA, Syntia) |
| [Ecosystem, Plugins & Firmware Tooling](ecosystem-plugins-firmware.md) | PyGhidra/Ghidrathon/Bridge comparison, 8+ LLM/MCP plugins, collaboration tools (IDArling, BN Enterprise, Ghidra Server), firmware pipeline (Binwalk, FirmAE, EMBA, FACT), safety patterns |
| [Ghidra Internals & Architecture](ghidra-internals-architecture.md) | P-code IR (75 ops), SLEIGH language, C++ decompiler engine, Trace RMI protocol, extension points, DB framework, Auto Analysis Manager scheduling, DataTypeManager API, program merge framework, p-code emulator JIT, headless CI/CD patterns |
| [Vulnerability Discovery & Exploit Development](vulnerability-discovery-exploit-dev.md) | Taint analysis (PANDA/Triton/angr/DFSan), automatic exploit generation (rex/Mayhem), ROP chain generation (ROPgadget/angrop/ROPium), binary patching (patcherex/e9patch), vulnerability pattern detection (BinAbsInspector/Joern/CodeQL), PoC generation workflows |
| [Malware Analysis & Anti-Analysis](malware-analysis-anti-analysis.md) | Automated unpacking (Unipacker/Qiling), anti-debug/anti-VM detection and bypass (ScyllaHide/TitanHide), behavioral analysis (API Monitor/Frida/ETW), malware classification and YARA, modern sandboxes (CAPE/ANY.RUN/Joe Sandbox), Ghidra malware tooling (capa/FLOSS), threat intelligence integration (STIX/MITRE ATT&CK) |
| [Binary Rewriting & Transformation](binary-rewriting-transformation.md) | Static rewriting (GTIRB/DDisasm, RetroWrite, e9patch, McSema/Remill, BOLT), dynamic instrumentation (DynamoRIO, Intel Pin, Frida, Valgrind), binary hardening and debloating, coverage instrumentation, Ghidra patching capabilities, integration patterns |
| [AI/LLM-Assisted Reverse Engineering](ai-assisted-reverse-engineering.md) | Prompt engineering for RE, fine-tuning strategies (IDIOMS/LLM4Decompile pipelines, LoRA), agent architectures (ReAct/tool-use/multi-agent), MCP protocol deep dive (6 Ghidra MCP servers compared), evaluation methodology (BinMetric), receipts/provenance architecture, safety (sandboxing, prompt injection, policy modes), open model comparison |

---

## Roadmap Cross-Reference

Maps each roadmap item from the deep research report to the research documents that provide depth.

| Roadmap Item | Phase | Primary Research Docs | Key Findings |
|---|---|---|---|
| **Receipts-first automation** | MVP | [Ecosystem](ecosystem-plugins-firmware.md), [Ghidra Internals](ghidra-internals-architecture.md), [AI-Assisted RE](ai-assisted-reverse-engineering.md) | No existing plugin provides structured audit trails; GhidrAssist RLHF is partial exception. Receipts architecture designed: hash-chain audit trails, confidence scoring, rollback via Ghidra transactions. Analyzer + Plugin interfaces are the integration surface. |
| **Semantic search / find similar functions** | MVP | [Binary Similarity](binary-similarity-semantic-search.md), [Ghidra Internals](ghidra-internals-architecture.md) | VexIR2Vec is best fit for p-code architecture; BSim internals documented (GenerateSignatures pipeline, LSH indexing, 3 DB backends); layered FID → embeddings → LLM is the right design. Emerging: EBM, KEENHash, multi-modal embeddings. |
| **Modern Python story** | MVP | [Ecosystem](ecosystem-plugins-firmware.md), [Ghidra Internals](ghidra-internals-architecture.md) | PyGhidra (bundled, JPype) is canonical; Ghidrathon (Jep) for tighter in-process coupling. Headless CI/CD patterns documented with PyGhidra integration. |
| **Corpus-scale knowledge base** | Mid-term | [Binary Similarity](binary-similarity-semantic-search.md), [Diffing](diffing-matching-deobfuscation.md), [Malware Analysis](malware-analysis-anti-analysis.md) | BSim + PostgreSQL already provides corpus-scale search; needs neural embedding backend and Lumina-style annotation sharing. BSim for malware family correlation documented. |
| **Diffing uplift** | Mid-term | [Diffing](diffing-matching-deobfuscation.md), [Ghidra Internals](ghidra-internals-architecture.md), [Vuln Discovery](vulnerability-discovery-exploit-dev.md) | BSim Program Correlator + PatchDiff Correlator + ghidriff automation; BinExport interop via existing plugin; narrative reports via markdown output. PatchDiff-AI multi-agent pipeline for automated Patch Tuesday analysis. |
| **Type lifecycle UX** | Mid-term | [Decompilation & Type Recovery](decompilation-type-recovery.md), [Ghidra Internals](ghidra-internals-architecture.md) | BinSub (63x speedup) and RETYPD for constraint-based inference; IDIOMS for joint neural prediction; DataTypeManager API deep dive (programmatic type creation, archives, conflict handling); SURE 2025 evaluation framework documented. |
| **Dynamic-static unification** | Long-term | [Symbolic Execution & Fuzzing](symbolic-execution-fuzzing-dynamic.md), [Ghidra Internals](ghidra-internals-architecture.md), [Vuln Discovery](vulnerability-discovery-exploit-dev.md) | Trace RMI protocol supports custom connectors; p-code emulator JIT documented; SymQEMU best binary-only concolic engine; taint analysis frameworks (PANDA/Triton/angr) provide dynamic evidence; 7 concrete fusion patterns. |
| **Safe ML/agent runtime** | Long-term | [AI-Assisted RE](ai-assisted-reverse-engineering.md), [Ecosystem](ecosystem-plugins-firmware.md) | 8+ MCP servers compared; 3 policy modes (offline/allow-listed/full cloud); sandboxing architecture; prompt injection from binary content documented; receipts/provenance system with hash-chain audit trails designed; open model evaluation for local deployment. |

---

## Key Tools & Projects Quick Reference

### RE Platforms

| Tool | Category | License | Notes |
|---|---|---|---|
| Ghidra | Disassembler/decompiler | Apache 2.0 | This repo. P-code IR, SLEIGH, headless, shared server |
| IDA Pro + Hex-Rays | Disassembler/decompiler | Commercial | De facto industry standard; Lumina, FLIRT, microcode API |
| Binary Ninja | Disassembler/decompiler | Commercial | LLIL/MLIL/HLIL, WARP, enterprise server |
| angr | Binary analysis framework | BSD | Python, symbolic execution, CFG recovery, VEX IR |
| radare2 / Rizin + Cutter | Disassembler/toolkit | LGPL/GPL | CLI-first, r2pipe scripting, FOSS |

### Binary Similarity & Matching

| Tool/Model | Type | Year | Key Feature |
|---|---|---|---|
| BSim (Ghidra) | P-code feature vectors | 2023 | Cross-architecture via p-code; PostgreSQL/H2/Elastic backend; LSH indexing |
| Lumina (IDA) | MD5 hash metadata | ~2018 | Public + private server; crowd-sourced; no semantic matching |
| WARP (Binary Ninja) | UUIDv5 function GUID | 2025 | Open format; enterprise private libraries; variant instruction normalization |
| Function ID (Ghidra) | Byte hash | — | Ships with Ghidra; .fidb databases |
| FLIRT (IDA) | Pattern signatures | ~1990s | Mature ecosystem; FLAIR tools for custom sigs |
| VexIR2Vec | IR-based embeddings | 2024 | Architecture-neutral via VEX IR; +40% cross-optimization |
| jTrans | Transformer | 2022 | Jump-aware encoding; BinaryCorp dataset; 62.5% R@1 |
| CRABS-former | Transformer | 2024 | Cross-architecture normalized assembly |
| BinaryAI | Transformer | 2024 | Binary-to-source SCA |
| EBM | LLM uptraining | NeurIPS 2025 | LLM-generated embeddings for binary similarity |
| KEENHash | Program-level similarity | ISSTA 2025 | Whole-program similarity via kernel hashing |

### Diffing & Deobfuscation

| Tool | Type | Status | Key Feature |
|---|---|---|---|
| BinDiff | Graph-based diffing | Open source (Apache 2.0) | Industry standard; IDA/BN/Ghidra plugins |
| BinExport | Protobuf export format | Open source | Cross-tool disassembly interchange |
| Diaphora | IDA diffing plugin | Open source | Decompiler-driven heuristics |
| ghidriff | Ghidra headless differ | Open source | Markdown output; BSim integration |
| GTIRB | Binary rewriting IR | Open source | GrammaTech; DDisasm + round-trip rewriting |
| gooMBA | MBA simplification | IDA 8.3+ built-in | Z3-verified; outperforms SiMBA |
| D-810 | Microcode deobfuscation | IDA plugin | CFF + MBA + dead code |
| Syntia | Program synthesis | Research | MCTS-guided; foundational for msynth/QSynth |

### Symbolic Execution & Fuzzing

| Tool | Type | Key Feature |
|---|---|---|
| SymCC | Compiler-based concolic | 3 orders of magnitude faster than KLEE; requires source |
| SymQEMU | Binary concolic | No source needed; QEMU-based; compilation-level performance |
| AFL++ | Coverage-guided fuzzer | QEMU/Frida/Unicorn binary modes; persistent mode |
| libFuzzer | In-process fuzzer | LLVM SanitizerCoverage; succeeded by Centipede |
| Manticore | Symbolic execution | Binaries + smart contracts; MUI for BN/Ghidra |
| BINSEC | Formal binary analysis | OCaml; SMT + abstract interpretation |
| Qiling | OS-level emulation | Unicorn-based; syscall/API hooking; multi-OS |
| Unicorn | CPU emulation | Lightweight; 15+ language bindings; JIT |

### Vulnerability Discovery & Exploit Development

| Tool | Type | Key Feature |
|---|---|---|
| PANDA taint2 | Whole-system taint analysis | QEMU-based; byte-level; full kernel+userland taint |
| Triton | DBA + symbolic + taint | Pin-based; combines taint + SE + SMT; Python API |
| angr rex | Automatic exploit generation | Crash → exploit for CGC/simple Linux binaries |
| ROPgadget | ROP chain generation | Multi-arch gadget finder; chain compiler |
| angrop | ROP automation (angr) | Integrated with angr symbolic execution |
| patcherex | Binary patching (angr) | Technique-based patching; CFG-aware insertion |
| e9patch | Static binary rewriting | Trampoline-based; no recompilation needed |
| BinAbsInspector | Vuln detection (Ghidra) | Abstract interpretation; buffer overflow/UAF/null-deref |
| Joern / ghidra2cpg | Code property graph | Inter-procedural vuln queries on decompiled code |

### Malware Analysis & Anti-Analysis

| Tool | Type | Key Feature |
|---|---|---|
| Unipacker | Generic unpacker | Unicorn-based emulation; UPX/ASPack/PEtite/FSG |
| PE-sieve | Memory scanner | Detects hollowed/injected modules in running processes |
| ScyllaHide | Anti-anti-debug | User-mode; hooks NtQueryInformationProcess, timing, etc. |
| CAPE Sandbox | Malware sandbox | Open source; config/payload extraction; YARA integration |
| ANY.RUN | Interactive sandbox | Commercial SaaS; real-time interaction during execution |
| capa | Capability detection | Rule-based; identifies malware behaviors; Ghidra integration |
| FLOSS | String extraction | Decodes obfuscated strings; stack string recovery |
| FakeNet-NG | Network simulation | Simulates DNS/HTTP/SMTP for behavioral analysis |

### Binary Rewriting & Instrumentation

| Tool | Type | Key Feature |
|---|---|---|
| GTIRB + DDisasm | Static rewriting | Round-trip: binary → IR → transform → reassemble |
| RetroWrite | Static rewriting | Position-independent; symbolization for ASLR binaries |
| e9patch | Static patching | Trampoline insertion; no disassembly needed |
| McSema / Remill | LLVM lifting | Binary → LLVM IR; enables compiler optimizations |
| BOLT (Meta) | Post-link optimization | Profile-guided binary rewriting; 5-15% speedup |
| DynamoRIO | Dynamic instrumentation | Tool creation API; drcov coverage; code cache |
| Intel Pin | Dynamic instrumentation | Pintool API; fine-grained instrumentation |
| Frida | Dynamic instrumentation | Stalker tracing; Interceptor hooks; GumJS scripting |

### Ghidra Python & LLM Integration

| Tool | Mechanism | Best For |
|---|---|---|
| PyGhidra | JPype (bundled) | Headless automation, CI/CD, Jupyter |
| Ghidrathon | Jep/JNI (Mandiant) | In-process UI scripting with full pip |
| Ghidra Bridge | RPC/TCP | External scripting without modifying install |
| GhidrAssist | LLM + ReAct agent | Most mature Ghidra LLM plugin; MCP companion |
| ReVa | MCP server in Ghidra | Focused tools for long-form RE |
| GhidrOllama | Ollama local API | Simple, offline LLM integration |
| ret-sync | Debugger↔disassembler | Real-time sync (WinDbg/GDB/LLDB ↔ IDA/Ghidra/BN) |

### Firmware Pipeline

| Tool | Purpose | Key Feature |
|---|---|---|
| Binwalk | Firmware extraction | Rust rewrite (v3.1); signature scanning + entropy |
| FirmAE | Firmware emulation | 79% success rate (vs 16% Firmadyne) |
| EMBA | End-to-end analysis | Extraction + static + dynamic + SBOM |
| FACT | Searchable analysis | Web UI; comparison across firmware library |

---

## Key Papers & Benchmarks Quick Reference

### Benchmarks

| Benchmark | Topic | Year/Venue | Description |
|---|---|---|---|
| Decompile-Bench | Decompilation | NeurIPS 2025 | 2M binary↔source function pairs; anti-leakage eval set |
| ExeBench | Decompilation | — | 5K C functions with IO examples; re-executability eval |
| REFuSe-Bench | Binary similarity | NeurIPS 2024 | Realistic BFSD eval; simple CNN matches complex models |
| BinBench | Binary functions | PeerJ CS 2023 | Multi-task benchmark (similarity, boundaries, compiler ID) |
| BinCodex | Binary similarity | May 2024 | Multi-level variation-controlled dataset |
| BinMetric | LLM binary analysis | IJCAI 2025 | 1K questions across 6 binary analysis tasks |
| Realtype | Type recovery | 2025 (IDIOMS) | Complex/realistic user-defined types |
| SURE 2025 | Type inference | 2025 | Benchmarks Ghidra/angr/BN type inference quality |
| Dec-Synergy | LLM-assisted RE | 2025 | 48-participant human study; 109 hours; analyst productivity |

### Key Papers

| Paper | Topic | Year/Venue | Key Contribution |
|---|---|---|---|
| Nova | Neural decompilation | ICLR 2025 | Hierarchical attention + contrastive learning for assembly |
| IDIOMS | Joint code+type prediction | 2025 (CMU) | Fine-tune LLM on Ghidra output for refined code + UDTs |
| LLM4Decompile | LLM decompilation | EMNLP 2024 | Largest open LLM series for decompilation (1.3B–33B) |
| SK2Decompile | Structure+naming decompilation | 2025 | Two-phase RL: structure recovery then identifier naming |
| SLaDe | Small model decompilation | CGO 2024 | 200M params; 6x more accurate than Ghidra |
| TRex | Deductive type recovery | USENIX Sec 2025 | Behavior-capturing types; outperforms Ghidra on 124/125 bins |
| BinSub | Algebraic type inference | SAS 2024 | 63x speedup over RETYPD; angr implementation |
| DIRTY | Variable name+type recovery | USENIX Sec 2022 | 66.4% name / 75.8% type recovery |
| StateFormer | Fine-grained type recovery | FSE 2021 | Transfer learning on program state |
| VexIR2Vec | Architecture-neutral embeddings | TOSEM 2024 | +40% cross-opt, +21% cross-arch via VEX IR |
| EBM | LLM binary embeddings | NeurIPS 2025 | LLM uptraining for binary function similarity |
| jTrans | Jump-aware similarity | ISSTA 2022 | 62.5% R@1 on BinaryCorp (2x prior SOTA) |
| SymCC | Compiler-based concolic | USENIX Sec 2020 | 3 orders of magnitude over KLEE |
| SymQEMU | Binary concolic | NDSS 2021 | Source-free compilation-based concolic |
| HarnessAgent | LLM harness generation | Dec 2025 | 87% C success rate; automated fuzz harness |
| PromeFuzz | Knowledge-driven fuzzing | CCS 2025 | 25 new vulns; 3 CVEs |
| Chosen-instruction attack | VM deobfuscation | NDSS 2022 | Breaks VMProtect/Themida via crafted inputs |
| Trace-informed synthesis | Deobfuscation | OOPSLA 2024 | Dynamic traces guide compositional synthesis |
| PatchDiff-AI | Automated patch analysis | Akamai 2024 | Multi-agent AI; >80% success on Patch Tuesday |
| Mayhem (ForAllSecure) | Automatic exploit generation | IEEE S&P 2012 | DARPA CGC winner; combined SE + fuzzing |
| ropbot | Automated ROP | NDSS 2026 | Fully automated ROP chain compilation |
| ReCopilot | LLM RE assistant | 2025 | CPT/SFT/DPO pipeline; hybrid agent architecture |
| D-LiFT | Quality-driven decompilation | 2025 | RL with quality feedback for decompilation refinement |
