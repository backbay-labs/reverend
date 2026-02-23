# RE Ecosystem: Plugins, Agents, and Firmware Tooling

> Research survey of the reverse engineering plugin ecosystem, LLM/agent integrations,
> collaboration tools, and firmware/IoT analysis pipelines.
>
> Verification note (as of 2026-02-19): plugin compatibility, maintenance status,
> and SaaS feature matrices in this document are high-churn and should be revalidated
> before production or procurement decisions.

---

## Ghidra Python Integration Paths

Ghidra retains a legacy Jython (Python 2.7) scripting path while also supporting modern
CPython workflows (PyGhidra and related integrations). Several projects bridge CPython 3
into Ghidra with different trade-offs.

### PyGhidra (formerly Pyhidra)

- **Repo**: https://github.com/NationalSecurityAgency/ghidra (under `Ghidra/Features/PyGhidra`)
- **Origin**: Developed by DC3 (DoD Cyber Crime Center) as "Pyhidra", adopted into upstream Ghidra.
- **Mechanism**: Uses **JPype** to embed the JVM in CPython (or attach CPython to the JVM). Java objects appear as native Python objects; no serialization boundary.
- **Capabilities**: Full access to the Ghidra API from CPython 3. Works in headless mode (launch analysis from a Python script) and as a Ghidra GUI plugin (interactive REPL inside Ghidra). Supports `pip`-installed packages.
- **Status**: As of 2026-02-19, PyGhidra is included in modern Ghidra releases. Exact package/version mappings should be rechecked against current release notes before publication.
- **Best for**: Headless automation pipelines, Jupyter notebook analysis, CI/CD integration.

### Ghidrathon (Mandiant/FLARE)

- **Repo**: https://github.com/mandiant/Ghidrathon
- **Mechanism**: Uses **Jep** (Java Embedded Python) via JNI to embed the CPython interpreter inside the JVM. The Python interpreter runs *within* Ghidra's Java process.
- **Capabilities**: Interactive interpreter window, Script Manager integration, headless mode. Supports Python virtual environments. Full access to `currentProgram`, `FlatAPI`, etc.
- **Trade-offs**: Tighter in-process coupling than JPype (lower overhead for Java/Python boundary crossings). Requires building a native Jep library for your platform. Designed by FLARE for malware analysis workflows with tools like capa, Unicorn Engine, and angr.
- **Best for**: UI-integrated scripting where you want in-process Python with full package ecosystem.

### Ghidra Bridge (justfoxing)

- **Repo**: https://github.com/justfoxing/ghidra_bridge
- **Mechanism**: RPC proxy built on `jfx_bridge`. A server script runs inside Ghidra's Jython environment; an external CPython 3 client sends commands over TCP. Objects are proxied transparently.
- **Trade-offs**: No native library compilation required. Higher latency per call due to RPC serialization. The bridge predates PyGhidra/Ghidrathon and was the first practical CPython 3 solution.
- **Status**: Usable for external scripting workflows, but maintenance activity should be revalidated against recent repository activity before relying on it for long-term plans.
- **Best for**: Quick external scripting without touching the Ghidra install; legacy setups.

### Native Jython

- **Version**: Python 2.7 (frozen; no Python 3 port planned).
- **Limitations**: Cannot install packages via pip. No numpy, no requests, no modern crypto libraries. String handling differences from Python 3. Limited community ecosystem.
- **Still useful for**: Simple built-in scripts that only use the Ghidra API and Java stdlib. Zero setup cost since it ships with Ghidra.

### Comparison Summary

| Approach | Python Ver | Mechanism | In-Process | Packages | Setup Effort |
|---|---|---|---|---|---|
| PyGhidra | 3.x | JPype | Yes | Full pip | Low (bundled) |
| Ghidrathon | 3.x | Jep/JNI | Yes | Full pip | Medium (native build) |
| Ghidra Bridge | 3.x | RPC/TCP | No | Full pip | Low |
| Jython | 2.7 | JVM | Yes | None | Zero |

---

## LLM/Agent Plugins for RE Tools

A rapidly growing category of plugins connects large language models to disassemblers and
decompilers. These range from simple "explain this function" scripts to full agentic frameworks.

Maintenance, feature counts, and API compatibility in this section are high-churn facts; treat these entries as point-in-time snapshots and verify before operational adoption.

### GhidrAssist

- **Repo**: https://github.com/jtang613/GhidrAssist
- **Author**: Jason Tang
- **Features**: Function explanation, interactive chat, variable/function renaming suggestions, RAG augmentation (add context documents), RLHF dataset generation for fine-tuning, and an **agentic mode** using the ReAct pattern for autonomous binary investigation.
- **Backend**: Any OpenAI-v1-compatible API (OpenAI, Ollama, LM Studio, text-generation-webui).
- **MCP companion**: GhidrAssistMCP (https://github.com/jtang613/GhidrAssistMCP) exposes 34 tools and 5 resources via MCP, enabling external AI assistants to drive Ghidra analysis.

### GhidrOllama

- **Repo**: https://github.com/lr-m/GhidrOllama
- **Approach**: Lightweight Ghidra Python script that calls Ollama's local API. Explains functions, suggests names, rewrites decompiled code with comments. Default keybinding: `Q`.
- **Advantage**: Simple single-script install; fully offline with local Ollama models.

### OGhidra

- **Repo**: https://github.com/llnl/OGhidra
- **Origin**: Lawrence Livermore National Laboratory.
- **Approach**: Bridges LLMs via Ollama with Ghidra for natural-language-driven binary analysis.

### ReVa (Reverse Engineering Assistant)

- **Repo**: https://github.com/cyberkaida/reverse-engineering-assistant
- **Approach**: MCP server running inside Ghidra (SSE transport, port 8080). Provides many small, focused tools to the LLM rather than dumping entire decompilation. Focuses on limiting context rot for long-form RE tasks.
- **Modes**: Assistant mode (GUI) and headless mode (CI/CD pipelines).
- **Requires**: Ghidra 11.3+.

### Gepetto (IDA Pro)

- **Repo**: https://github.com/JusticeRage/Gepetto
- **Features**: Explain Function (Ctrl+Alt+G), Add Code Comments (Ctrl+Alt+K), Suggest Variable Names (Ctrl+Alt+R).
- **Backends**: OpenAI, Gemini, Ollama, Groq, Azure OpenAI, LM Studio, Together, DeepSeek, LLaMA, Mixtral.
- **Caveat**: General-purpose LLMs may get things wrong; always verify.

### ida_copilot

- **Repo**: https://github.com/DearVa/ida_copilot
- **Approach**: LangChain-based agent that autonomously analyzes decompiled code in IDA. The agent decides next actions based on context, interacting with IDA through Python APIs. Features include automatic code analysis, AI-powered function renaming, and exploit generation.

### IDA-Assistant

- **Repo**: https://github.com/stuxnet147/IDA-Assistant
- **Approach**: Uses Anthropic Claude models with an interactive chat interface inside IDA Pro.

### BinAssist (Binary Ninja)

- **Repo**: https://github.com/jtang613/BinAssist
- **Author**: Jason Tang (same author as GhidrAssist).
- **Architecture**: Two-part system: BinAssist plugin (UI with Explain/Query/Actions tabs) and BinAssistMCP server (36 tools, 8 resources, 7 prompts via MCP).
- **Competitor**: Binary Ninja's official **Sidekick** (https://sidekick.binary.ninja/) is a managed AI service integrated into BN. BinAssist is open and supports any compatible LLM.

### Binary Ninja Sidekick

- **URL**: https://sidekick.binary.ninja/
- **Nature**: Official, commercial AI assistant from Vector 35. Deeply integrated with BN's IL and type system. Not open-source.

### MCP Bridges for RE Tools

The Model Context Protocol (Anthropic, Dec 2024) has become the dominant integration pattern:

| Project | Tool | Notes |
|---|---|---|
| GhidraMCP (LaurieWired) | Ghidra | Java plugin + Python MCP server |
| GhidrAssistMCP | Ghidra | 34 tools, action-based API |
| GhidraMCP (13bm) | Ghidra | 69 tools via active socket |
| GhydraMCP (Starsong) | Ghidra | HATEOAS REST API + MCP bridge, multi-instance |
| ReVa | Ghidra | SSE transport, headless support |
| ida-pro-mcp (mrexodia) | IDA Pro | AI-powered RE assistant bridge |
| BinAssistMCP | Binary Ninja | 36 tools, multi-binary sessions |
| binary_ninja_mcp (fosdickio) | Binary Ninja | General MCP server for BN |

### Safety Concerns

- **Data exfiltration**: Sending decompiled code to cloud LLM APIs may leak proprietary binaries, classified firmware, or client IP. Offline/local models (Ollama, LM Studio) mitigate this.
- **Non-determinism**: LLM outputs vary across runs. Renamed variables or added comments may be inconsistent or wrong. No guarantee of correctness.
- **Audit trails**: Most plugins do not log what changes the LLM suggested vs. what the analyst accepted. GhidrAssist's RLHF dataset generation is a partial exception.
- **Prompt injection**: Malicious strings in binaries (e.g., crafted symbol names) could manipulate LLM behavior if passed unsanitized.

---

## Collaboration Tools

### IDArling (IDA Pro)

- **Repo**: https://github.com/IDArlingTeam/IDArling
- **Model**: Real-time synchronization of IDA database changes across multiple connected IDA instances. Changes propagate instantly.
- **Architecture**: Integrated server (inside IDA) or standalone server (command-line). Uses PyQt5.
- **Status**: Original project is no longer actively maintained. IDA has announced official collaborative RE support. Several community forks exist (fidgetingbits, hotwinter/IDArl1ng).

### Binary Ninja Enterprise

- **URL**: https://binary.ninja/enterprise/
- **Features**: Remote project management with push/pull of analysis snapshots, synced type archives (auto-sync every 30s, configurable), real-time chat per project file, conflict resolution, user/permission management at project and file level.
- **Type Archives**: Shared type definitions that sync automatically across team members via the enterprise server. Changes by the local user are sent immediately; remote changes are polled periodically.
- **Model**: Git-like snapshot commits with merge support. Most mature commercial collaboration solution in the RE space.

### Ghidra Shared Server

- **Documentation**: https://github.com/NationalSecurityAgency/ghidra (VersionControl/project_repository)
- **Model**: Check-out / check-in with versioning. Supports exclusive check-out (required for memory map or language changes). Non-conflicting changes merge automatically; conflicts require manual resolution by the last user checking in.
- **Limitations**:
  - No real-time sync (check-out/check-in workflow only).
  - Memory structure changes require exclusive access due to cascading impact.
  - Merge UI is functional but basic compared to modern VCS tools.
  - No built-in chat, review workflows, or provenance tracking.
  - Server setup requires manual configuration (svrAdmin, SSH keys).
- **Strengths**: Free, self-hosted, supports large teams at NSA scale. Adequate for serial workflows.

### What Modern RE Collaboration Would Look Like

Current tools are roughly where software development was before Git:
- **Review workflows**: PR-like review of annotation changes before merge (no tool supports this natively).
- **Provenance**: Who renamed this function, when, and why? Ghidra tracks versions but not fine-grained attribution.
- **Branching**: Exploratory analysis branches that can be merged or discarded (BN Enterprise comes closest).
- **Cross-tool sync**: Annotations made in Ghidra should be portable to BN or IDA (BinExport partially addresses this for structure, not annotations).
- **Async-first**: Most RE work is asynchronous; real-time sync is nice but not the primary need.

---

## Firmware/IoT Analysis Pipeline

### Binwalk

- **Repo**: https://github.com/ReFirmLabs/binwalk
- **Version**: 3.1.0 (rewritten in Rust for performance and reduced false positives).
- **Purpose**: Scan firmware images for known file signatures, extract embedded filesystems (SquashFS, JFFS2, UBI, FAT, NTFS, APFS), compressed archives, and cryptographic keys.
- **Features**: Signature scanning (libmagic), entropy analysis (detect packed/encrypted regions), recursive extraction, plugin system for custom decryption/unpacking.
- **Role in pipeline**: Usually the first tool applied to a raw firmware image. Produces extracted filesystem trees for further analysis.

### Firmadyne

- **Repo**: https://github.com/firmadyne/firmadyne
- **Purpose**: Automated emulation and dynamic analysis of Linux-based embedded firmware at scale.
- **Components**: Modified kernels (MIPS v2.6, ARM v4.1/v3.10) for instrumentation, userspace NVRAM library, filesystem extractor, scraper for 42+ vendor download sites.
- **Scale**: Evaluated on 23,035 firmware images; extracted 9,486; found 846/1,971 (43%) vulnerable to at least one of 74 exploits.
- **Limitations**: Only 16.28% emulation success rate on router/camera firmware. NVRAM emulation and hardware peripheral stubs are the main failure points.

### FirmAE

- **Repo**: https://github.com/pr0v3rbs/FirmAE
- **Paper**: ACSAC 2020 - "Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis"
- **Improvement over Firmadyne**: Five arbitration techniques increase emulation success from 16.28% to **79.36%** (4.8x improvement) on 1,124 router/camera images from top 8 vendors.
- **Results**: Checked 320 known vulnerabilities (306 more than Firmadyne) and found 12 new 0-days in 23 devices.

### EMBA

- **Repo**: https://github.com/e-m-b-a/emba
- **Purpose**: End-to-end firmware security analyzer covering extraction, static analysis, dynamic analysis (user-mode + system emulation), SBOM generation, and vulnerability aggregation.
- **Extraction**: Uses both unblob and binwalk for maximum coverage.
- **Static analysis**: Checks for insecure binaries, outdated components, vulnerable scripts, hardcoded passwords.
- **Dynamic analysis**: Boots firmware in emulation to observe runtime behavior.
- **SBOM**: Automatically generates Software Bill of Materials and maps components to known CVEs. Critical for 2024+ regulatory compliance.
- **Output**: Command-line tool with web-based HTML report for browsing results.

### FACT (Firmware Analysis and Comparison Tool)

- **Repo**: https://github.com/fkie-cad/FACT_core
- **Origin**: Fraunhofer FKIE (German government research).
- **Purpose**: Automated firmware analysis with browsable, searchable, and comparable results.
- **Architecture**: Web-based UI (HTML/JS/CSS) + REST API with SwaggerUI. Stores all extracted files and analysis results in a searchable database.
- **Features**: Byte pattern search across all unpacked files, comparison of firmware versions, growing set of analysis plugins.
- **Differentiation**: Designed for organizational use where multiple analysts need to search and compare firmware across a library of images.

### Pipeline Integration with Interactive RE

The typical firmware analysis pipeline flows:

```
Raw firmware image
  -> Binwalk/unblob (extract filesystem)
  -> EMBA/FACT (automated vulnerability scan + SBOM)
  -> Firmadyne/FirmAE (emulate and test dynamically)
  -> Ghidra/IDA/BN (interactive RE of specific binaries)
```

Integration points:
- EMBA and FACT can identify specific binaries of interest (e.g., vulnerable web servers, custom daemons) that warrant manual RE.
- Extracted ELF binaries from Binwalk output can be loaded directly into Ghidra.
- FirmAE's emulated environment can be attached to with GDB, which Ghidra's debugger can connect to for live analysis.
- FACT's REST API could feed binary metadata into a Ghidra headless pipeline via PyGhidra.

---

## Interoperability and Toolchain Integration

### GTIRB (GrammaTech)

- **Repo**: https://github.com/GrammaTech/gtirb
- **Purpose**: Language-agnostic intermediate representation for binary analysis and rewriting. Aims to be "LLVM for binaries."
- **Design**: Stores raw machine-code bytes (not instruction semantics) plus symbolic operand information, control flow, and extensible AuxData tables. Supports multiple architectures.
- **Ecosystem**:
  - **DDisasm**: Disassembler that produces GTIRB from binaries.
  - **gtirb-pprinter**: Pretty-prints GTIRB as assembly or reassembles to executable.
  - **gtirb-rewriting**: API for modifying GTIRB; foundation for binary hardening/debloating transforms.
  - **gtirb-ghidra-plugin**: Import/export GTIRB in Ghidra.
  - **gtirb-vscode**: VSCode extension for working with GTIRB files.
  - **Retypd**: Binary type recovery running on GTIRB.
- **Value**: Enables tool composition -- disassemble with DDisasm, analyze with custom tools, rewrite, and reassemble. The serialized protobuf format enables cross-language interop.

### BinExport

- **Repo**: https://github.com/google/binexport
- **Purpose**: Export disassembly data from IDA Pro, Ghidra, and Binary Ninja into a Protocol Buffer format. Primary consumer is BinDiff for binary diffing.
- **Format**: Captures instructions, functions, CFGs, and metadata in a machine-readable protobuf.
- **Python library**: `python-binexport` (PyPI) loads .BinExport files from any supported disassembler.
- **Cross-tool value**: The closest thing to a universal exchange format for disassembly data. Enables diffing across tools (e.g., diff an IDA export against a Ghidra export).
- **Limitation**: Focused on structure for diffing; does not carry annotations, comments, or type information.

### r2pipe (radare2)

- **Repo**: https://github.com/radareorg/radare2-r2pipe
- **Purpose**: Scripting API for radare2. Single-method API: send a command string, receive output.
- **Languages**: Python, C, NodeJS, Swift, and more.
- **Key functions**: `r2.cmd('aa')` for raw output, `r2.cmdj('aflj')` for parsed JSON.
- **r2papi**: Higher-level typed API (Python, TypeScript) released with r2-5.9.4 (May 2024).
- **Integration**: Can communicate with local or remote radare2 instances via pipe, TCP, or HTTP. Useful for scripting radare2 analysis from external tools or orchestrating it alongside Ghidra.

### angr-Ghidra Integration

Two main projects bridge angr's symbolic execution engine with Ghidra:

**AngryGhidra**
- **Repo**: https://github.com/Nalen98/AngryGhidra
- **Approach**: Ghidra plugin that lets you set up and run angr symbolic execution from within Ghidra's UI.

**Ghidra Angr Integration Tool (Foundry Zero)**
- **Repo**: https://github.com/foundryzero/ghidra-angr-integration-tool
- **Approach**: Uses Ghidra's p-code representation so it can symbolically execute any architecture Ghidra supports. Select start/end points, define symbolic variables, constraints, and hooks without leaving Ghidra. Includes a Python 3 REPL for mid-simulation inspection.
- **Advantage**: Architecture-agnostic via p-code; does not require a separate angr loader for each architecture.

---

## Safety and Trust Patterns for ML Integration

### Offline-First Model Deployment

- **Rationale**: Sending decompiled code to cloud APIs risks leaking proprietary binaries, classified firmware, or client data.
- **Solutions**: Ollama, LM Studio, and text-generation-webui enable local model inference. GhidrOllama, GhidrAssist, and Gepetto all support local backends.
- **Trade-off**: Local models (7B-70B parameter) are less capable than frontier cloud models. Quantized models (GGUF) trade quality for memory/speed.
- **Recommendation**: Default to offline for sensitive work; use cloud APIs only for non-sensitive research or with explicit data handling agreements.

### Receipts and Provenance for Automated Changes

- **Problem**: When an LLM renames 200 functions, how do you know which names are good and which are hallucinated?
- **Current state**: Most plugins apply changes immediately with no undo log or provenance trail.
- **GhidrAssist exception**: RLHF dataset generation captures human accept/reject decisions.
- **Ideal pattern**: Every automated change should be logged as a structured receipt (what changed, who/what requested it, what model was used, what prompt was sent, what the original value was). This enables audit, rollback, and quality measurement.
- **Hash-chain audit trails**: AuditableLLM (https://www.mdpi.com/2079-9292/15/1/56) proposes hash-chain-backed tamper-evident audit logs for LLM lifecycle events.

### Sandboxing and Policy Modes

- **Tool sandboxing**: LLM-driven tools that modify the database (rename, retype, add comments) should operate in a preview/sandbox mode by default. Changes should be staged and require explicit approval.
- **Scope limitation**: Agentic plugins (ida_copilot, GhidrAssist ReAct mode) can take unbounded actions. Policy modes should limit which API calls the agent can make (read-only vs. read-write).
- **Container isolation**: For MCP servers, run the server process in a container or sandbox to limit filesystem and network access.
- **Prompt injection defense**: Binary symbol names and strings can contain adversarial content. Sanitize all binary-derived data before including in LLM prompts.

### Secure Secrets Management for API Keys

- **Problem**: Plugins store API keys in config files (often plaintext in Ghidra's preferences directory).
- **Better patterns**: Use OS keychain (macOS Keychain, Windows Credential Manager, Linux secret-service), environment variables, or a secrets manager. Never commit API keys to shared Ghidra script directories.
- **Organizational deployment**: Proxy API requests through an internal gateway that handles authentication, rate limiting, and logging. Individual analysts should not need direct API keys.

---

## EPIC E26 Operationalization: Firmware Domain Pack

### Pack Contract (Reproducible + Policy-Safe)

| Contract Element | Requirement | Release Check |
|---|---|---|
| `pack_id` | Immutable version tag (example: `firmware-pack-v1.0.0`) | Pack ID and manifest hash included in artifacts |
| Firmware provenance | Image `sha256`, vendor/version, source URL, license policy result | Unknown/forbidden license class is blocking |
| Extraction determinism | Toolchain versions for binwalk/unblob/EMBA/FirmAE pinned in manifest | Version drift invalidates run |
| Execution isolation | Emulation runs in sandboxed VM/network namespace with no production credentials | Isolation profile attached to run metadata |
| Data handling policy | Offline-first analysis for T3/T4 images; cloud connectors explicitly disabled by default | Policy mode recorded and audited |
| Artifact traceability | SBOM + component mapping + metric report carry checksum-linked run ID | Missing linkages are blocking |

### Baseline-vs-Pack Lift Harness

Run contract (example, deterministic local runner):

```bash
bash eval/run_smoke.sh \
  --real-target-manifest eval/reports/e23/real_target_manifest.json \
  --output eval/output/smoke/e26-firmware-pack-metrics.json

python3 eval/scripts/check_regression.py \
  --current eval/output/smoke/e26-firmware-pack-metrics.json \
  --baseline eval/reports/e23/real_target_baseline.json \
  --output eval/output/smoke/e26-firmware-pack-regression.json
```

Lift scorecard requirements for `firmware` slice (pack output must beat stock baseline):

| Metric | Stock Baseline Comparator | Pack Target | Gate |
|---|---|---|---|
| Filesystem extraction success | Stock extraction-only pipeline | `>= +0.12` absolute lift | Block if not met |
| Emulation boot success | Stock Firmadyne-like default profile | `>= +0.20` absolute lift | Block if not met |
| Component attribution recall | Stock signature-only component tagging | `>= +0.10` absolute lift | Block if not met |
| Known-CVE hit rate on benchmark set | Stock static-only CVE scan hit rate | `>= +0.08` absolute lift | Block if not met |
| Median triage time per image | Stock baseline median | `<= 0.85x` of baseline latency | Block if regressed |

### Release Decision Artifacts (Limits, Risks, Operator Guidance)

| Artifact | Required Contents | Owner |
|---|---|---|
| `eval/releases/e26/firmware/lift-scorecard.md` | Baseline vs pack deltas, confidence bounds, pass/fail | Eval/Research |
| `docs/evidence/e26/firmware-risk-register.md` | Emulation blind spots (NVRAM/peripheral gaps), false-negative risks, mitigations | Security |
| `docs/evidence/e26/firmware-operator-guidance.md` | Allowed firmware classes, handling of proprietary images, escalation runbook | Operations |

Release criteria:
- `GO`: all lift targets pass, provenance/license policy passes, and operator guidance is published.
- `HOLD`: any failed lift metric, unapproved license/provenance state, policy-mode mismatch, or missing risk disposition.

---

## Key Takeaways for Ghidra Integration

1. **PyGhidra is the canonical Python path**. It is bundled with Ghidra, maintained by NSA, and provides full CPython 3 access via JPype. Ghidrathon (Jep) is a strong alternative when tighter in-process coupling is needed, particularly for Mandiant/FLARE-style workflows.

2. **MCP is the emerging standard for LLM-RE integration**. At least 6 independent Ghidra MCP servers exist. Building on MCP rather than bespoke APIs means compatibility with Claude, ChatGPT, and any MCP-aware client. GhidrAssistMCP and ReVa are the most mature.

3. **Agentic RE is real but immature**. GhidrAssist's ReAct mode and ida_copilot demonstrate autonomous binary analysis. The missing pieces are provenance/audit trails, sandboxed execution, and reliable evaluation of output quality.

4. **Collaboration is Ghidra's weakest area**. The check-out/check-in server model works but lacks real-time sync, review workflows, and fine-grained attribution. Binary Ninja Enterprise is the current gold standard for collaborative RE. A Ghidra plugin providing Git-like branching and PR-style review would be high impact.

5. **Firmware pipelines are well-tooled but disconnected**. Binwalk, EMBA, FirmAE, and FACT each solve a piece of the firmware analysis problem. The gap is orchestration: no tool chains these together with interactive Ghidra analysis in a single workflow. PyGhidra headless mode + EMBA's REST outputs could bridge this.

6. **GTIRB and BinExport are the interop bridges**. GTIRB enables binary rewriting workflows; BinExport enables cross-tool diffing. Both use protobuf serialization. A Ghidra plugin that can round-trip through GTIRB would unlock the GrammaTech ecosystem.

7. **Safety defaults matter**. Any LLM integration should default to offline models, read-only mode, and logged changes. Cloud API usage should require explicit opt-in. Prompt injection from binary content is an underappreciated risk.

8. **r2pipe and angr integration** extend Ghidra's reach into dynamic analysis and symbolic execution. The Foundry Zero angr integration is particularly interesting because it uses Ghidra's own p-code, making it architecture-agnostic.
