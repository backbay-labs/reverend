# Python Integration Operations Matrix

> Practical operational reliability study of Ghidra's Python integration paths:
> PyGhidra (JPype), Ghidrathon (Jep), and Ghidra Bridge (RPC).
>
> Verification note (as of 2026-02-19): platform compatibility, version support,
> and failure modes documented here are based on issue tracker reports, release notes,
> and community documentation. Revalidate against current releases before production deployment.

---

## 1. Platform Compatibility Matrix

### Ghidra + JDK Version Requirements

| Ghidra Version | Minimum JDK | Recommended JDK | Python Versions | Notes |
|---|---|---|---|---|
| 11.0.x | 17 | 17 | 3.7-3.12 | PyGhidra introduced as bundled feature |
| 11.1.x | 17 | 17 or 21 | 3.7-3.12 | GhidraDev requires JDK 17 |
| 11.2.x | 21 | 21 | 3.9-3.12 | JDK 21 becomes minimum |
| 11.3.x | 21 | 21 | 3.9-3.13 | JIT p-code emulator added; PyGhidra GUI plugin |
| 12.0.x | 21 | 21 | 3.9-3.13 | PyGhidra 3.0 default; Jython deprecated but still available via header; concolic emulator |

### PyGhidra (JPype) Platform Matrix

PyGhidra uses JPype1 to embed the JVM inside CPython. JPype1 1.6.0 (July 2025) added Python 3.13 support. PyGhidra pins JPype1 to 1.5.2 on some releases to avoid a Windows crash in 1.6.0.

| Platform | Python 3.9 | Python 3.10 | Python 3.11 | Python 3.12 | Python 3.13 | Notes |
|---|---|---|---|---|---|---|
| **Ubuntu 22.04 (x86_64)** | Works | Works | Works | Works | Works (JPype >= 1.6.0) | Primary CI target; well-tested |
| **Ubuntu 24.04 (x86_64)** | Works | Works | Works | Works | Works | System Python is 3.12 |
| **RHEL 9 / Rocky 9 (x86_64)** | Works | Works | Works | Works | Partial | System Python is 3.9; newer versions via AppStream or deadsnakes |
| **Alpine Linux (musl)** | Broken | Broken | Broken | Broken | Broken | Ghidra's native decompiler binary requires glibc; musl incompatible without gcompat. Alpine `testing` repo has a ghidra-headless package but unsupported by Ghidra team |
| **macOS 13 Ventura (Intel)** | Works | Works | Works | Works | Works | Requires Xcode CLI tools |
| **macOS 14 Sonoma (Apple Silicon)** | Works | Works | Works | Works | Works | Universal2 JPype wheels available; JDK must be ARM64 |
| **macOS 15 Sequoia (Apple Silicon)** | Works | Works | Works | Works | Works | Same as 14; test with latest JPype wheels |
| **Windows 10 (x86_64)** | Works | Works | Works | Works | Partial | PyGhidra launcher may ignore active venvs (issue #8180); JPype 1.6.0 has a reported Windows crash -- pin to 1.5.2 |
| **Windows 11 (x86_64)** | Works | Works | Works | Works | Partial | Same venv and JPype issues as Win10 |
| **Windows Server 2022** | Works | Works | Works | Works | Partial | Headless-focused; same caveats |
| **Linux ARM64 (aarch64)** | Works | Works | Works | Works | Works | JPype provides manylinux aarch64 wheels; Ghidra native decompiler must be built for ARM64 |

**Key issues:**
- Python 3.13 support requires JPype1 >= 1.6.0, but PyGhidra may pin an older JPype version. Check `pyghidra` package constraints before upgrading Python.
- Windows venv activation is ignored by the PyGhidra launcher (Ghidra issue [#8180](https://github.com/NationalSecurityAgency/ghidra/issues/8180)). Workaround: install PyGhidra into the system Python or use `PYGHIDRA_PYTHON` environment variable.
- Alpine Linux: Ghidra's native C++ decompiler binary is linked against glibc. Running on musl requires `gcompat` or a custom glibc layer. The Ghidra team does not support Alpine (issue [#4005](https://github.com/NationalSecurityAgency/ghidra/issues/4005)).

### Ghidrathon (Jep) Platform Matrix

Ghidrathon uses Jep (Java Embedded Python) via JNI. Jep 4.2 adds Python 3.12 support. Ghidrathon's recent releases overhauled installation to remove manual Gradle builds.

| Platform | Python 3.9 | Python 3.10 | Python 3.11 | Python 3.12 | Python 3.13 | Notes |
|---|---|---|---|---|---|---|
| **Ubuntu 22.04 (x86_64)** | Works | Works | Works | Works (Jep >= 4.2) | Unknown | CI tested |
| **Ubuntu 24.04 (x86_64)** | Works | Works | Works | Works | Unknown | |
| **RHEL 9 (x86_64)** | Works | Works | Works | Works | Unknown | Requires dev headers for Jep native build |
| **Alpine Linux** | Broken | Broken | Broken | Broken | Broken | Same glibc issue as PyGhidra plus Jep native build complications |
| **macOS 13+ (Intel)** | Works | Works | Works | Works | Unknown | Requires Xcode + Java Developer Package |
| **macOS 14+ (Apple Silicon)** | Works | Works | Works | Works | Unknown | ARM64 JDK required; Jep must build for ARM64 |
| **Windows 10/11** | Partial | Partial | Partial | Partial | Unknown | Windows Store Python causes load failures (issue [#10](https://github.com/mandiant/Ghidrathon/issues/10)); native module build requires MSVC compiler; venv activation throws exceptions (issue [#3](https://github.com/mandiant/Ghidrathon/issues/3)) |
| **Windows Server 2022** | Partial | Partial | Partial | Partial | Unknown | Same compiler/venv issues as desktop Windows |

**Key issues:**
- Python 3.13 support depends on Jep releasing a compatible version; not confirmed as of this writing.
- Windows: Jep native module compilation requires Visual Studio Build Tools. The Windows Store Python distribution is incompatible.
- Virtual environments: Ghidrathon only works reliably when Jep is installed into the system-wide Python on Windows. On Linux/macOS, venvs work if `jep` is installed in the active environment and `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` is set correctly.
- Thread incompatibility: Using Ghidrathon's interpreter from another Python thread causes Jep to error because the interpreter is tied to the main thread (issue [#7](https://github.com/mandiant/Ghidrathon/issues/7)).

### Ghidra Bridge (RPC) Platform Matrix

Ghidra Bridge is a pure-Python RPC proxy (`jfx_bridge`). It has no native dependencies, making it the most portable option.

| Platform | Python 3.9 | Python 3.10 | Python 3.11 | Python 3.12 | Python 3.13 | Notes |
|---|---|---|---|---|---|---|
| **Any Linux (x86_64/ARM64)** | Works | Works | Works | Works | Works | No native deps; pure Python |
| **macOS (any)** | Works | Works | Works | Works | Works | |
| **Windows (any)** | Works | Works | Works | Works | Works | |
| **Alpine Linux** | Works | Works | Works | Works | Works | Only option that works on Alpine without glibc compat |

**Key issues:**
- Maintenance: Ghidra Bridge activity has declined as PyGhidra and Ghidrathon have matured. Verify recent commit activity before adopting for new projects.
- The bridge requires Ghidra to be running with the Jython bridge server script loaded. With Ghidra 12.0 defaulting to PyGhidra and deprecating Jython, the bridge's server-side component may require the `# @runtime Jython` header or alternative arrangements.
- Connection drops reported under heavy load (issue [#40](https://github.com/justfoxing/ghidra_bridge/issues/40)).

---

## 2. CI/CD Integration Patterns

### Docker Images for Headless Ghidra

| Image | Base | Ghidra Versions | PyGhidra | Size | Notes |
|---|---|---|---|---|---|
| [`blacktop/ghidra`](https://hub.docker.com/r/blacktop/ghidra) | Ubuntu / Alpine variants | 10.x - 12.x | Varies by tag | ~1.5-2.5 GB | Most popular community image; supports headless via `analyzeHeadless` |
| [`fkiecad/ghidra_headless_base`](https://hub.docker.com/r/fkiecad/ghidra_headless_base) | Debian | Various | No | ~1.5 GB | Fraunhofer FKIE base image for headless scripting |
| Custom (recommended) | Ubuntu 22.04/24.04 | Pin specific version | Yes (pip install) | ~2-3 GB | Full control over Python + JDK + PyGhidra versions |

**Recommended Dockerfile pattern:**

```dockerfile
FROM eclipse-temurin:21-jdk-jammy

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=12.0
ARG GHIDRA_DATE=20260101
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
    -O /tmp/ghidra.zip \
    && unzip /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && ln -s /opt/ghidra_* /opt/ghidra

# Install PyGhidra
RUN python3 -m pip install --no-cache-dir pyghidra

# Set environment
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV GHIDRA_HEADLESS_MAXMEM=4G

ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
```

**Alpine note:** Do not use Alpine as a base for Ghidra containers. The native decompiler binary requires glibc. Use Ubuntu or Debian-based images.

### GitHub Actions Workflow

```yaml
name: Ghidra Analysis Pipeline

on:
  push:
    paths: ['binaries/**', 'scripts/**']
  workflow_dispatch:
    inputs:
      binary_path:
        description: 'Path to binary to analyze'
        required: true

jobs:
  analyze:
    runs-on: ubuntu-22.04
    timeout-minutes: 60

    strategy:
      matrix:
        binary: [target1.exe, target2.elf, target3.so]
      max-parallel: 3

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 21
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '21'

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Cache Ghidra installation
        uses: actions/cache@v4
        with:
          path: /opt/ghidra
          key: ghidra-12.0-${{ runner.os }}

      - name: Install Ghidra
        if: steps.cache-ghidra.outputs.cache-hit != 'true'
        run: |
          wget -q $GHIDRA_DOWNLOAD_URL -O /tmp/ghidra.zip
          sudo unzip /tmp/ghidra.zip -d /opt
          sudo ln -sf /opt/ghidra_* /opt/ghidra

      - name: Install PyGhidra
        run: pip install pyghidra

      - name: Run headless analysis
        env:
          GHIDRA_HEADLESS_MAXMEM: 4G
        run: |
          /opt/ghidra/support/analyzeHeadless \
            /tmp/ghidra_project ProjectName \
            -import binaries/${{ matrix.binary }} \
            -postScript scripts/extract_results.py \
            -scriptPath scripts/ \
            -analysisTimeoutPerFile 1800 \
            -max-cpu 2

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: analysis-${{ matrix.binary }}
          path: results/
```

### GitLab CI Pattern

```yaml
ghidra-analysis:
  image: blacktop/ghidra:12.0
  stage: analyze
  parallel:
    matrix:
      - BINARY: [target1.exe, target2.elf]
  variables:
    MAXMEM: "4G"
  script:
    - analyzeHeadless /tmp/project Analysis
        -import $CI_PROJECT_DIR/binaries/$BINARY
        -postScript $CI_PROJECT_DIR/scripts/extract.py
        -scriptPath $CI_PROJECT_DIR/scripts/
        -analysisTimeoutPerFile 1800
  artifacts:
    paths:
      - results/
  cache:
    key: ghidra-project
    paths:
      - /tmp/project/
```

### Caching Strategies

| What to Cache | Key Strategy | Typical Size | Benefit |
|---|---|---|---|
| Ghidra installation | `ghidra-{version}-{os}` | ~700 MB | Avoid re-downloading each run |
| Ghidra project databases | `ghidra-project-{hash(binaries)}` | Varies (100 MB - 10 GB) | Skip re-import and re-analysis of unchanged binaries |
| PyGhidra/pip packages | `pip-{hash(requirements.txt)}` | ~50-200 MB | Faster dependency install |
| JDK | Use setup-java action caching | ~300 MB | Usually cached by action |

**Warning:** Ghidra project files contain lock files that may cause issues when restored from cache on a different machine. Clear lock files before reuse: `find /project -name "*.lock" -delete`.

### Parallel Analysis Patterns

Ghidra's `HeadlessAnalyzer` is single-instance per JVM. For parallel analysis of multiple binaries:

1. **Multiple processes (recommended):** Launch separate `analyzeHeadless` processes, each handling one or a batch of binaries. Use CI matrix strategies (GitHub Actions `matrix`, GitLab `parallel.matrix`) or GNU parallel.

2. **Shared project with sequential import:** Import all binaries into one project, then process them with `-process` flag. Analysis within a single program is internally parallel (up to `-max-cpu` cores), but programs are processed sequentially.

3. **Kubernetes jobs:** For large-scale batch (100s-1000s of binaries), use Kubernetes Jobs with Ghidra Docker images. Each pod processes a subset of binaries. Use a shared volume or object storage for results.

```bash
# GNU parallel example: analyze 100 binaries across 4 concurrent processes
find ./binaries -type f | parallel -j4 \
  /opt/ghidra/support/analyzeHeadless /tmp/project_{%} Analysis \
    -import {} \
    -postScript extract.py \
    -analysisTimeoutPerFile 600
```

**Constraint:** Java by default assigns one GC thread and one JIT compiler thread per core. When running many headless instances on a multi-core server, limit JVM threads per instance:

```bash
JAVA_TOOL_OPTIONS="-XX:ParallelGCThreads=2 -XX:CICompilerCount=2" \
  analyzeHeadless ...
```

---

## 3. Headless Mode Reliability

### Success/Failure Modes by Integration

| Integration | Headless Support | Reliability | Common Failure Modes |
|---|---|---|---|
| **PyGhidra** | Native (via `pyghidra.start()` or `analyzeHeadless` with PyGhidra scripts) | High | JVM heap exhaustion; JPype class loading errors; Python/Java type mismatch at boundary |
| **Ghidrathon** | Supported (scripts run via Script Manager in headless mode) | Medium | Jep native library load failures; thread-safety violations; venv detection failures on Windows |
| **Ghidra Bridge** | Requires Ghidra GUI/headless running with bridge server script | Low-Medium | RPC connection timeouts; serialization failures for large objects; slow iteration |
| **Native analyzeHeadless** | Primary design target | High | OOM on large binaries; decompiler timeout on obfuscated functions; lock file conflicts |

### Memory Management

The JVM and Python maintain separate heaps. Both must be sized appropriately.

**JVM Heap:**
- Set via `GHIDRA_HEADLESS_MAXMEM` environment variable or `-Xmx` JVM argument
- Default is often 768M, which is insufficient for binaries > 50 MB
- Recommended: 4G for typical binaries, 8-16G for large binaries (> 100 MB) or binaries with large PDB files
- Symptoms of exhaustion: `java.lang.OutOfMemoryError: Java heap space` (issue [#1997](https://github.com/NationalSecurityAgency/ghidra/issues/1997), [#2485](https://github.com/NationalSecurityAgency/ghidra/issues/2485))
- Jython memory overflow can hang Ghidra with 100% CPU (issue [#3326](https://github.com/NationalSecurityAgency/ghidra/issues/3326))

**Python Heap (PyGhidra/Ghidrathon):**
- Standard Python memory management; no special configuration
- Large data structures (e.g., collecting decompiled output for all functions) can exhaust Python memory
- Recommendation: process functions in batches, write results incrementally to disk

**Combined memory formula:**
```
Total RAM needed = JVM_HEAP + Python_HEAP + OS_overhead
Typical: 4G (JVM) + 2G (Python) + 1G (OS) = 7G minimum per headless instance
```

### Timeout Handling

| Mechanism | Scope | Configuration | Behavior |
|---|---|---|---|
| `-analysisTimeoutPerFile` | Per-binary auto-analysis | Seconds (CLI arg) | Cancels analysis via `HeadlessTimedTaskMonitor`; script can check `analysisTimedOut()` |
| Decompiler timeout | Per-function decompilation | `DecompileOptions.setDefaultTimeout()` (default 60s) | Individual function decompilation cancelled; other functions continue |
| Script timeout | Not built-in | Implement via Python `signal.alarm()` or threading timer | Must be handled in script code |
| CI-level timeout | Entire job | CI system config (e.g., `timeout-minutes` in GitHub Actions) | Process killed; no graceful cleanup |

**Long-running analysis patterns:**
- For binaries with > 100K functions, expect analysis times of 30-120 minutes
- Decompiler is the bottleneck: peaks at ~10-12 concurrent threads regardless of available cores (issue [#2791](https://github.com/NationalSecurityAgency/ghidra/issues/2791))
- Obfuscated binaries with control-flow flattening can cause individual function decompilation to hit timeouts
- Recommendation: set `-analysisTimeoutPerFile` to 2-3x the expected analysis time; use per-function decompiler timeouts as a safety net

### Ghidra's Single-Thread Constraint

Ghidra's analysis pipeline is fundamentally single-threaded per program:
- Only one Analyzer runs at a time via `AutoAnalysisManager`
- The decompiler has its own internal thread pool (capped at ~10-12 effective threads)
- Scripts execute on the analysis thread and block other analysis

**Workarounds for throughput:**
1. Process multiple binaries in parallel (separate JVM processes)
2. Within a script, use Ghidra's shared thread pool (`AutoAnalysisManager.getSharedAnalsysThreadPool()`) for embarrassingly parallel work
3. For PyGhidra scripts, use Python `concurrent.futures` for non-Ghidra-API work (file I/O, ML inference), but call Ghidra APIs from the main thread only

---

## 4. Dependency Reproducibility

### Virtual Environment Management

| Tool | PyGhidra Compat | Ghidrathon Compat | Bridge Compat | Notes |
|---|---|---|---|---|
| **venv** (stdlib) | Good (Linux/macOS), Broken (Windows launcher ignores venv) | Partial (Linux OK; Windows fails) | Good | Simplest; use `PYGHIDRA_PYTHON` env var on Windows |
| **conda/mamba** | Good | Good | Good | Best for managing native deps (JPype/Jep); can pin JDK too |
| **uv** | Good | Good | Good | Fast; good lockfile support; handles native wheels well |
| **pipx** | Not recommended | Not recommended | OK for bridge CLI | Designed for CLI tools, not library integration |

### Pinning Strategies

**For PyGhidra workflows:**
```
# requirements.txt (pin exact versions)
pyghidra==3.0.0
JPype1==1.5.2          # Pin to avoid Windows crash in 1.6.0
# Your analysis packages
networkx==3.4.2
pefile==2024.8.26
yara-python==4.5.1
```

**For Ghidrathon workflows:**
```
# requirements.txt
jep==4.2.0
# RE packages
capstone==5.0.3
unicorn==2.1.1
angr==9.2.133
```

**Lockfile recommendations:**
- `uv lock` produces a `uv.lock` file with exact hashes -- preferred for reproducibility
- `pip-compile` (pip-tools) produces a `requirements.txt` with hashes
- `conda-lock` produces cross-platform lockfiles with native library versions

### JPype/Jep Native Library Conflicts

**JPype:**
- JPype loads `libjvm` at startup. Only one JVM can be loaded per Python process.
- If `JAVA_HOME` points to a different JDK than the one Ghidra expects, JPype will load the wrong JVM. Symptom: `java.lang.UnsupportedClassVersionError`.
- JPype 1.6.0 has a known crash on Windows. PyGhidra pins to 1.5.2 to avoid this.
- JPype is incompatible with Jep in the same process (both try to control the JVM lifecycle).

**Jep:**
- Jep loads `libpython` into the JVM. The Python version must exactly match the `jep` wheel's target version.
- If multiple Python versions are installed, Jep may find the wrong `libpython`. Symptom: `Fatal Python error: init_fs_encoding`.
- `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) must include the Python library directory.
- Jep's native library (`libjep.so`/`jep.dll`) must be discoverable via `java.library.path`.

**Known incompatible combinations:**
| Package A | Package B | Conflict | Workaround |
|---|---|---|---|
| JPype1 | Jep | Both try to manage JVM lifecycle | Use only one per Python process |
| angr | unicorn (version mismatch) | angr pins specific unicorn versions | Pin angr's required unicorn version |
| JPype1 1.6.0 | Windows | Crash on shutdown | Pin JPype1==1.5.2 |
| torch (CUDA) | JPype1 | Both load large native libraries; memory pressure | Increase system RAM; use separate processes |

---

## 5. Failure Mode Catalog

### PyGhidra / JPype Failures

| Symptom | Cause | Severity | Workaround |
|---|---|---|---|
| `ModuleNotFoundError: No module named '_jpype'` | JPype native extension not built for this Python version/platform | Blocks startup | Reinstall JPype: `pip install --force-reinstall JPype1` |
| `java.lang.UnsupportedClassVersionError` | JAVA_HOME points to JDK < 21 but Ghidra 11.2+ requires 21 | Blocks startup | Set `JAVA_HOME` to JDK 21 |
| `RuntimeError: JVM is not running` | `pyghidra.start()` not called before Ghidra API access | Blocks analysis | Call `pyghidra.start()` at top of script |
| `java.lang.OutOfMemoryError: Java heap space` | JVM heap too small for binary size | Crashes analysis | Increase `GHIDRA_HEADLESS_MAXMEM` or pass `-Xmx` via PyGhidra launcher |
| Process hangs at 100% CPU after OOM | Jython/Python script triggered OOM; GC thrashing | Hangs process | Set memory limits; use `-analysisTimeoutPerFile`; use `ulimit` as safety net |
| `TypeError: Cannot convert Python object` | Passing unsupported Python type across JPype boundary | Script error | Use explicit Java type constructors: `from java.lang import String` |
| PyGhidra launcher ignores venv (Windows) | Known bug in launcher script | Wrong packages used | Set `PYGHIDRA_PYTHON` env var to venv Python path |
| `Ghidra was not started with PyGhidra` (Ghidra 12.x) | Script expects PyGhidra runtime but Ghidra started without it | Script error | Launch via `pyghidraRun` or ensure PyGhidra mode is enabled |
| Slow startup (30-60s) | JPype JVM initialization + Ghidra class scanning | Performance | Expected; cache Ghidra project to avoid re-analysis |

### Ghidrathon / Jep Failures

| Symptom | Cause | Severity | Workaround |
|---|---|---|---|
| `java.lang.UnsatisfiedLinkError: jep.dll` | Jep native library not found; `java.library.path` not set | Blocks startup | Set `LD_LIBRARY_PATH` or add Jep library dir to `java.library.path` |
| `Fatal Python error: init_fs_encoding` | Wrong `libpython` loaded; multiple Python versions installed | Crashes JVM | Ensure `PATH`/`LD_LIBRARY_PATH` points to correct Python |
| `jep.JepException: <class 'ModuleNotFoundError'>` | Package not installed in the Python environment Ghidrathon is using | Script error | Install package in system Python (Windows) or correct venv (Linux/macOS) |
| Thread error: interpreter state invalid | Using Ghidrathon from non-main thread | Crashes | Only call Ghidrathon from the main thread; do not spawn Python threads that access Ghidra API |
| Windows Store Python load failure | Windows Store Python uses app execution aliases that Jep cannot load | Blocks startup | Install Python from python.org, not the Windows Store |
| Venv not detected (Windows) | `ghidraRun.bat` does not inherit activated venv | Wrong packages | Install Jep and packages into system Python on Windows |

### Ghidra Bridge Failures

| Symptom | Cause | Severity | Workaround |
|---|---|---|---|
| `ConnectionRefusedError` | Bridge server not running in Ghidra | Blocks connection | Start `ghidra_bridge_server.py` in Ghidra's Script Manager first |
| Connection drops during long operations | RPC timeout; large object serialization failure | Intermittent | Increase timeout: `b = ghidra_bridge.GhidraBridge(response_timeout=300)` |
| Iteration takes minutes for large binaries | Each proxy object access is an RPC round-trip | Performance | Fetch data in bulk: use `b.remote_eval()` to run code server-side and return results |
| `BrokenPipeError` after idle period | TCP connection timed out | Intermittent | Reconnect; use keepalive or wrap in retry logic |
| Incompatible with Ghidra 12.0 default | Ghidra 12.0 defaults to PyGhidra, not Jython; bridge server is a Jython script | Blocks connection | Add `# @runtime Jython` header to bridge server script, or adapt bridge to work with PyGhidra runtime |

### General Ghidra Headless Failures

| Symptom | Cause | Severity | Workaround |
|---|---|---|---|
| `LockException: project is locked` | Previous process did not clean up lock file | Blocks startup | Delete `.lock` files in project directory |
| Analysis produces no output | Binary format not recognized; wrong loader | Silent failure | Specify `-loader` explicitly; check import log |
| Decompiler timeout on specific functions | Obfuscated/complex control flow exceeding timeout | Partial results | Increase decompiler timeout; skip problematic functions in script |
| `ClassNotFoundException` for custom analyzers | Extension not installed in Ghidra's extensions directory | Script error | Install extension before running headless analysis |

---

## 6. Performance Comparison

### Function Enumeration Throughput

Iterating over all functions in a program is a common operation. Performance varies dramatically by integration method.

| Integration | 10K Functions | 100K Functions | 1M Functions | Notes |
|---|---|---|---|---|
| **PyGhidra (in-process)** | ~1-2s | ~5-15s | ~30-120s | Direct Java object access via JPype; minimal overhead per call |
| **Ghidrathon (in-process)** | ~1-2s | ~5-15s | ~30-120s | Similar to PyGhidra; Jep boundary crossing is slightly faster per-call but difference is negligible |
| **Ghidra Bridge (RPC)** | ~20-60s | ~10-30 min | Impractical | Each function access is an RPC round-trip; `BridgedIterables` are documented as unusably slow for large binaries (issue [#24](https://github.com/justfoxing/ghidra_bridge/issues/24)) |
| **Native Java script** | ~0.5-1s | ~3-8s | ~15-60s | Baseline; no boundary crossing overhead |

### Decompilation Throughput

| Integration | 1K Functions | 10K Functions | 100K Functions | Notes |
|---|---|---|---|---|
| **PyGhidra** | ~30-60s | ~5-15 min | ~1-3 hrs | Bottlenecked by decompiler native process, not Python binding |
| **Ghidrathon** | ~30-60s | ~5-15 min | ~1-3 hrs | Same bottleneck |
| **Ghidra Bridge** | ~2-5 min | ~30-90 min | Impractical | RPC overhead on top of decompiler time |
| **Native Java** | ~25-50s | ~4-12 min | ~45 min-2.5 hrs | Slight advantage from avoiding binding overhead |

**Key insight:** For decompilation-heavy workloads, the choice of Python integration has minimal impact because the native C++ decompiler process is the bottleneck. The decompiler peaks at ~10-12 effective threads regardless of available cores.

### Memory Footprint

| Integration | Base Overhead | Per-Program Addition | Notes |
|---|---|---|---|
| **PyGhidra** | JVM (200-500 MB) + Python (50-100 MB) + JPype (~20 MB) | Program-dependent (100 MB - 10 GB) | Single process; shared memory space |
| **Ghidrathon** | JVM (200-500 MB) + embedded Python (~80-150 MB) | Program-dependent | Python runs inside JVM process; slightly lower total than PyGhidra |
| **Ghidra Bridge** | JVM (200-500 MB) + separate Python process (50-100 MB) | Program-dependent + RPC buffer overhead | Two separate processes; higher total memory |

### IPC Overhead Comparison

| Metric | PyGhidra (JPype) | Ghidrathon (Jep) | Ghidra Bridge (RPC) |
|---|---|---|---|
| Per-call latency | ~1-5 us | ~0.5-3 us | ~0.5-5 ms |
| Bulk data transfer (1 MB) | ~1-5 ms | ~1-5 ms | ~50-200 ms |
| Startup time | ~15-30s (JVM init) | ~15-30s (JVM init + Jep init) | ~15-30s (Ghidra) + ~1s (bridge connect) |
| Concurrency model | Python GIL; Java threads accessible | Python GIL; single-thread Jep constraint | Full concurrency (separate processes) |

---

## 7. Package Ecosystem Compatibility

### Test Matrix: Important Python Packages

Status legend: **W** = Works, **P** = Partial / with caveats, **X** = Broken/Incompatible, **?** = Untested/Unknown

| Package | PyGhidra | Ghidrathon | Bridge | Known Issues |
|---|---|---|---|---|
| **numpy** | W | W | W | JPype 1.5.x had numpy 2.0 compat issues; fixed in 1.5.1+ |
| **pandas** | W | W | W | No known conflicts |
| **networkx** | W | W | W | Excellent for callgraph analysis |
| **scikit-learn** | W | W | W | Memory-intensive models may compete with JVM heap |
| **torch** | P | P | W | CUDA memory + JVM heap can exhaust GPU/system RAM; works in separate process (Bridge) more reliably |
| **transformers** (HF) | P | P | W | Same memory concerns as torch; tokenizer native libs work |
| **angr** | P | W | W | angr + JPype both load native libs; angr pins specific unicorn version; test thoroughly |
| **capstone** | W | W | W | Mandiant explicitly uses with Ghidrathon |
| **unicorn** | W | W | W | Version must match angr's requirement if both used |
| **frida** | X | X | W | Frida spawns its own processes and uses IPC; incompatible with in-process JVM; use Bridge or separate process |
| **yara-python** | W | W | W | No known conflicts |
| **pefile** | W | W | W | Pure Python; works everywhere |
| **lief** | W | W | W | Native library; works with standard pip wheels |

### Notes on In-Process vs Out-of-Process

PyGhidra and Ghidrathon run Python inside (or tightly coupled to) the JVM process. This means:

- **Memory competition:** Large ML models (torch, transformers) compete with JVM heap for RAM. Solution: increase total system RAM or offload ML inference to a separate process.
- **Native library conflicts:** Packages that load their own native libraries (frida, angr's unicorn backend) may conflict with JVM native libraries. Test combinations carefully.
- **Signal handling:** Python packages that install signal handlers (some testing frameworks, debuggers) may conflict with JVM signal handling. JPype explicitly manages this, but edge cases exist.

Ghidra Bridge avoids these issues because Python runs in a completely separate process, but pays for it with RPC latency.

---

## 8. Recommended Configurations

### Interactive Scripting (GUI REPL)

| Aspect | Recommendation | Rationale |
|---|---|---|
| **Integration** | PyGhidra (Ghidra 11.3+/12.0+) or Ghidrathon | In-process for low latency; PyGhidra is bundled and requires no extra install |
| **Python version** | 3.12 | Best balance of package support and stability |
| **JDK** | Temurin 21 | Required for Ghidra 11.2+/12.0 |
| **Package management** | venv (Linux/macOS) or conda (Windows) | venv is simplest; conda avoids Windows venv bugs |
| **JVM heap** | 4-8G | GUI + analysis + Python overhead |

### Headless CI/CD

| Aspect | Recommendation | Rationale |
|---|---|---|
| **Integration** | PyGhidra with `analyzeHeadless` | Native headless support; no GUI dependencies; best-maintained path |
| **Python version** | 3.12 | Widest compatibility; 3.13 support still maturing |
| **JDK** | Temurin 21 | Required; use Docker base `eclipse-temurin:21-jdk-jammy` |
| **Container base** | Ubuntu 22.04 or 24.04 | glibc required; do not use Alpine |
| **JVM heap** | 4-8G per instance | Scale based on binary size |
| **Parallelism** | Multiple processes (1 binary per JVM) | Avoid single-instance bottleneck |
| **Timeout** | `-analysisTimeoutPerFile 1800` (30 min) | Prevent runaway analysis |
| **Lockfiles** | `uv lock` or `pip-compile` | Reproducible dependencies |

### Developer Runbook: Local Toolchain Guardrails

For this repository's evaluation pipeline, use the same pinned runtime pair as CI:

1. JDK: Temurin 21 (`java` + `javac`)
2. Python: 3.11.x (`python3`)

Use your package manager/version manager of choice to install those versions, then verify locally before running heavy workflows:

```bash
python3 --version | grep -E '^Python 3\.11\.'
java -version 2>&1 | head -n 1 | grep -E '"21(\.|")'
javac -version 2>&1 | grep -E '^javac 21(\.|$)'
bash scripts/cyntra/preflight.sh | tee /tmp/cyntra-preflight.log
grep -F '[preflight] python toolchain OK:' /tmp/cyntra-preflight.log
grep -F '[preflight] java toolchain OK:' /tmp/cyntra-preflight.log
grep -F '[preflight] preflight checks passed' /tmp/cyntra-preflight.log
```

Expected outcomes:
- each command exits `0`
- Python prints `3.11.x`
- Java and `javac` both report major `21`
- `preflight` reports both toolchain checks as OK and ends with `preflight checks passed`

Recommended command set before opening a PR:

```bash
bash scripts/cyntra/gates.sh --mode=context
bash scripts/cyntra/gates.sh --mode=diff
bash scripts/cyntra/gates.sh --mode=all
```

If preflight reports a Java mismatch, reset `JAVA_HOME` to a JDK 21 installation and ensure `$JAVA_HOME/bin` appears before other Java paths in `PATH`.

### Jupyter Notebook Analysis

| Aspect | Recommendation | Rationale |
|---|---|---|
| **Integration** | PyGhidra | Direct API access from notebook cells; `pyghidra.start()` in first cell |
| **Python version** | 3.11 or 3.12 | Jupyter ecosystem well-tested on these |
| **JDK** | Temurin 21 | |
| **Package management** | conda or uv | Manage JDK + Python + Jupyter in one environment |
| **JVM heap** | 4-8G | Set via `pyghidra.start(vm_args=['-Xmx8g'])` |
| **Notebook pattern** | Start JVM once; open/close programs as needed | JVM startup is expensive; reuse across cells |

### Large-Scale Batch Processing (1000+ binaries)

| Aspect | Recommendation | Rationale |
|---|---|---|
| **Integration** | PyGhidra via `analyzeHeadless` in containers | Stateless; horizontally scalable |
| **Orchestration** | Kubernetes Jobs or CI matrix | Each pod/runner handles a batch of binaries |
| **Python version** | 3.12 | |
| **JDK** | Temurin 21 | |
| **Container** | Custom Ubuntu 22.04 image with Ghidra + PyGhidra pre-installed | Minimize cold-start time |
| **JVM tuning** | `-Xmx4g -XX:ParallelGCThreads=2 -XX:CICompilerCount=2` | Limit per-instance resource usage when running many in parallel |
| **Results storage** | Write to shared volume or object storage (S3/GCS) | Avoid filling container disk |
| **Timeout** | `-analysisTimeoutPerFile 600` per binary; job-level timeout at 2x | Prevent one bad binary from blocking the batch |
| **Retry strategy** | Re-queue failed binaries with increased heap | OOM is the most common failure mode |

### ML Pipeline (Embedding Generation, Model Training)

| Aspect | Recommendation | Rationale |
|---|---|---|
| **Integration** | PyGhidra for feature extraction; separate process for ML inference | Avoid JVM + CUDA memory conflicts |
| **Architecture** | Two-stage: (1) Ghidra headless extracts features to files, (2) ML pipeline consumes features | Decouples RE engine from ML framework |
| **Python version** | 3.11 (torch compatibility) or 3.12 | Match ML framework requirements |
| **JDK** | Temurin 21 | |
| **Feature format** | JSON Lines or Parquet per function | Streamable; works with pandas/pyarrow |
| **Package management** | conda (for CUDA + native deps) or uv | conda excels at managing CUDA toolkit + Python |
| **JVM heap** | 8-16G (large binaries produce large feature sets) | |
| **GPU** | Not needed for Ghidra stage; needed for ML stage | Keep stages separate to avoid resource conflicts |

---

## Appendix A: Version Compatibility Quick Reference

### Minimum Tested Combinations

| Use Case | Ghidra | JDK | Python | JPype1 | Jep | OS |
|---|---|---|---|---|---|---|
| PyGhidra baseline | 11.3 | 21 | 3.12 | 1.5.2 | N/A | Ubuntu 22.04 |
| PyGhidra latest | 12.0 | 21 | 3.12 | 1.5.2 | N/A | Ubuntu 24.04 |
| Ghidrathon baseline | 11.2 | 21 | 3.11 | N/A | 4.2 | Ubuntu 22.04 |
| Ghidrathon on macOS | 11.3 | 21 (ARM64) | 3.12 | N/A | 4.2 | macOS 14 (AS) |
| Bridge baseline | 11.x | 17 or 21 | 3.10 | N/A | N/A | Any |
| CI Docker | 12.0 | 21 | 3.12 | 1.5.2 | N/A | Ubuntu 22.04 container |

### End-of-Support Warnings

| Component | Version | Status | Migration Path |
|---|---|---|---|
| Jython scripting | Ghidra 12.0 | Deprecated (requires `# @runtime Jython` header) | Migrate scripts to Python 3 / PyGhidra |
| JDK 17 | Ghidra 11.2+ | No longer sufficient | Upgrade to JDK 21 |
| Python 3.8 and below | All integrations | Unsupported | Upgrade to 3.9+ (prefer 3.12) |
| Ghidra Bridge | N/A | Declining maintenance | Migrate to PyGhidra |
| JPype1 < 1.5.0 | PyGhidra | Missing Python 3.12 support | Upgrade JPype1 |

---

## Appendix B: Troubleshooting Decision Tree

```
Script fails to run
├── "No module named '_jpype'" or "No module named 'jpype'"
│   └── Reinstall JPype: pip install --force-reinstall JPype1==1.5.2
├── "Ghidra was not started with PyGhidra"
│   └── Launch via pyghidraRun or call pyghidra.start() first
├── "UnsatisfiedLinkError: jep"
│   └── Set LD_LIBRARY_PATH to include Jep native library directory
├── "Fatal Python error: init_fs_encoding"
│   └── Multiple Python versions installed; fix PATH/LD_LIBRARY_PATH
├── "OutOfMemoryError: Java heap space"
│   └── Increase GHIDRA_HEADLESS_MAXMEM (e.g., 8G)
├── "ConnectionRefusedError" (Bridge)
│   └── Start bridge server in Ghidra first
├── "UnsupportedClassVersionError"
│   └── JAVA_HOME points to wrong JDK; set to JDK 21
├── Very slow iteration (Bridge)
│   └── Use remote_eval() for server-side computation
└── Analysis produces no results
    └── Check import log; verify binary format is supported
```

---

## Sources

- [PyGhidra on PyPI](https://pypi.org/project/pyghidra/)
- [Ghidrathon GitHub](https://github.com/mandiant/Ghidrathon)
- [Ghidra Bridge GitHub](https://github.com/justfoxing/ghidra_bridge)
- [JPype1 Documentation](https://jpype.readthedocs.io/en/latest/)
- [Jep GitHub](https://github.com/ninia/jep)
- [Ghidra Issue #7141 - Python 3.13 Support](https://github.com/NationalSecurityAgency/ghidra/issues/7141)
- [Ghidra Issue #8180 - PyGhidra Venv on Windows](https://github.com/NationalSecurityAgency/ghidra/issues/8180)
- [Ghidra Issue #8555 - Python Scripts in 12.1](https://github.com/NationalSecurityAgency/ghidra/issues/8555)
- [Ghidra Issue #4005 - Alpine Linux Decompiler](https://github.com/NationalSecurityAgency/ghidra/issues/4005)
- [Ghidra Issue #2791 - Batch Decompilation Performance](https://github.com/NationalSecurityAgency/ghidra/issues/2791)
- [Ghidra Issue #1997 - OutOfMemoryError](https://github.com/NationalSecurityAgency/ghidra/issues/1997)
- [Ghidra Issue #3326 - Jython Memory Overflow](https://github.com/NationalSecurityAgency/ghidra/issues/3326)
- [Ghidrathon Issue #7 - Thread Incompatibility](https://github.com/mandiant/Ghidrathon/issues/7)
- [Ghidrathon Issue #10 - Windows Installation](https://github.com/mandiant/Ghidrathon/issues/10)
- [Ghidra Bridge Issue #24 - Slow Iterables](https://github.com/justfoxing/ghidra_bridge/issues/24)
- [Ghidra Bridge Issue #40 - Connection Breakdown](https://github.com/justfoxing/ghidra_bridge/issues/40)
- [blacktop/docker-ghidra](https://github.com/blacktop/docker-ghidra)
- [fkie-cad/docker_ghidra_headless_base](https://github.com/fkie-cad/docker_ghidra_headless_base)
- [Ghidra 12.0 What's New](https://ghidradocs.com/12.0_PUBLIC/docs/WhatsNew.html)
- [Ghidra 11.3 What's New](https://www.ghidradocs.com/11.3_PUBLIC/docs/WhatsNew.html)
- [Mandiant Ghidrathon Blog Post](https://cloud.google.com/blog/topics/threat-intelligence/ghidrathon-snaking-ghidra-python-3-scripting/)
- [Ghidrathon + Unicorn + Capstone Tutorial](https://0xca7.github.io/posts/ghidrathon_unicorn/)
- [ghidrecomp - Python Ghidra Decompiler](https://github.com/clearbluejar/ghidrecomp)
- [Ghidra Headless Analyzer README](https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html)
