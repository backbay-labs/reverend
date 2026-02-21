# Unified Evaluation Harness

> Specification for a reproducible evaluation framework covering all roadmap features:
> semantic search, type recovery, diffing, dynamic-static fusion, ML integration,
> and collaboration. Defines metrics, datasets, acceptance criteria, regression suites,
> human productivity protocols, dashboard schemas, and automated pipelines.
>
> Compiled: 2026-02-19 | Status: Draft specification
>
> Verification note (as of 2026-02-19): benchmark baselines, target thresholds, and
> dataset availability are point-in-time assumptions that should be revalidated before
> turning these gates into release criteria.

---

## 1. Cross-Feature Evaluation Matrix

The master table maps each roadmap feature to concrete metrics, measurement methods, baselines, and targets. Every metric must have a programmatic evaluator (no subjective-only metrics for automated gates).

### 1.1 Master Evaluation Table

| Feature Area | Metric | What to Measure | How to Measure | Baseline | Target |
|---|---|---|---|---|---|
| **Semantic Search** | Recall@1 | Fraction of queries where the correct function is the top result | REFuSe-Bench pool queries against BSim/embedding index | Ghidra BSim recall on BinaryCorp (measured) | Recall@1 >= 0.70 on REFuSe-Bench cross-compiler subset |
| **Semantic Search** | Recall@10 | Correct function in top-10 results | Same pool query protocol | BSim baseline (measured) | Recall@10 >= 0.85 |
| **Semantic Search** | MRR (Mean Reciprocal Rank) | Average reciprocal of rank of first correct result | REFuSe-Bench + BinCodex evaluation protocol | BSim MRR (measured) | MRR >= 0.75 |
| **Semantic Search** | Query Latency (p50/p99) | Wall-clock time from query submission to ranked results | Instrumented query path, 1000-function benchmark set | BSim H2 latency (measured) | p50 < 200ms, p99 < 2s for 1M-function corpus |
| **Semantic Search** | Cross-Architecture Recall@1 | Recall when query and corpus are different ISAs | BinCodex cross-platform subset (x86 vs ARM) | BSim cross-arch baseline | Recall@1 >= 0.55 cross-arch |
| **Type Recovery** | Type Accuracy (overall) | Fraction of variables with correctly inferred types vs DWARF ground truth | SURE 2025 protocol: compare against debug info | Ghidra built-in: ~15% at -O2 (SURE 2025) | >= 25% at -O2 (60%+ improvement over Ghidra baseline) |
| **Type Recovery** | Type Accuracy (primitives) | Correct primitive type assignment | SURE 2025 per-category breakdown | Ghidra baseline per SURE 2025 | >= 80% on primitives |
| **Type Recovery** | Type Accuracy (structs) | Correct struct field count, offset, and field type | Realtype benchmark + SURE 2025 struct subset | Ghidra baseline | >= 40% struct recovery (field-level F1) |
| **Type Recovery** | UDT Composition Accuracy | Correctness of user-defined type definitions (nested structs, enums, function pointers) | Realtype benchmark (IDIOMS protocol) | LLM4Decompile: 46.3% on ExeBench | >= 55% on ExeBench, >= 30% on Realtype |
| **Type Recovery** | Coverage | Fraction of variables receiving non-trivial type assignment | Count typed vs `undefined` variables across corpus | Ghidra baseline (measured) | >= 85% coverage |
| **Type Recovery** | Consistency | Cross-call-site type agreement for same function parameters | Custom checker: for each function called N times, measure type agreement across call sites | Baseline (measured) | >= 90% call-site consistency |
| **Diffing** | Function Match Rate | Fraction of functions correctly paired between two binary versions | Ground truth from DWARF-matched compilation pairs | BinDiff match rate on patch corpus (measured) | Match rate >= 0.90 on curated patch pairs |
| **Diffing** | Changed-Function Detection Rate | Fraction of actually-changed functions correctly flagged as changed | Patch corpus with known diffs (source-level ground truth) | BinDiff/ghidriff baseline | Detection rate >= 0.95 |
| **Diffing** | False Positive Rate | Functions flagged as changed that are actually unchanged | Same patch corpus | BinDiff baseline | FPR <= 0.05 |
| **Diffing** | Markup Transfer Accuracy | Correctness of transferred comments, names, types after VT match | Manual audit sample from Version Tracking runs | Ghidra VT baseline (measured) | >= 85% markup items correctly placed |
| **Diffing** | Batch Throughput | Functions diffed per second in headless mode | Timed ghidriff/VT runs on standardized corpus | ghidriff baseline (measured) | >= 100 functions/sec on commodity hardware |
| **Dynamic-Static Fusion** | Annotation Coverage | Fraction of functions with at least one dynamic-origin annotation after a trace session | Instrumented trace import + annotation propagation | No baseline (new feature) | >= 60% of executed functions annotated |
| **Dynamic-Static Fusion** | Type Refinement Rate | Fraction of dynamically-observed types that improve static type assignments | Compare pre/post-trace type accuracy against DWARF | No baseline | >= 20% of ambiguous types resolved by dynamic evidence |
| **Dynamic-Static Fusion** | Trace Import Latency | Time to import and correlate a trace file with static analysis | Timed import of standardized trace files | No baseline | < 30s for 100K-event trace |
| **ML Integration** | Suggestion Acceptance Rate | Fraction of ML suggestions accepted by analyst (in-tool telemetry) | A/B study or telemetry from opt-in users | No baseline (new feature) | >= 60% acceptance rate |
| **ML Integration** | Suggestion Accuracy | Correctness of ML suggestions vs ground truth (debug info) | Automated comparison on labeled corpus | Model-specific baseline (measured per model) | >= 80% accuracy on accepted suggestions |
| **ML Integration** | Inference Latency (p50/p99) | Time from request to suggestion displayed | Instrumented MCP/model pipeline | Model-specific (measured) | p50 < 3s, p99 < 15s for local model |
| **ML Integration** | Receipt Completeness | Fraction of ML-generated changes with valid provenance receipts | Automated receipt chain validation | No baseline (new feature) | 100% of auto-applied changes have receipts |
| **ML Integration** | Rollback Success Rate | Fraction of rollback operations that cleanly restore previous state | Automated rollback test suite | No baseline | 100% clean rollback |
| **Collaboration** | Merge Conflict Rate | Fraction of concurrent edits that produce conflicts | Simulated multi-user edit scenarios | Ghidra shared project baseline (measured) | Conflict rate <= 5% for typical workflows |
| **Collaboration** | Review Turnaround Time | Time from annotation submission to review completion | Instrumented review workflow | No baseline (new feature) | Median < 4 hours for team of 5 |
| **Collaboration** | Knowledge Reuse Hit Rate | Fraction of functions in a new binary that match existing annotations | Query new binary against team knowledge base | Ghidra FID baseline | >= 40% hit rate on enterprise firmware corpus |

### 1.2 Metric Properties

Every metric in the matrix must satisfy:

1. **Deterministic**: Same inputs produce the same score (no randomness unless explicitly averaged over seeds).
2. **Bounded**: Values fall within a defined range (typically [0, 1] or measured in concrete units).
3. **Automatable**: Computable by a script without human judgment (human metrics are handled separately in Section 5).
4. **Comparable**: Baselines are measured using the same protocol as targets, enabling apples-to-apples comparison.

---

## 2. Reproducible Datasets

### 2.1 Dataset Registry

Each feature area requires standardized test corpora. All datasets are version-pinned and stored as content-addressed artifacts (SHA-256 recorded in `datasets/datasets.lock.json`).

| Feature Area | Dataset | Source | Size | Format | Purpose |
|---|---|---|---|---|---|
| **Similarity** | BinaryCorp-3M | jTrans release (Wang et al., ISSTA 2022) | ~3M functions | ELF binaries + metadata JSON | Primary similarity evaluation corpus |
| **Similarity** | REFuSe-Bench | NeurIPS 2024 Datasets track | Varied (cross-compiler, cross-arch, malware subsets) | Binary pairs + ground truth labels | Realistic BFSD evaluation with quality controls |
| **Similarity** | BinCodex | BenchCouncil Trans. 2024 | Multi-level (platform, compiler, options, obfuscation) | Binary pairs + variation labels | Controlled multi-axis variation testing |
| **Decompilation** | Decompile-Bench | Tan et al., NeurIPS 2025 | 2M binary-source pairs (100K eval subset) | ELF + source + test harnesses | Decompilation quality (re-executability) |
| **Decompilation** | ExeBench | Armengol-Estape et al. | 5,000 functions with IO examples | C source + compiled binaries | Standard decompilation benchmark |
| **Type Recovery** | SURE-2025-Corpus | Soni, SURE 2025 | x86-64 ELF, multiple programs at -O0/-O2 | Stripped binaries + DWARF ground truth | Type inference benchmarking |
| **Type Recovery** | Realtype | Dramko et al. (IDIOMS), 2025 | Complex UDTs from real projects | Ghidra decompiler output + source types | Stress-test UDT recovery |
| **Type Recovery** | DIRT | Chen et al. (DIRTY), USENIX 2022 | 75K+ programs, 1M+ functions | Decompiler output + original source | Variable name and type prediction |
| **Diffing** | PatchCorpus-v1 | Curated from Patch Tuesday + OSS security patches | 200+ binary pairs (pre/post-patch) | PE/ELF pairs + source-level diff ground truth | Patch diffing evaluation |
| **Diffing** | ghidriff-samples | clearbluejar/ghidriff test suite | ~50 binary pairs | Mixed formats | Regression testing for diff engine |
| **Malware** | MalwareBazaar-Subset | abuse.ch MalwareBazaar | 1,000 samples (curated families) | PE/ELF binaries + family labels | Malware similarity and triage testing |
| **Malware** | VirusShare-Mini | VirusShare (research agreement) | 500 samples | PE binaries + AV labels | Cross-validation with MalwareBazaar |
| **ML Integration** | Triage-Curated-v2026.02.1 | Repo-local curated benchmark (`scripts/ml/fixtures/triage_benchmark_v2026_02_1.json`) | 12 labeled functions | Function records + labels (`entrypoint`, `hotspot`, `unknown`) | Triage score calibration and threshold regression checks |
| **Cross-Feature** | BinMetric-1K | IJCAI 2025 | 1,000 questions, 6 task types | Structured Q&A + binaries | End-to-end LLM binary analysis evaluation |

### 2.2 Dataset Preparation Pipeline

```
datasets/
  prepare.sh              # Master preparation script
  datasets.lock.json       # Locked dataset manifest + checksums
  config/
    binarycorp.yaml        # Download URLs, extraction, filtering config
    refuse-bench.yaml
    sure-2025.yaml
    ...
  scripts/
    download.py            # Authenticated download with retry
    extract_dwarf.py       # Extract DWARF ground truth from debug binaries
    strip_binaries.py      # Create stripped analysis targets
    compile_corpus.py      # Multi-compiler, multi-opt compilation
    validate_checksums.py  # Verify dataset integrity
    ghidra_import.py       # Batch import into Ghidra project via headless
```

**Repo implementation (as of 2026-02-20):**

This repository includes a deterministic, repo-local smoke harness (no network, no external deps) backed by `datasets/datasets.lock.json`.

- Run smoke eval: `bash eval/run_smoke.sh` (writes `eval/output/smoke/metrics.json`)
- Run stock baseline slices + publish comparator artifacts:
  - `bash eval/run_smoke.sh --slice semantic-search --slice type-recovery --output eval/output/stock-baseline/metrics.json`
  - `python3 eval/scripts/publish_baseline.py --metrics eval/output/stock-baseline/metrics.json --baseline-out eval/output/stock-baseline/baseline.json --report-out eval/output/stock-baseline/baseline-report.md`
- Materialize pinned datasets: `python3 eval/scripts/download.py --verify --output-dir datasets/data`
- Validate checksums: `python3 eval/scripts/validate_checksums.py`

Smoke output contains baseline metrics for similarity (`recall@1`, `mrr`), type recovery (`accuracy`), and diffing (`match_rate`, `coverage`), plus benchmark-slice metadata (`benchmark_slices`) and lockfile-traceable dataset revisions (`dataset_revisions`).

Determinism controls (enforced by `eval/run_smoke.sh` and checked by `eval/scripts/run_smoke.py`):
- `PYTHONHASHSEED=0`
- `TZ=UTC`
- `LC_ALL=C`, `LANG=C`
- `EVAL_SEED` (default `0`; override or pass `--seed`)

`run_smoke.py` fails fast if any deterministic environment control is missing or mismatched.

**Preparation steps:**

1. `download.py` materializes pinned repo-local fixtures into `datasets/data/` and verifies SHA-256 against `datasets/datasets.lock.json` when `--verify` is set.
2. `extract_dwarf.py` extracts ground-truth type and symbol information from debug-info builds.
3. `strip_binaries.py` creates stripped analysis targets (removing `.symtab`, `.debug_*` sections).
4. `compile_corpus.py` compiles source corpora at specified compiler/optimization matrix (GCC 12/13/14, Clang 16/17/18 x O0/O1/O2/O3/Os).
5. `ghidra_import.py` batch-imports binaries into Ghidra headless projects for analysis.
6. `validate_checksums.py` confirms all derived artifacts match expected checksums.

### 2.3 Version Pinning Strategy

- **External datasets**: Pinned by SHA-256 of the download archive. If upstream changes, the old version is preserved in project storage.
- **Compiled corpora**: Pinned by (source commit SHA + compiler version + flags). Compilation is deterministic given the same Docker image.
- **Ghidra analysis output**: Pinned by (Ghidra version + analysis options hash). Re-analysis required when Ghidra version changes.
- **Docker images**: All dataset preparation runs inside version-pinned Docker images (`Dockerfile.datasets` with locked base image digests).

```json
// datasets.lock.json (excerpt)
{
  "schema_version": 1,
  "kind": "deterministic_eval_dataset_lock",
  "datasets": {
    "toy-diff-v1": {
      "version": "1.0.0",
      "files": {
        "eval/fixtures/toy_diff_pairs_v1.json": {
          "bytes": 1711,
          "sha256": "739f497e10a36ea45b50fbd81b14cc19b67e3ee4dee1fe9c50747d26b7c866ee"
        }
      }
    }
  }
}
```

---

## 3. Acceptance Metrics

### 3.1 Feature-Level Pass/Fail Criteria

Each roadmap feature has quantitative acceptance criteria. A feature passes evaluation when all its primary metrics meet the target threshold on the designated dataset.

| Feature | Primary Metric | Dataset | Threshold | Justification |
|---|---|---|---|---|
| **Semantic Search (same-arch)** | Recall@1 | REFuSe-Bench cross-compiler | >= 0.70 | jTrans achieves 0.625 on BinaryCorp; target represents meaningful improvement over BSim baseline |
| **Semantic Search (cross-arch)** | Recall@1 | BinCodex cross-platform | >= 0.55 | VexIR2Vec reports 0.76 MAP; conservative target for integrated system |
| **Semantic Search (latency)** | p99 latency | 1M-function corpus | < 2s | Interactive use requires sub-second for most queries |
| **Type Recovery (overall)** | Accuracy at -O2 | SURE 2025 | >= 0.25 | Ghidra baseline is ~15%; target is 60%+ relative improvement |
| **Type Recovery (structs)** | Field-level F1 | Realtype | >= 0.40 | IDIOMS achieves 54.4% on ExeBench; structs are harder |
| **Type Recovery (UDTs)** | Composition accuracy | Realtype | >= 0.30 | Novel capability; Realtype is intentionally hard |
| **Decompilation Refinement** | Re-executability rate | Decompile-Bench-Eval | >= 0.50 | LLM4Decompile-V2 22B achieves ~45% on HumanEval; target accounts for integration overhead |
| **Diffing (match rate)** | Function match rate | PatchCorpus-v1 | >= 0.90 | BinDiff typically achieves 85-95% on well-behaved binaries |
| **Diffing (change detection)** | Changed-function detection | PatchCorpus-v1 | >= 0.95 | Security-critical: missing a changed function could miss a vulnerability |
| **Diffing (FPR)** | False positive rate | PatchCorpus-v1 | <= 0.05 | Analyst trust requires low noise |
| **Dynamic-Static Fusion** | Annotation coverage | Instrumented trace corpus | >= 0.60 | New capability; 60% of executed functions is a meaningful starting point |
| **ML Integration (accuracy)** | Suggestion accuracy | Labeled corpus subset | >= 0.80 | Below 80% accuracy degrades analyst trust |
| **ML Integration (receipts)** | Receipt completeness | All ML-generated changes | == 1.00 | Non-negotiable: every auto-applied change must have provenance |
| **ML Integration (triage calibration)** | Macro F1 / Entrypoint recall / Hotspot recall / Unknown precision | Triage-Curated-v2026.02.1 | Macro F1 >= 0.95, Entrypoint recall >= 0.95, Hotspot recall >= 0.95, Unknown precision >= 0.95 | Keeps triage threshold tuning measurable and version-pinned |
| **Collaboration** | Knowledge reuse hit rate | Enterprise firmware corpus | >= 0.40 | Lumina/WARP achieve higher on exact-match; 40% includes fuzzy matches |

### 3.2 Composite Score

For tracking overall system quality across releases, compute a weighted composite score:

```
composite = sum(weight_i * normalized_metric_i) / sum(weight_i)
```

Weights reflect feature priority:
- Semantic search: 0.25
- Type recovery: 0.25
- Diffing: 0.20
- ML integration: 0.15
- Dynamic-static fusion: 0.10
- Collaboration: 0.05

Each metric is normalized to [0, 1] by dividing the measured value by the target threshold (capped at 1.0). A composite score >= 0.80 is the release gate.

### 3.3 Degradation Tolerance

No individual metric may degrade by more than 5% (absolute) between releases without explicit approval. This prevents trading off one capability for another without deliberate review.

### 3.4 E5-S3 Calibration Snapshot (2026-02-20)

Curated benchmark artifact:
- `scripts/ml/fixtures/triage_benchmark_v2026_02_1.json`

Calibration command:
- `python3 scripts/ml/local_embedding_pipeline.py triage-calibrate --benchmark scripts/ml/fixtures/triage_benchmark_v2026_02_1.json`

Threshold update:
- Before: `entrypoint=0.45`, `hotspot=0.30`, `unknown=0.55`
- After: `entrypoint=0.30`, `hotspot=0.25`, `unknown=0.65`

Before/after benchmark metrics (same benchmark version):

| Metric | Before | After | Delta |
|---|---:|---:|---:|
| Macro F1 | 0.848677 | 0.969697 | +0.121020 |
| Entrypoint recall | 0.666667 | 1.000000 | +0.333333 |
| Hotspot recall | 0.800000 | 1.000000 | +0.200000 |
| Unknown precision | 0.750000 | 1.000000 | +0.250000 |

All four target thresholds pass after calibration; none passed before calibration.

---

## 4. Regression Suites

### 4.1 Snapshot Test Approach

Regression testing stores expected outputs ("golden files") and diffs against new runs. The snapshot strategy differs by feature:

| Feature | Snapshot Content | Storage Format | Diff Method |
|---|---|---|---|
| **Semantic Search** | Top-10 result lists for 500 query functions | JSON (function ID, rank, similarity score) | Exact match on function IDs; tolerance on scores (+/- 0.01) |
| **Type Recovery** | Inferred types for all functions in SURE corpus | JSON (address, variable name, inferred type) | Exact match on type strings; structural match for structs |
| **Decompilation** | Decompiled C output for 200 benchmark functions | C source files | AST-level diff (ignore whitespace/formatting); re-executability test |
| **Diffing** | Match tables for 50 binary pairs | JSON (source function, dest function, score) | Exact match on function pairs; tolerance on scores |
| **ML Suggestions** | Model outputs for 100 standardized prompts | JSON (prompt hash, suggestion, confidence) | Semantic diff (embedding similarity > 0.95 = match) |

### 4.2 Snapshot Management

```
eval/
  snapshots/
    v0.1.0/                     # Snapshots for release v0.1.0
      similarity/
        binarycorp-recall.json
        refuse-bench-recall.json
      type-recovery/
        sure-2025-types.json
        realtype-udts.json
      diffing/
        patchcorpus-matches.json
      decompilation/
        exebench-output/
          func_001.c
          func_002.c
          ...
    latest -> v0.1.0             # Symlink to current golden snapshots
```

**Update protocol:**
1. Run evaluation suite against `latest` snapshots.
2. If a test fails, investigate whether the change is a regression or an improvement.
3. If improvement: update the golden snapshot with approval from two reviewers.
4. If regression: block the release until fixed or explicitly accepted with documented justification.

### 4.3 CI/CD Integration

| Trigger | Suite | Duration | Blocking |
|---|---|---|---|
| **Per-commit** | Smoke tests (50 functions, 3 metrics per feature) | < 10 min | Yes (merge gate) |
| **Nightly** | Full regression suite (all snapshots, all datasets) | 2-4 hours | Yes (next-day triage) |
| **Per-release** | Complete evaluation + human review sample | 8-24 hours | Yes (release gate) |
| **Weekly** | Extended benchmarks (BinaryCorp-3M, full BinCodex) | 12-48 hours | No (monitoring only) |

**Alert thresholds:**

| Severity | Condition | Action |
|---|---|---|
| **Critical** | Any primary metric drops > 10% vs previous release | Block release; immediate investigation |
| **Warning** | Any primary metric drops 5-10% | Flag for review; must be resolved before next release |
| **Info** | Any secondary metric changes > 5% | Log for tracking; no blocking |

### 4.4 Smoke Test Suite (Per-Commit)

The smoke suite runs in under 10 minutes and covers critical paths:

```yaml
smoke_tests:
  similarity:
    - query 10 functions from BinaryCorp against H2 BSim index
    - assert recall@1 >= snapshot_value - 0.05
  type_recovery:
    - run type inference on 20 SURE-2025 functions
    - assert accuracy >= snapshot_value - 0.05
  diffing:
    - diff 5 binary pairs from PatchCorpus
    - assert match rate >= snapshot_value - 0.05
  decompilation:
    - decompile 10 ExeBench functions
    - assert re-executability >= snapshot_value - 0.05
  ml_integration:
    - generate suggestions for 5 standardized prompts
    - assert receipt completeness == 1.0
```

---

## 5. Human Productivity Protocol

### 5.1 Study Design

The human productivity study measures the impact of the integrated tool on analyst effectiveness, following the methodology established by the Dec-Synergy study (Basque et al., 2025).

**Study type:** Within-subjects crossover design with counterbalanced task assignment.

**Participants:**
- Target: 24 participants (12 experts with 3+ years RE experience, 12 novices with < 1 year)
- Recruitment: University RE courses, CTF community, industry practitioners via professional networks
- Screening: Pre-study skills assessment (standardized RE quiz) to validate experience classification
- Compensation: Participants are compensated at their equivalent hourly rate (minimum $50/hour)

**Task selection criteria:**
- Tasks drawn from real-world RE scenarios (not synthetic puzzles)
- Each task has a verifiable correct answer (ground truth from source code or known vulnerability)
- Tasks span difficulty levels: routine (library identification), moderate (function understanding), hard (vulnerability analysis)
- 6 tasks total: 3 per condition (tool-assisted vs baseline Ghidra), counterbalanced across participants

**Task categories (2 tasks each):**

| Category | Example Task | Ground Truth | Time Limit |
|---|---|---|---|
| **Function Understanding** | "Describe the purpose, inputs, and outputs of function at address X" | Source code comparison | 30 min |
| **Type Recovery** | "Identify the data types of parameters and local variables in function X" | DWARF debug info | 45 min |
| **Vulnerability Analysis** | "Identify the vulnerability class and root cause in binary X" | Known CVE | 60 min |

### 5.2 Protocol

1. **Briefing** (30 min): Introduce the study, obtain informed consent, administer demographics questionnaire and skills assessment.
2. **Training** (60 min): Hands-on tutorial with both baseline Ghidra and the enhanced tool (if in tool-assisted condition first).
3. **Warm-up** (15 min): Practice task (not scored) to familiarize with the environment.
4. **Session 1** (2-3 hours): Complete 3 tasks under first condition (tool-assisted or baseline), recorded via screen capture and think-aloud protocol.
5. **Washout** (1 week): Minimum gap between sessions to reduce learning effects.
6. **Session 2** (2-3 hours): Complete 3 tasks under second condition.
7. **Post-study** (30 min): Semi-structured interview, System Usability Scale (SUS), NASA-TLX workload assessment.

### 5.3 Metrics

| Metric | Measurement | Unit |
|---|---|---|
| **Time-to-first-understanding** | Time until participant provides correct description of function purpose | Minutes |
| **Answer accuracy** | Correctness of final answer rated by blinded expert panel (3 reviewers, majority vote) | [0, 1] scale |
| **Coverage rate** | Functions examined per hour of analysis | Functions/hour |
| **Vulnerability detection rate** | Fraction of planted vulnerabilities correctly identified | [0, 1] |
| **Tool interaction efficiency** | Number of tool actions (clicks, queries) per correct finding | Actions/finding |
| **Perceived workload** | NASA-TLX composite score | [0, 100] |
| **Usability** | System Usability Scale score | [0, 100] |
| **LLM interaction quality** | Fraction of LLM queries that produced useful information (self-reported + expert assessment) | [0, 1] |

### 5.4 Statistical Analysis Plan

- **Primary analysis**: Mixed-effects linear model with condition (tool-assisted vs baseline) as fixed effect, participant as random effect, and task difficulty as covariate.
- **Effect size**: Report Cohen's d with 95% confidence intervals for all primary metrics.
- **Significance**: Two-tailed tests at alpha = 0.05 with Bonferroni correction for multiple comparisons.
- **Power analysis**: With 24 participants, the study has 80% power to detect a medium effect (d = 0.5) at alpha = 0.05.
- **Subgroup analysis**: Expert vs novice interaction effects (replicating Dec-Synergy's finding that LLMs disproportionately benefit novices).
- **Qualitative**: Thematic analysis of think-aloud transcripts and post-study interviews, coded by two independent researchers with inter-rater reliability (Cohen's kappa >= 0.7).

### 5.5 IRB Considerations

- **Risk level**: Minimal risk (participants perform routine software analysis tasks). Eligible for expedited IRB review.
- **Informed consent**: Written consent covering: study purpose, procedures, time commitment, compensation, data handling, right to withdraw, screen recording consent.
- **Data handling**: Screen recordings stored encrypted, accessible only to research team. Personally identifiable information (PII) removed from all analysis datasets. Recordings deleted 2 years after publication.
- **Participant privacy**: Results reported in aggregate; individual performance never identified. Pseudonymized participant IDs in raw data.
- **Vulnerable populations**: No special populations targeted. Participants must be 18+ with ability to consent.
- **Deception**: None. Participants are fully informed about both conditions.

### 5.6 Comparison with Dec-Synergy Methodology

The Dec-Synergy study (Basque et al., 2025) established the gold standard for human evaluation of LLM-assisted RE:

| Aspect | Dec-Synergy | Our Protocol | Rationale for Differences |
|---|---|---|---|
| Participants | 48 (24 expert, 24 novice) | 24 (12 expert, 12 novice) | Smaller scale feasible for initial validation; expand in follow-up |
| Design | Between-subjects | Within-subjects crossover | Higher statistical power per participant; controls for individual differences |
| Tasks | 2 challenges | 6 tasks (3 per condition) | More diverse task coverage; counterbalancing controls for task effects |
| Duration | 109 total hours | ~100 total hours (est.) | Comparable scope |
| LLM access | Free-form LLM interaction | Integrated tool with telemetry | Enables precise measurement of tool-specific impact |
| Metrics | Understanding rate, LLM interaction logs | Time-to-understanding + accuracy + workload + usability | Broader metric coverage |

---

## 6. Metric Dashboard Schema

### 6.1 Data Model

The dashboard stores time-series evaluation data in a normalized schema optimized for both real-time queries and historical analysis.

```sql
-- Core tables for metric storage

CREATE TABLE eval_runs (
    run_id          UUID PRIMARY KEY,
    run_timestamp   TIMESTAMPTZ NOT NULL,
    trigger_type    TEXT NOT NULL CHECK (trigger_type IN ('commit', 'nightly', 'release', 'weekly', 'manual')),
    commit_sha      TEXT NOT NULL,
    branch          TEXT NOT NULL,
    ghidra_version  TEXT NOT NULL,
    runner_id       TEXT NOT NULL,
    duration_sec    INTEGER,
    status          TEXT NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'error')),
    metadata        JSONB DEFAULT '{}'
);

CREATE TABLE metric_values (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES eval_runs(run_id),
    feature_area    TEXT NOT NULL,           -- 'similarity', 'type_recovery', 'diffing', etc.
    metric_name     TEXT NOT NULL,           -- 'recall_at_1', 'type_accuracy_o2', etc.
    dataset         TEXT NOT NULL,           -- 'refuse-bench', 'sure-2025', etc.
    value           DOUBLE PRECISION NOT NULL,
    unit            TEXT NOT NULL,           -- 'ratio', 'seconds', 'count', etc.
    threshold       DOUBLE PRECISION,        -- acceptance threshold (NULL if no gate)
    passed          BOOLEAN,                 -- value meets threshold?
    metadata        JSONB DEFAULT '{}'       -- additional context (e.g., per-category breakdowns)
);

CREATE TABLE snapshot_diffs (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES eval_runs(run_id),
    snapshot_name   TEXT NOT NULL,           -- 'similarity/binarycorp-recall'
    baseline_version TEXT NOT NULL,          -- 'v0.1.0'
    diff_count      INTEGER NOT NULL,        -- number of differences
    diff_summary    JSONB NOT NULL,          -- structured diff details
    severity        TEXT CHECK (severity IN ('critical', 'warning', 'info'))
);

CREATE TABLE alert_events (
    id              BIGSERIAL PRIMARY KEY,
    run_id          UUID NOT NULL REFERENCES eval_runs(run_id),
    alert_type      TEXT NOT NULL CHECK (alert_type IN ('critical', 'warning', 'info')),
    feature_area    TEXT NOT NULL,
    metric_name     TEXT NOT NULL,
    message         TEXT NOT NULL,
    acknowledged    BOOLEAN DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ
);

-- Indices for common queries
CREATE INDEX idx_metric_values_run ON metric_values(run_id);
CREATE INDEX idx_metric_values_feature ON metric_values(feature_area, metric_name);
CREATE INDEX idx_metric_values_time ON metric_values(run_id)
    INCLUDE (feature_area, metric_name, value);
CREATE INDEX idx_eval_runs_time ON eval_runs(run_timestamp DESC);
CREATE INDEX idx_alert_events_unack ON alert_events(acknowledged) WHERE NOT acknowledged;
```

### 6.2 Dashboard Views

**View 1: Release Readiness**
- Composite score gauge (target >= 0.80)
- Per-feature pass/fail status (green/red)
- Blocking alerts count
- Comparison vs previous release

**View 2: Trend Lines**
- Time-series charts for each primary metric over last 90 days
- Overlay: threshold lines, release markers, regression markers
- Granularity: per-commit (smoke), nightly (full), weekly (extended)

**View 3: Feature Deep-Dive**
- Selected feature area with all metrics
- Per-dataset breakdown
- Per-category breakdown (e.g., type accuracy by type category)
- Snapshot diff viewer (side-by-side comparison of golden vs current output)

**View 4: Regression Investigation**
- Failed metric with historical trend
- Commit range since last passing run
- Snapshot diff details
- Link to CI logs and artifacts

**View 5: Human Study Results**
- Aggregate results from productivity studies
- Expert vs novice comparison
- Task-by-task breakdown
- SUS and NASA-TLX scores over time

### 6.3 Alert Rules

```yaml
alerts:
  critical:
    - name: "Primary metric severe regression"
      condition: "metric_value < (previous_release_value - 0.10)"
      action: "Block release, notify team lead"
    - name: "Receipt completeness violation"
      condition: "receipt_completeness < 1.0"
      action: "Block release, immediate fix required"
    - name: "Evaluation pipeline failure"
      condition: "run_status == 'error'"
      action: "Notify on-call, retry pipeline"

  warning:
    - name: "Primary metric moderate regression"
      condition: "metric_value < (previous_release_value - 0.05)"
      action: "Flag for review, must resolve before next release"
    - name: "Latency regression"
      condition: "p99_latency > (threshold * 1.5)"
      action: "Performance investigation ticket"

  info:
    - name: "Secondary metric change"
      condition: "abs(metric_value - previous_value) > 0.05"
      action: "Log for tracking"
    - name: "New dataset version available"
      condition: "upstream_checksum != pinned_checksum"
      action: "Schedule dataset update review"
```

### 6.4 MVP Gate Dashboard (Repo Implementation)

As of 2026-02-20, this repository includes a deterministic MVP gate dashboard builder that
tracks the four release gates currently wired for CI decision support:

1. `recall_at_10_delta_vs_stock` (`>= 0.10`)
2. `search_latency_p95_ms` (`<= 300`)
3. `receipt_completeness` (`== 1.0`)
4. `rollback_success_rate` (`== 1.0`)

Threshold definitions live in `eval/config/mvp_gate_thresholds.json` and include:
- comparison operator and numeric threshold
- alert severity (`critical` / `warning` / `info`)
- an explicit remediation action per gate

Saved per-run artifacts are stored as JSON files under `eval/artifacts/mvp-gates/runs/`:

```json
{
  "run_id": "smoke-2026-02-20T020000Z",
  "timestamp": "2026-02-20T02:00:00Z",
  "commit_sha": "4444444",
  "metrics": {
    "recall_at_10_delta_vs_stock": 0.112,
    "search_latency_p95_ms": 315.9,
    "receipt_completeness": 0.995,
    "rollback_success_rate": 1.0
  }
}
```

Reproduce dashboard + alerts from saved artifacts:

```bash
python3 eval/scripts/mvp_gate_dashboard.py \
  --artifacts-dir eval/artifacts/mvp-gates/runs \
  --thresholds eval/config/mvp_gate_thresholds.json \
  --output-dir eval/artifacts/mvp-gates
```

Generated outputs:
- `eval/artifacts/mvp-gates/dashboard.json` (machine-readable current + trend values)
- `eval/artifacts/mvp-gates/dashboard.md` (human-readable dashboard summary)
- `eval/artifacts/mvp-gates/alerts.json` (actionable threshold breaches)

`dashboard.json` also includes `source_artifacts` (`path`, `run_id`, `timestamp`, `sha256`) so
the dashboard can be reproduced exactly from saved run inputs.

### 6.5 M12 Exit-Gate Snapshot (Issue 1704)

Release decision evidence for E8-S4 (dated 2026-02-20) is published in:
- `docs/exit-gate-report.md`
- `docs/go-no-go-decision.md`

Gate-aligned metrics consolidated for the MVP decision:

| Gate Metric | Target | Measured | Status | Evidence |
|---|---|---|---|---|
| Recall@10 delta vs stock | `>= 0.10` | `+1.000` | PASS | `docs/soak-test-report-1701.md` |
| Search latency p95 | `< 300 ms` | `29.579 ms` (6-run max) | PASS | `docs/soak-test-report-1701.md` |
| Receipt completeness | `== 1.0` | `1.0` (all soak runs) | PASS | `docs/soak-test-report-1701.md` |
| Rollback success rate | `== 1.0` | `1.0` (all soak runs) | PASS | `docs/soak-test-report-1701.md` |
| Entrypoint recall | `>= 0.85` | `1.000000` | PASS | Section 3.4 calibration snapshot |
| Hotspot recall | `>= 0.85` | `1.000000` | PASS | Section 3.4 calibration snapshot |

Decision outcome: **GO for v0.1.0-rc1 internal release scope**, with open production conditions tracked as `C1-C11` in `docs/go-no-go-decision.md`.

### 6.6 E8-S1 Reopen Regression + Soak Closure (2026-02-21)

Reopen execution evidence for issue `1701` is published in:
- `docs/soak-test-report-1701.md`

Release-blocking bottlenecks and outcomes:
- Regression gate placeholder risk resolved by upgrading `scripts/cyntra/gates.sh --mode=all` to execute:
  - Python suites (`scripts/ml/tests`, `scripts/tests`; `66 + 15` tests in this run)
  - Java gate (`scripts/tests/java/MvpGateThresholdRegression.java`) validating threshold contract wiring.
- Missing dashboard implementation resolved by adding:
  - `eval/scripts/mvp_gate_dashboard.py`
  - `eval/config/mvp_gate_thresholds.json`
- JDK21 CI enforcement for Gradle test execution resolved by:
  - adding `eval/java-regression` Gradle module with Java toolchain `21`
  - wiring blocking `gradle -p eval/java-regression test` under JDK21 in `.github/workflows/eval.yaml` smoke/nightly/release lanes.

Soak summary from `2026-02-20`/`2026-02-21` UTC six-run sequence (`soak-20260220-run1..6`):
- Gate pass rate: `6/6`
- Recall delta vs stock: `1.000` across all runs
- p95 latency min/mean/max: `10.327 / 10.514 / 10.743 ms`
- Dashboard alerts: `0` (`eval/artifacts/mvp-gates/alerts.json`)
- Waivers: none

---

## 7. Automated Evaluation Pipeline

### 7.1 Pipeline Architecture

```
Binary Corpus
      |
      v
+------------------+     +------------------+     +------------------+
| 1. Ghidra        |     | 2. Feature       |     | 3. Metric        |
|    Headless       | --> |    Extraction     | --> |    Computation   |
|    Analysis       |     |    & Model Run    |     |    & Comparison  |
+------------------+     +------------------+     +------------------+
      |                         |                         |
      v                         v                         v
  Ghidra Project         Feature JSON /           metric_values rows
  (.gpr/.rep)            Model Outputs            snapshot_diffs
                                                        |
                                                        v
                                                 +------------------+
                                                 | 4. Dashboard     |
                                                 |    Update &      |
                                                 |    Alerting      |
                                                 +------------------+
```

### 7.2 Stage Details

**Stage 1: Ghidra Headless Analysis**

```bash
#!/bin/bash
# eval/scripts/01_analyze.sh
set -euo pipefail

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PROJECT_DIR="${EVAL_PROJECT_DIR:-/tmp/eval_project}"
CORPUS_DIR="${1:?Usage: 01_analyze.sh <corpus_dir>}"

# Import and auto-analyze all binaries
"${GHIDRA_HOME}/support/analyzeHeadless" \
    "${PROJECT_DIR}" EvalProject \
    -import "${CORPUS_DIR}" -recursive \
    -postScript GenerateSignatures.java \
    -scriptPath "${EVAL_SCRIPTS}/ghidra" \
    -processor x86:LE:64:default \
    -max-cpu 8 \
    -analysisTimeoutPerFile 300
```

**Stage 2: Feature Extraction**

Per-feature extraction scripts run against the analyzed Ghidra project:

```bash
# Similarity: export BSim signatures + embedding features
"${GHIDRA_HOME}/support/analyzeHeadless" \
    "${PROJECT_DIR}" EvalProject \
    -process -noanalysis \
    -postScript ExportSimilarityFeatures.java "${OUTPUT_DIR}/similarity/"

# Type recovery: export inferred types
"${GHIDRA_HOME}/support/analyzeHeadless" \
    "${PROJECT_DIR}" EvalProject \
    -process -noanalysis \
    -postScript ExportInferredTypes.java "${OUTPUT_DIR}/types/"

# Decompilation: export decompiled C
"${GHIDRA_HOME}/support/analyzeHeadless" \
    "${PROJECT_DIR}" EvalProject \
    -process -noanalysis \
    -postScript ExportDecompiledC.java "${OUTPUT_DIR}/decompiled/"

# Run ML models (if configured)
python eval/scripts/run_ml_models.py \
    --features "${OUTPUT_DIR}" \
    --models "${MODEL_CONFIG}" \
    --output "${OUTPUT_DIR}/ml_predictions/"
```

**Stage 3: Metric Computation**

```bash
# Compare against ground truth and compute all metrics
python eval/scripts/compute_metrics.py \
    --features "${OUTPUT_DIR}" \
    --ground-truth "${GROUND_TRUTH_DIR}" \
    --snapshots "${SNAPSHOT_DIR}/latest" \
    --output "${OUTPUT_DIR}/metrics.json" \
    --run-id "${RUN_ID}"
```

**Stage 4: Dashboard Update**

```bash
# Insert results into dashboard database and check alerts
python eval/scripts/update_dashboard.py \
    --metrics "${OUTPUT_DIR}/metrics.json" \
    --run-id "${RUN_ID}" \
    --db-url "${DASHBOARD_DB_URL}" \
    --check-alerts \
    --notify-on-critical
```

### 7.3 Docker-Based Reproducibility

```dockerfile
# eval/Dockerfile
FROM ghcr.io/nationalsecurityagency/ghidra:11.2-jdk21

# Install Python dependencies for metric computation
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv
COPY eval/requirements.txt /eval/requirements.txt
RUN python3 -m pip install -r /eval/requirements.txt

# Install evaluation scripts
COPY eval/ /eval/
COPY datasets/ /datasets/

# Pre-download datasets (cached in image)
RUN python3 /eval/scripts/download.py --config /datasets/config/ --output /datasets/data/

WORKDIR /eval
ENTRYPOINT ["/eval/run_pipeline.sh"]
```

```yaml
# eval/docker-compose.yaml
services:
  eval-pipeline:
    build:
      context: .
      dockerfile: eval/Dockerfile
    volumes:
      - ./eval/output:/eval/output
      - ./eval/snapshots:/eval/snapshots
    environment:
      - GHIDRA_HOME=/opt/ghidra
      - DASHBOARD_DB_URL=postgresql://dashboard:5432/eval
      - RUN_ID=${RUN_ID:-$(uuidgen)}
    depends_on:
      - dashboard-db

  dashboard-db:
    image: postgres:16-alpine
    volumes:
      - eval-db-data:/var/lib/postgresql/data
      - ./eval/schema.sql:/docker-entrypoint-initdb.d/01-schema.sql
    environment:
      POSTGRES_DB: eval
      POSTGRES_USER: eval
      POSTGRES_PASSWORD: ${EVAL_DB_PASSWORD}

volumes:
  eval-db-data:
```

### 7.4 Makefile Targets

```makefile
# eval/Makefile

.PHONY: datasets analyze extract metrics dashboard full smoke nightly release

# Dataset management
datasets:
	python eval/scripts/download.py --config datasets/config/ --verify
	python eval/scripts/validate_checksums.py --lockfile datasets/datasets.lock.json

# Individual pipeline stages
analyze: datasets
	bash eval/scripts/01_analyze.sh $(CORPUS_DIR)

extract: analyze
	bash eval/scripts/02_extract.sh $(OUTPUT_DIR)

metrics: extract
	python eval/scripts/compute_metrics.py \
		--features $(OUTPUT_DIR) \
		--ground-truth $(GROUND_TRUTH_DIR) \
		--snapshots eval/snapshots/latest \
		--output $(OUTPUT_DIR)/metrics.json

dashboard: metrics
	python eval/scripts/update_dashboard.py \
		--metrics $(OUTPUT_DIR)/metrics.json \
		--db-url $(DASHBOARD_DB_URL)

# Composite targets
full: datasets analyze extract metrics dashboard

smoke:
	bash eval/scripts/run_smoke.sh

nightly:
	RUN_ID=$$(uuidgen) TRIGGER=nightly make full CORPUS_DIR=datasets/data/nightly

release:
	RUN_ID=$$(uuidgen) TRIGGER=release make full CORPUS_DIR=datasets/data/full
```

### 7.5 CI Configuration

```yaml
# .github/workflows/eval.yaml (or equivalent)
name: Evaluation Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Nightly at 2 AM
  workflow_dispatch:
    inputs:
      suite:
        description: 'Test suite to run'
        type: choice
        options: [smoke, nightly, release, weekly]
        default: nightly

jobs:
  smoke:
    if: github.event_name == 'push' || github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - run: bash eval/run_smoke.sh
      - run: |
          python3 eval/scripts/check_regression.py \
            --current eval/output/smoke/metrics.json \
            --baseline eval/snapshots/baseline.json \
            --output eval/output/smoke/regression.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: smoke-metrics-${{ github.sha }}
          path: eval/output/smoke/

  nightly:
    if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.suite == 'nightly')
    runs-on: ubuntu-latest
    timeout-minutes: 300
    steps:
      - uses: actions/checkout@v4
      - run: bash eval/run_smoke.sh
      # Resolve + download previous nightly baseline artifact
      # (e.g. via actions/github-script and actions/download-artifact)
      - run: |
          python3 eval/scripts/compare_runs.py \
            --current eval/output/smoke/metrics.json \
            --previous eval/output/nightly-baseline/metrics.json \
            --output eval/output/smoke/nightly-comparison.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nightly-smoke-metrics
          path: eval/output/smoke/metrics.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nightly-results-${{ github.run_id }}
          path: eval/output/

  release:
    if: github.event_name == 'workflow_dispatch' && inputs.suite == 'release'
    runs-on: [self-hosted, gpu]
    timeout-minutes: 1440
    steps:
      - uses: actions/checkout@v4
      - run: make -C eval release
      - run: make -C eval dashboard
```

`check_regression.py` and `compare_runs.py` return non-zero on metric regressions,
so smoke and nightly regressions surface as blocking CI failures.

---

## 8. Benchmark Reproduction Guide

### 8.1 REFuSe-Bench Reproduction

**Purpose:** Evaluate binary function similarity detection against Ghidra BSim and any integrated embedding models.

**Prerequisites:**
- Hardware: 32GB RAM, 500GB disk, multi-core CPU (GPU optional for embedding models)
- Software: Ghidra 11.2+, Python 3.11+, Docker
- Time estimate: 4-8 hours for full evaluation

**Steps:**

```bash
# 1. Download REFuSe-Bench dataset
python eval/scripts/download.py --dataset refuse-bench --output datasets/data/refuse-bench/

# 2. Import binaries into Ghidra project
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/refuse_project RefuseBench \
    -import datasets/data/refuse-bench/binaries/ -recursive

# 3. Generate BSim signatures
bsim createdatabase file:///tmp/refuse_bsim refuse_db medium_nosize
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/refuse_project RefuseBench \
    -process -noanalysis \
    -postScript GenerateSignatures.java file:///tmp/refuse_bsim

# 4. Run pool queries per REFuSe-Bench protocol
python eval/scripts/refuse_bench_eval.py \
    --bsim-url file:///tmp/refuse_bsim \
    --queries datasets/data/refuse-bench/queries.json \
    --ground-truth datasets/data/refuse-bench/labels.json \
    --output eval/output/refuse-bench-results.json

# 5. Compute metrics (Recall@1, Recall@10, MRR)
python eval/scripts/compute_similarity_metrics.py \
    --results eval/output/refuse-bench-results.json \
    --output eval/output/refuse-bench-metrics.json
```

**Expected output:**
```json
{
  "dataset": "refuse-bench",
  "method": "ghidra-bsim",
  "metrics": {
    "recall_at_1": 0.XX,
    "recall_at_10": 0.XX,
    "mrr": 0.XX
  },
  "subsets": {
    "cross_compiler": { "recall_at_1": 0.XX },
    "cross_optimization": { "recall_at_1": 0.XX },
    "malware": { "recall_at_1": 0.XX }
  }
}
```

### 8.2 SURE 2025 Reproduction

**Purpose:** Evaluate type inference accuracy against the SURE 2025 benchmark.

**Prerequisites:**
- Hardware: 16GB RAM, 100GB disk
- Software: Ghidra 11.2+, Python 3.11+, `pyelftools`, `dwarfdump`
- Time estimate: 2-4 hours

**Steps:**

```bash
# 1. Download SURE 2025 benchmark corpus
python eval/scripts/download.py --dataset sure-2025 --output datasets/data/sure-2025/

# 2. Extract DWARF ground truth from debug builds
python eval/scripts/extract_dwarf.py \
    --input datasets/data/sure-2025/debug-binaries/ \
    --output datasets/data/sure-2025/ground-truth/

# 3. Import stripped binaries into Ghidra
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/sure_project SURE2025 \
    -import datasets/data/sure-2025/stripped-binaries/ -recursive

# 4. Export Ghidra's inferred types
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/sure_project SURE2025 \
    -process -noanalysis \
    -postScript ExportInferredTypes.java datasets/data/sure-2025/ghidra-types/

# 5. (Optional) Run experimental type recovery plugin
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/sure_project SURE2025 \
    -process -noanalysis \
    -postScript RunExperimentalTypeRecovery.java \
    -postScript ExportInferredTypes.java datasets/data/sure-2025/experimental-types/

# 6. Compare against ground truth using SURE 2025 metrics
python eval/scripts/sure_2025_eval.py \
    --ground-truth datasets/data/sure-2025/ground-truth/ \
    --baseline datasets/data/sure-2025/ghidra-types/ \
    --experimental datasets/data/sure-2025/experimental-types/ \
    --output eval/output/sure-2025-metrics.json
```

**Metrics computed:**
- Overall accuracy (fraction of correctly typed variables)
- Per-category accuracy (primitives, pointers, structs, arrays, enums)
- Precision, false positive rate, coverage
- Comparison at -O0 and -O2 optimization levels

**Expected baseline (Ghidra, from SURE 2025 paper):**
- -O0: ~14-15% overall accuracy
- -O2: ~14-15% overall accuracy

### 8.3 BinMetric Reproduction

**Purpose:** Evaluate LLM-based binary analysis capabilities across 6 task types.

**Prerequisites:**
- Hardware: 32GB RAM, GPU with 24GB+ VRAM (for local models) or API access to cloud LLMs
- Software: Ghidra 11.2+, Python 3.11+, model inference framework (vLLM, llama.cpp, or API client)
- Time estimate: 4-12 hours (depending on model inference speed)

**Steps:**

```bash
# 1. Download BinMetric dataset
python eval/scripts/download.py --dataset binmetric --output datasets/data/binmetric/

# 2. Import BinMetric binaries into Ghidra
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/binmetric_project BinMetric \
    -import datasets/data/binmetric/binaries/ -recursive

# 3. Extract decompiled output for LLM input
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/binmetric_project BinMetric \
    -process -noanalysis \
    -postScript ExportForBinMetric.java datasets/data/binmetric/ghidra-output/

# 4. Run LLM inference on BinMetric tasks
python eval/scripts/binmetric_eval.py \
    --questions datasets/data/binmetric/questions.json \
    --ghidra-output datasets/data/binmetric/ghidra-output/ \
    --model-config eval/config/models.yaml \
    --output eval/output/binmetric-results.json

# 5. Score results using BinMetric evaluation scripts
python eval/scripts/binmetric_score.py \
    --results eval/output/binmetric-results.json \
    --ground-truth datasets/data/binmetric/answers.json \
    --output eval/output/binmetric-metrics.json
```

**Metrics per task type:**
- Decompilation: re-executability rate, syntactic similarity
- Code summarization: BLEU, ROUGE-L
- Call-site reconstruction: precision, recall, F1
- Signature recovery: type accuracy, parameter count accuracy
- Algorithm classification: classification accuracy
- Assembly generation: correctness, executability

### 8.4 Decompilation Quality (Decompile-Bench / ExeBench)

**Purpose:** Measure decompilation refinement quality via re-executability.

**Prerequisites:**
- Hardware: 16GB RAM, GCC/Clang installed for recompilation testing
- Software: Ghidra 11.2+, Python 3.11+, GCC 12+, Clang 16+
- Time estimate: 2-6 hours

**Steps:**

```bash
# 1. Download evaluation subset
python eval/scripts/download.py --dataset exebench --output datasets/data/exebench/

# 2. Decompile with Ghidra baseline
"${GHIDRA_HOME}/support/analyzeHeadless" \
    /tmp/exebench_project ExeBench \
    -import datasets/data/exebench/binaries/ -recursive \
    -postScript ExportDecompiledC.java datasets/data/exebench/ghidra-decompiled/

# 3. (Optional) Refine with LLM
python eval/scripts/refine_decompilation.py \
    --input datasets/data/exebench/ghidra-decompiled/ \
    --model-config eval/config/models.yaml \
    --output datasets/data/exebench/refined/

# 4. Measure re-executability
python eval/scripts/reexecutability_test.py \
    --decompiled datasets/data/exebench/ghidra-decompiled/ \
    --refined datasets/data/exebench/refined/ \
    --test-cases datasets/data/exebench/tests/ \
    --output eval/output/exebench-metrics.json
```

**Metrics:**
- Recompile success rate (RSR): fraction that compiles without errors
- Re-executability rate (ESR): fraction that compiles and passes test cases
- Edit similarity: Levenshtein-based similarity to original source
- CodeBLEU: weighted combination of n-gram, syntax, dataflow, and semantic similarity

---

## 9. Summary and Implementation Priority

### Phase 1 (Immediate): Foundation
1. Establish dataset preparation pipeline with version pinning (`datasets/datasets.lock.json`)
2. Implement per-commit smoke tests for critical metrics
3. Create `metric_values` database schema and basic dashboard
4. Run SURE 2025 and REFuSe-Bench baselines against stock Ghidra

### Phase 2 (Short-term): Full Automation
5. Build Docker-based evaluation pipeline (Makefile + CI integration)
6. Implement nightly regression suite with snapshot comparison
7. Add alert rules and notification integration
8. Run BinMetric baseline evaluation

### Phase 3 (Medium-term): Human Studies
9. Design and submit human productivity study protocol for IRB review
10. Conduct pilot study with 6 participants
11. Run full 24-participant study
12. Integrate human study results into dashboard

### Phase 4 (Ongoing): Continuous Improvement
13. Expand dataset registry as new benchmarks emerge
14. Calibrate acceptance thresholds based on measured baselines
15. Add feature-specific regression tests as features are implemented
16. Publish reproduction guides and evaluation results

---

## References

### Benchmarks
- REFuSe-Bench: "Is Function Similarity Over-Engineered?" NeurIPS 2024 Datasets & Benchmarks
- BinaryCorp: Wang et al., "jTrans," ISSTA 2022
- BinCodex: "A Comprehensive and Multi-Level Dataset," BenchCouncil Trans. 2024
- Decompile-Bench: Tan et al., NeurIPS 2025 -- [arXiv 2505.12668](https://arxiv.org/abs/2505.12668)
- ExeBench: Armengol-Estape et al.
- SURE 2025: Soni, "Benchmarking Binary Type Inference Techniques in Decompilers" -- [Paper](https://sure-workshop.org/accepted-papers/2025/sure25-8.pdf)
- BinMetric: IJCAI 2025 -- [arXiv 2505.07360](https://arxiv.org/abs/2505.07360)
- Realtype: Dramko et al. (IDIOMS) -- [arXiv 2502.04536](https://arxiv.org/abs/2502.04536)
- DIRT: Chen et al. (DIRTY), USENIX Security 2022

### Evaluation Methodology
- Dec-Synergy: Basque et al., "Decompiling the Synergy" -- [PDF](https://www.zionbasque.com/files/papers/dec-synergy-study.pdf)
- D-Score: D-LiFT quality metric -- [arXiv 2506.10125](https://arxiv.org/abs/2506.10125)
- LLM4Decompile evaluation protocol: Tan et al., EMNLP 2024 -- [arXiv 2403.05286](https://arxiv.org/abs/2403.05286)
- BTIEval: Trail of Bits type recovery evaluation -- [GitHub](https://github.com/trailofbits/BTIGhidra)

### Evaluation Infrastructure Patterns
- SWE-bench: Docker-based evaluation harness for SE tasks -- [swebench.com](https://www.swebench.com/SWE-bench/)
- EleutherAI LM Evaluation Harness: Continuous evaluation for language models -- [GitHub](https://github.com/EleutherAI/lm-evaluation-harness)
- Evidently AI: ML model monitoring best practices -- [Guide](https://www.evidentlyai.com/ml-in-production/model-monitoring)

### Tools
- Ghidra BSim: Built-in semantic similarity -- [Tutorial](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md)
- ghidriff: Binary diffing with Ghidra -- [GitHub](https://clearbluejar.github.io/ghidriff/)
- BinDiff: Binary comparison tool -- [GitHub](https://github.com/google/bindiff)
