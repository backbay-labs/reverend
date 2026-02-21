<p align="center">
  <img src="docs/assets/reverend-hero.png" alt="Reverend hero banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/reverend/actions/workflows/eval.yaml"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/reverend/eval.yaml?branch=main&style=flat-square&logo=github&label=eval-gates" alt="Eval Gates" /></a>
  <img src="https://img.shields.io/badge/JDK-21-22D3EE?style=flat-square&logo=openjdk&logoColor=white&labelColor=02040A" alt="JDK 21" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-8B5CF6?style=flat-square&logo=python&logoColor=white&labelColor=02040A" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/License-Apache--2.0-64748B?style=flat-square&labelColor=02040A" alt="Apache 2.0 License" />
</p>

<h1 align="center">Reverend</h1>

<p align="center">
  <em>Evidence-backed reverse engineering on top of Ghidra.</em>
</p>

<p align="center">
  <a href="#why-reverend">Why Reverend</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#architecture">Architecture</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#run-locally">Run Locally</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#implemented-subsystems">Implemented Subsystems</a>
</p>

<p align="center">
  <img src="docs/assets/reverend-divider.svg" alt="divider" width="82%" />
</p>

## Why Reverend

Stock Ghidra gives world-class interactive analysis. Reverend adds a **governed automation layer** so agentic workflows are testable, reviewable, and policy-enforced.

| Capability | Upstream Ghidra | Reverend |
| --- | --- | --- |
| Agent operation guardrails | Manual conventions | Capability-token enforcement + scope limits (`ghidra.security.capability.*`) |
| Network egress controls | External/proxy-only controls | Built-in policy modes: `OFFLINE`, `ALLOWLIST`, `CLOUD` (`ghidra.security.policy.*`) |
| Structured proposal lifecycle | Ad-hoc comments/scripts | Proposal state machine with review transitions (`ghidra.security.proposal.*`) |
| Security/audit event model | Generic logging | Typed audit + violation incident records (`ghidra.security.audit.*`) |
| Deterministic CI gate stack | Project-defined | Smoke/soak/regression + security compile/evidence gates (`scripts/cyntra/gates.sh`) |
| Receipt integrity primitives | N/A | Append-only hash-chain receipt store (`scripts/ml/receipt_store.py`) |

## Architecture

```mermaid
flowchart LR
    A["Binary Intake"] --> B["Ghidra Core Analysis"]
    B --> C["Proposal Service (ghidra.security.proposal)"]
    C --> D["Review and Apply"]

    D --> E["Audit and Violations (ghidra.security.audit)"]
    D --> F["Receipt Chain (scripts/ml/receipt_store.py)"]

    B --> G["Semantic and Triage Pipelines (scripts/ml/local_embedding_pipeline.py)"]
    G --> C

    H["Capability and Egress Policy (ghidra.security.capability/policy)"] --> C
    H --> G

    I["Quality Gates (scripts/cyntra and eval)"] --> H
    I --> G
    I --> F
```

## Implemented Subsystems

### 1) Security Control Plane (Java)

- Capability tokens, scopes, expiry, mutation limits: `Ghidra/Framework/Generic/src/main/java/ghidra/security/capability/`
- Egress policy and endpoint/rate/payload enforcement: `Ghidra/Framework/Generic/src/main/java/ghidra/security/policy/`
- Audit events and violation incident records (in-memory + file-backed): `Ghidra/Framework/Generic/src/main/java/ghidra/security/audit/`

### 2) Proposal and Review Lifecycle (Java)

- Proposal model, deltas, reviews, lifecycle states: `Ghidra/Framework/Generic/src/main/java/ghidra/security/proposal/`
- Service orchestration for submit/review/apply transitions: `Ghidra/Framework/Generic/src/main/java/ghidra/security/proposal/ProposalService.java`

### 3) Retrieval, Triage, and Corpus Sync (Python)

- Local embedding/search/triage CLI and fixtures: `scripts/ml/local_embedding_pipeline.py`, `scripts/ml/fixtures/`
- Append-only receipt hash-chain integrity: `scripts/ml/receipt_store.py`
- Approved-only corpus sync worker with policy/provenance checks: `scripts/ml/corpus_sync_worker.py`

### 4) Evaluation + Release Gates

- Smoke/soak/regression harness: `eval/run_smoke.sh`, `eval/run_soak.sh`, `eval/scripts/`
- Threshold dashboard and baseline configs: `eval/scripts/mvp_gate_dashboard.py`, `eval/config/mvp_gate_thresholds.json`
- Kernel/CI gate runner (context, diff, Java, evidence integrity): `scripts/cyntra/gates.sh`

## Run Locally

### Prerequisites

- Python `>= 3.11`
- JDK `21` (`java` and `javac` both on 21)
- Gradle (or `./gradlew`)

### Build + Validate

```bash
# Fetch build dependencies
gradle -I gradle/support/fetchDependencies.gradle

# Strict env/context/toolchain preflight
scripts/cyntra/preflight.sh

# Compile + security module tests
./gradlew --no-daemon :Generic:compileJava
./gradlew --no-daemon :Generic:test --tests "ghidra.security.*"
python3 scripts/cyntra/check-junit-failures.py --results-dir Ghidra/Framework/Generic/build/test-results/test

# Full deterministic gate stack
CYNTRA_GATE_ISSUE_ID=1704 bash scripts/cyntra/gates.sh --mode=all

# Roadmap/evidence consistency validator
scripts/cyntra/validate-roadmap-completion.sh

# Build distribution
./gradlew --no-daemon buildGhidra
```

### Headless Smoke From Built Distribution

```bash
mkdir -p build/dist/_smoke
unzip -q -o build/dist/ghidra_*_mac_arm_64.zip -d build/dist/_smoke
build/dist/_smoke/ghidra_12.1_DEV/support/analyzeHeadless -help
```

## Optional: Cyntra Automation

If you want autonomous workcell execution over the bead backlog:

```bash
scripts/cyntra/bootstrap.sh
scripts/cyntra/run-once.sh
scripts/cyntra/run-watch.sh
scripts/cyntra/cyntra.sh status
```

Operational details: `docs/cyntra-kernel-runbook.md`.

## Key Evidence and Decision Docs

- Exit-gate report: `docs/exit-gate-report.md`
- Formal decision record: `docs/go-no-go-decision.md`
- Security signoff + abuse scenarios: `docs/security/`
- RC functional validation packet: `docs/evidence/rc-functional-validation/`

## Remotes

- `origin`: `git@github.com:backbay-labs/reverend.git`
- `upstream`: `git@github.com:NationalSecurityAgency/ghidra.git`

Reverend keeps upstream compatibility where practical while adding controlled autonomous-analysis primitives for team-scale reverse engineering.
