<p align="center">
  <img src="docs/assets/reverend-hero.png" alt="Reverend hero banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/reverend/actions/workflows/eval.yaml">
    <img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/reverend/eval.yaml?branch=main&style=for-the-badge&label=Eval%20Gates&labelColor=02040A" alt="Eval Gates" />
  </a>
  <img src="https://img.shields.io/badge/Status-RC1-22D3EE?style=for-the-badge&labelColor=02040A" alt="Status RC1" />
  <img src="https://img.shields.io/badge/Roadmap-48%2F48%20Done-10B981?style=for-the-badge&labelColor=02040A" alt="Roadmap 48/48 Done" />
  <img src="https://img.shields.io/badge/Security-GA%20Conditional-F43F5E?style=for-the-badge&labelColor=02040A" alt="Security GA Conditional" />
  <img src="https://img.shields.io/badge/JDK-21-22D3EE?style=for-the-badge&logo=openjdk&logoColor=white&labelColor=02040A" alt="JDK 21" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-8B5CF6?style=for-the-badge&logo=python&logoColor=white&labelColor=02040A" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/License-Apache--2.0-64748B?style=for-the-badge&labelColor=02040A" alt="Apache 2.0 License" />
</p>

# Reverend

Reverend is a production-oriented Ghidra fork focused on evidence-backed, agent-assisted reverse engineering.

This repo combines:
- Ghidra core (upstream-compatible build/distribution flow)
- Reverend workflow primitives (proposal/receipt/security/eval layers)
- Cyntra kernel automation (beads backlog + workcell orchestration)

## What Reverend Adds

- Evidence-backed proposal workflow for rename/type/comment operations
- Security controls for agent operations (`CapabilityGuard`, policy modes, audit trails)
- Deterministic evaluation harnesses (smoke, soak, regression thresholds)
- Kernel-native execution model via Cyntra workcells and bead dependencies

## Current Program State

- RC roadmap scope: complete (`48/48` roadmap rows done)
- MVP exit-gate artifacts: `docs/exit-gate-report.md`, `docs/go-no-go-decision.md`
- GA posture: still conditional until production criteria in `C1-C11` are closed

## Repository Map

- `Ghidra/` - Ghidra framework, features, processors, and plugins
- `scripts/cyntra/` - preflight, gates, backlog sync, dispatch wrappers
- `eval/` - smoke/soak/regression harnesses and thresholds
- `docs/` - execution board, security signoff, evidence, operator runbooks
- `.beads/` - canonical roadmap/backlog graph (`issues.jsonl`, `deps.jsonl`)

## Prerequisites

- Python `>= 3.11`
- JDK `21` (`java` and `javac` both on 21)
- Gradle (or `./gradlew` wrapper)

## Quick Start

```bash
# 1) fetch build dependencies once
gradle -I gradle/support/fetchDependencies.gradle

# 2) strict environment + context validation
scripts/cyntra/preflight.sh

# 3) run full quality/security/eval gate stack
CYNTRA_GATE_ISSUE_ID=1704 bash scripts/cyntra/gates.sh --mode=all

# 4) verify roadmap closure + evidence integrity
scripts/cyntra/validate-roadmap-completion.sh

# 5) build a local distribution
./gradlew --no-daemon buildGhidra
```

Build artifacts are written to `build/dist/`.

## Cyntra Operations

```bash
scripts/cyntra/bootstrap.sh
scripts/cyntra/preflight.sh
scripts/cyntra/run-once.sh
scripts/cyntra/run-watch.sh
scripts/cyntra/cyntra.sh status
```

Kernel operating details: `docs/cyntra-kernel-runbook.md`.

## Local Runtime Smoke

After building, headless sanity can be validated from the distribution zip:

```bash
mkdir -p build/dist/_smoke
unzip -q -o build/dist/ghidra_*_mac_arm_64.zip -d build/dist/_smoke
build/dist/_smoke/ghidra_12.1_DEV/support/analyzeHeadless -help
```

A full RC functional validation bundle is tracked at:
- `docs/evidence/rc-functional-validation/`

## Upstream

- `origin`: `git@github.com:backbay-labs/reverend.git`
- `upstream`: `git@github.com:NationalSecurityAgency/ghidra.git`

Reverend keeps upstream Ghidra compatibility where practical while layering autonomous analysis and governance workflows for team-scale reverse engineering.
