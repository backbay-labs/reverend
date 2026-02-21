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
