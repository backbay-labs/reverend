<p align="center">
  <img src="docs/assets/reverend-hero.png" alt="Reverend hero banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/backbay-labs/reverend/actions/workflows/eval.yaml"><img src="https://img.shields.io/github/actions/workflow/status/backbay-labs/reverend/eval.yaml?branch=main&style=flat-square&logo=github&label=eval-gates" alt="Eval Gates" /></a>
  <img src="https://img.shields.io/badge/status-RC1-22D3EE?style=flat-square&labelColor=02040A" alt="Status RC1" />
  <img src="https://img.shields.io/badge/roadmap-48%2F48_done-10B981?style=flat-square&labelColor=02040A" alt="Roadmap 48/48 done" />
  <img src="https://img.shields.io/badge/security-GA_conditional-F43F5E?style=flat-square&labelColor=02040A" alt="Security GA conditional" />
  <img src="https://img.shields.io/badge/JDK-21-22D3EE?style=flat-square&logo=openjdk&logoColor=white&labelColor=02040A" alt="JDK 21" />
  <img src="https://img.shields.io/badge/Python-3.11%2B-8B5CF6?style=flat-square&logo=python&logoColor=white&labelColor=02040A" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/license-Apache--2.0-64748B?style=flat-square&labelColor=02040A" alt="Apache 2.0 License" />
</p>

<h1 align="center">Reverend</h1>

<p align="center">
  <em>Command the binary. Verify every claim.</em>
</p>

<p align="center">
  <a href="#overview">Overview</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#quick-start">Quick Start</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#cyntra-kernel-operations">Cyntra Operations</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="#program-status">Program Status</a>
  <span>&nbsp;&middot;&nbsp;</span>
  <a href="docs/cyntra-kernel-runbook.md">Runbook</a>
</p>

---

## Overview

Reverend is a production-oriented Ghidra fork focused on evidence-backed, agent-assisted reverse engineering.

It combines:
- Upstream-compatible Ghidra core build and distribution flow
- Reverend workflow primitives (proposal, receipt, security, eval)
- Cyntra kernel automation (beads backlog plus workcell orchestration)

### What Reverend Adds

- **Evidence-backed proposals** for rename/type/comment operations
- **Security controls** for agent operations (`CapabilityGuard`, policy modes, audit trails)
- **Deterministic evaluation** harnesses (smoke, soak, regression thresholds)
- **Kernel-native execution** through Cyntra workcells and bead dependencies

## Program Status

| Area | Current State | Source |
| --- | --- | --- |
| Roadmap Scope | Complete (`48/48` rows done) | `docs/execution-board-12-weeks.md` |
| Exit Gate Packet | Published | `docs/exit-gate-report.md` |
| Formal Decision | RC `GO`, GA conditional | `docs/go-no-go-decision.md` |
| Security Evidence | Abuse-scenario suites + checksums | `docs/security/` |

GA remains conditional until production criteria `C1-C11` are closed.

## Quick Start

```bash
# 1) Fetch build dependencies
gradle -I gradle/support/fetchDependencies.gradle

# 2) Validate environment + context (strict)
scripts/cyntra/preflight.sh

# 3) Run full gate stack (quality + security + eval)
CYNTRA_GATE_ISSUE_ID=1704 bash scripts/cyntra/gates.sh --mode=all

# 4) Verify roadmap closure + evidence integrity
scripts/cyntra/validate-roadmap-completion.sh

# 5) Build a local distribution
./gradlew --no-daemon buildGhidra
```

Build artifacts are written to `build/dist/`.

## Cyntra Kernel Operations

```bash
scripts/cyntra/bootstrap.sh
scripts/cyntra/preflight.sh
scripts/cyntra/run-once.sh
scripts/cyntra/run-watch.sh
scripts/cyntra/cyntra.sh status
```

Detailed operator workflow: `docs/cyntra-kernel-runbook.md`.

## Local Runtime Smoke

After building, validate headless startup from the generated distribution:

```bash
mkdir -p build/dist/_smoke
unzip -q -o build/dist/ghidra_*_mac_arm_64.zip -d build/dist/_smoke
build/dist/_smoke/ghidra_12.1_DEV/support/analyzeHeadless -help
```

Full RC validation artifacts are tracked in:
- `docs/evidence/rc-functional-validation/`

## Repository Map

- `Ghidra/` - Framework, features, processors, plugins
- `scripts/cyntra/` - Preflight, gates, backlog sync, dispatch wrappers
- `eval/` - Smoke/soak/regression harnesses and thresholds
- `docs/` - Execution board, security signoff, evidence, runbooks
- `.beads/` - Canonical backlog graph (`issues.jsonl`, `deps.jsonl`)

## Upstream and Remotes

- `origin`: `git@github.com:backbay-labs/reverend.git`
- `upstream`: `git@github.com:NationalSecurityAgency/ghidra.git`

Reverend maintains practical upstream compatibility while layering autonomous analysis and governance workflows for team-scale reverse engineering.
