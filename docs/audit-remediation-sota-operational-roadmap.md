# Audit Remediation + SOTA Operationalization Roadmap (E20-E21)

## Goal
Close all audit findings from the 2026-02-22 comprehensive review, converge split worktrees, and deliver an operational "SOTA assistant inside Ghidra" with clean builds, deterministic gates, production wiring, and end-to-end validation artifacts.

## Scope
- Fix hard build breakages and gate blind spots in the active tree (`reverend`).
- Resolve known compile blockers in the integrated tree (`reverend-main`) before sync.
- Replace cockpit stub-service fallback with live service wiring.
- Make gate/runtime behavior deterministic and auditable (including kernel completion integrity).
- Ship indexed, non-O(N), evidence-backed query flows and end-to-end mission integration.

## Finding-to-Bead Mapping
| Finding | Bead | Expected Output |
|---|---|---|
| `:Reverend` compile break (`Icons.SEARCH_ICON`) | `3101` | `:Reverend:compileJava` + `:Reverend:test` pass |
| Gate/CI misses plugin/module breakages | `3102` | Expanded local + CI compile/test scope |
| Cockpit is stubbed by default | `3103` | Production service bootstrap and runtime wiring |
| Python gate non-self-contained (`pytest`) | `3104` | Deterministic Python gate deps and test runner parity |
| `reverend-main` compile blockers pending | `3105` | TraceModeling/Semantic cockpit compile fixes landed |
| Hash-collision-prone cache keys | `3106` | Stable digest-based cache keys and regression tests |
| Roadmap/docs/CSV drift | `3107` | Single-source reconciliation + CI enforcement |
| Kernel zero-diff completion integrity gap | `3108` | No-op policy/justification gate + telemetry checks |
| Worktree divergence (`master` vs `main`) | `3109` | Repeatable sync/convergence playbook and checks |
| O(N) heuristic query path and TODO embedding gap | `3201-3204` | Indexed retrieval + embedding-backed ranking |
| Weak Java<->Python mission integration | `3205` | End-to-end cockpit-to-mission operational flow |
| "Operational" claim not benchmark/gate-backed | `3206-3208` | Benchmark-gated release packet and runbook |

## Epic E20: Audit Closure + Delivery Integrity (`3100`)
Stories: `3101-3109`

Execution order:
1. `3101`, `3104`, `3105` start in parallel.
2. `3102`, `3103`, `3106`, `3109` once blockers close.
3. `3107`, `3108` after gate stack hardening.

## Epic E21: SOTA Assistant Operationalization (`3200`)
Stories: `3201-3208`

Execution order:
1. Build indexed and collision-safe query core (`3201-3204`).
2. Wire cockpit to missions/receipts (`3205`).
3. Enforce benchmark gates and publish local operator path (`3206-3207`).
4. Publish GA packet with reproducible evidence (`3208`).

## Required Verification Gates
- `./gradlew --no-daemon :Reverend:compileJava :Reverend:test --tests "ghidra.reverend.*"`
- `./gradlew --no-daemon :Generic:compileJava :Generic:test --tests "ghidra.security.*"`
- `bash scripts/cyntra/gates.sh --mode=all`
- `scripts/cyntra/validate-roadmap-completion.sh`
- `scripts/cyntra/preflight.sh`

## Context Reproducibility
- Keep every bead `context_files` path committed on branch `main` before dispatch.
- Do not point beads at uncommitted worktree-only files; workcells are created from committed refs.
- Treat `preflight` context warnings as blockers unless you intentionally set `CYNTRA_STRICT_CONTEXT_MAIN=0` for emergency recovery.

## Kernel Execution
- One cycle: `scripts/cyntra/run-once.sh`
- Continuous: `scripts/cyntra/run-watch.sh`
- Status: `scripts/cyntra/cyntra.sh status`
- Live telemetry: `tail -f .cyntra/logs/events.jsonl`

## Exit Criteria
- No compile failures in active or integrated merge path for Reverend/Generic/frontier modules in scope.
- Gate/CI block on relevant module failures (not Generic-only).
- Cockpit uses live services by default and passes headless/UI parity.
- Query path is indexed/evidence-backed (no full-program decompile scan per request on hot path).
- Kernel completion policy prevents silent zero-diff closes without explicit no-op justification.
- Release packet proves local operational workflow with reproducible commands and artifacts.
