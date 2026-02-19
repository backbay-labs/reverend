# Task: E1-S1: Pin datasets and stand up deterministic evaluation harness

## Context
- Issue: 1001
- Workcell: wc-1001-20260219T232412Z
- Branch: wc/1001/20260219T232412Z
- Toolchain: codex
- Model: gpt-5.2
- Tags: roadmap12w, type:story, epic:E1, lane:eval-devops, week:1, dk_size:M, dk_risk:medium

## Security Policy
- Egress: open
- Write roots: ./
- On violation: escalate

## Execution Guidelines
- Start by stating a short plan (3–6 bullets) before making edits.
- Satisfy the acceptance criteria and keep changes minimal.
- Prefer root-cause fixes; avoid unrelated refactors and drive-by formatting.
- Respect forbidden paths exactly (do not modify them).
- Prefer ripgrep (`rg`) for search; keep commands deterministic and repo-local.
- Run the listed quality gates before finishing; if a gate can't be run, explain why and give the exact command(s) to run.
- Finish with a concise summary of changes, key files touched, and any follow-up steps.

## Description
Type: Story. Epic: E1. Build dataset lock and baseline harness plumbing for similarity/type/diff metrics.

## Acceptance Criteria
- A locked dataset manifest exists with reproducible versions/checksums
- Evaluation entrypoints run in a clean environment without manual steps
- Seed and environment controls are documented and enforced

## Relevant Files
- docs/research/evaluation-harness.md
- docs/research/INDEX.md

## Quality Gates (must all pass)
- test: `bash scripts/cyntra/gates.sh --mode=all`
- typecheck: `bash scripts/cyntra/gates.sh --mode=context`
- lint: `bash scripts/cyntra/gates.sh --mode=diff`
- max-diff-size: type=diff-check
- secret-detection: type=diff-check

## Completion Checklist
- [ ] Acceptance criteria satisfied
- [ ] Forbidden paths respected
- [ ] Quality gates run (or commands provided)
- [ ] Clear summary + next steps
