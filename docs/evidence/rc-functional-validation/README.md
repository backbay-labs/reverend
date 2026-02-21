# RC Functional Validation (2026-02-21)

This folder captures the post-remediation validation pass for security gate hardening, evidence integrity, roadmap validation, and local runtime viability.

## Command Results

- `scripts/cyntra/preflight.sh` (strict): FAIL only on uncommitted-context invariant (`00b-preflight-strict.txt`)
- `CYNTRA_STRICT_CONTEXT_MAIN=0 scripts/cyntra/preflight.sh`: PASS with context-commit warning (`00-preflight.txt`)
- `./gradlew --no-daemon :Generic:compileJava`: PASS (`01-generic-compile.txt`)
- `./gradlew --no-daemon :Generic:test --tests "ghidra.security.*"`: PASS (`02-generic-security-tests.txt`)
- `scripts/cyntra/check-junit-failures.py --results-dir Ghidra/Framework/Generic/build/test-results/test`: PASS (`03-generic-security-junit-check.txt`)
- Targeted regression (`FileSecurityAuditLoggerTest`, `CapabilityGuardTest`, `EgressPolicyEnforcerTest`): PASS (`04-*`, `05-*`)
- `CYNTRA_GATE_ISSUE_ID=1704 scripts/cyntra/gates.sh --mode=all`: PASS (`06-cyntra-gates-all.txt`)
- `scripts/cyntra/validate-roadmap-completion.sh`: PASS (`07-roadmap-validator.txt`)
- `eval/run_smoke.sh` + `eval/scripts/check_regression.py`: PASS (`08-*`)
- `eval/run_soak.sh` (`10 iterations`): PASS/stable (`09-*`)
- `eval/run_soak.sh --iterations 1` wrapper sanity: PASS (`09b-*`)
- `./gradlew --no-daemon buildGhidra`: PASS (`10-build-ghidra.txt`)
- Built dist headless launcher help: PASS (`11-headless-help.txt`)
- Built dist headless import smoke (`/bin/ls`, `-noanalysis`, `-deleteProject`): PASS (`12-headless-import-smoke.txt`)

## Distribution Artifact

- `build/dist/ghidra_12.1_DEV_20260220_mac_arm_64.zip`
