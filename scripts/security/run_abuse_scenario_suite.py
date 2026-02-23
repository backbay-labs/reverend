#!/usr/bin/env python3
"""Execute adversarial abuse scenarios and emit reviewable evidence artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_ISSUE_ID = "1702"
SPEC_UNDER_TEST = "docs/research/agent-runtime-security-spec.md"
COMPLIANCE_REFERENCE = "docs/research/legal-compliance-playbook.md"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    log_name: str
    command: tuple[str, ...]
    expected_controls: str
    pass_observed_controls: str
    remediation_if_failed: str
    additional_evidence: tuple[str, ...] = ()


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        scenario_id="S1",
        name="Direct or indirect agent write attempt to canonical corpus state",
        log_name="scenario-01-no-direct-agent-write.log",
        command=(
            "python3",
            "scripts/tests/no_direct_agent_write_invariant.py",
            "--output-dir",
            "{output_dir}/no-direct-agent-write",
        ),
        expected_controls=(
            "Capability checks deny unauthorized sync writes and emit paired "
            "corpus_access_audit + corpus_violation_incident records."
        ),
        pass_observed_controls=(
            "Invariant suite returned PASS for all checks; unauthorized write "
            "paths were denied before backend/state mutation."
        ),
        remediation_if_failed=(
            "Restore fail-closed authorization in scripts/ml/corpus_sync_worker.py "
            "(WRITE.CORPUS_SYNC precheck plus deny/audit emission on violation)."
        ),
        additional_evidence=(
            "no-direct-agent-write/no-direct-agent-write-invariant.json",
            "no-direct-agent-write/no-direct-agent-write-invariant.md",
        ),
    ),
    Scenario(
        scenario_id="S2",
        name="Egress policy bypass by targeting non-allowlisted cloud endpoint",
        log_name="scenario-02-allowlist-egress.log",
        command=(
            "python3",
            "-m",
            "unittest",
            "-v",
            "scripts/ml/tests/test_corpus_sync_worker.py",
            "-k",
            "allowlist_mode_blocks_non_approved_destination",
        ),
        expected_controls=(
            "allowlist mode blocks non-approved destinations and emits deterministic "
            "EGRESS_BLOCKED incident remediation."
        ),
        pass_observed_controls=(
            "Allowlist-mode blocking test passed and recorded deterministic block behavior."
        ),
        remediation_if_failed=(
            "Re-enable endpoint allowlist matching and EGRESS_BLOCKED incident "
            "emission in scripts/ml/corpus_sync_worker.py."
        ),
    ),
    Scenario(
        scenario_id="S3",
        name="Project-level policy override bypass (offline project tries remote sync)",
        log_name="scenario-03-policy-mode-scope.log",
        command=(
            "python3",
            "-m",
            "unittest",
            "-v",
            "scripts/ml/tests/test_corpus_sync_worker.py",
            "-k",
            "sync_policy_modes_are_configurable_per_project",
        ),
        expected_controls=(
            "Per-project policy modes override defaults; offline project is denied "
            "while cloud project may proceed."
        ),
        pass_observed_controls=(
            "Per-project mode scoping test passed; offline-deny semantics remained enforced."
        ),
        remediation_if_failed=(
            "Repair project policy resolution in EndpointPolicyConfig/EndpointPolicyRule "
            "to preserve offline deny semantics."
        ),
    ),
    Scenario(
        scenario_id="S4",
        name="Provenance-chain tampering to bypass read-side trust checks",
        log_name="scenario-04-provenance-chain.log",
        command=(
            "python3",
            "-m",
            "unittest",
            "-v",
            "scripts/ml/tests/test_corpus_sync_worker.py",
            "-k",
            "read_rejects_incomplete_provenance_chain",
        ),
        expected_controls=(
            "Read path rejects malformed chain continuity and emits "
            "PROVENANCE_CHAIN_INVALID deny audit."
        ),
        pass_observed_controls=(
            "Provenance continuity validation test passed; malformed artifacts were rejected."
        ),
        remediation_if_failed=(
            "Reinstate provenance continuity validation in "
            "scripts/ml/corpus_sync_worker.py::_validate_provenance_chain(...) and "
            "deny malformed artifacts."
        ),
    ),
    Scenario(
        scenario_id="S5",
        name="Receipt-history tampering (mutate historic record)",
        log_name="scenario-05-receipt-tamper.log",
        command=(
            "python3",
            "-m",
            "unittest",
            "-v",
            "scripts/ml/tests/test_receipt_store.py",
            "-k",
            "verify_integrity_detects_tampering",
        ),
        expected_controls=(
            "Hash-chain integrity checks detect mutation and block further appends."
        ),
        pass_observed_controls=(
            "Receipt integrity tampering test passed and append was blocked on tampered state."
        ),
        remediation_if_failed=(
            "Restore canonical hash verification and append-time integrity guard in "
            "scripts/ml/receipt_store.py."
        ),
    ),
    Scenario(
        scenario_id="S6",
        name="Malware safety profile drift to unsafe mode/egress",
        log_name="scenario-06-malware-safety-profiles.log",
        command=(
            "python3",
            "scripts/security/validate_malware_safety_profiles.py",
            "--profiles",
            "scripts/security/malware_safety_policy_profiles.json",
        ),
        expected_controls=(
            "Malware profile set is fail-closed: no cloud mode, sandbox-only detonation, "
            "and explicit non-wildcard allowlist semantics."
        ),
        pass_observed_controls=(
            "Malware safety profile validator passed; unsafe mode/egress profile drift was blocked."
        ),
        remediation_if_failed=(
            "Restore fail-closed malware profile constraints in "
            "scripts/security/malware_safety_policy_profiles.json and "
            "scripts/security/validate_malware_safety_profiles.py."
        ),
    ),
)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def _shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _load_manifest_metadata() -> dict[str, str]:
    metadata = {"workcell": "unknown", "branch": "unknown"}
    manifest_path = Path("manifest.json")
    if not manifest_path.exists():
        return metadata

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return metadata

    metadata["workcell"] = str(manifest.get("workcell_id") or "unknown")
    metadata["branch"] = str(manifest.get("branch_name") or "unknown")
    return metadata


def _write_scenario_log(
    log_path: Path,
    command: list[str],
    completed: subprocess.CompletedProcess[str],
) -> None:
    lines = [
        f"$ {_shell_join(command)}",
        "",
        "--- stdout ---",
        completed.stdout.rstrip(),
        "",
        "--- stderr ---",
        completed.stderr.rstrip(),
        "",
        f"exit_code={completed.returncode}",
        "",
    ]
    log_path.write_text("\n".join(lines), encoding="utf-8")


def _run_scenarios(output_dir: Path) -> tuple[list[dict[str, object]], dict[str, int]]:
    outcomes: list[dict[str, object]] = []

    for scenario in SCENARIOS:
        command = [part.format(output_dir=str(output_dir)) for part in scenario.command]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        log_path = output_dir / scenario.log_name
        _write_scenario_log(log_path, command, completed)

        status = "PASS" if completed.returncode == 0 else "FAIL"
        observed_controls = (
            scenario.pass_observed_controls
            if status == "PASS"
            else f"Scenario command failed with exit code {completed.returncode}; see {log_path}."
        )
        outcomes.append(
            {
                "scenario_id": scenario.scenario_id,
                "name": scenario.name,
                "status": status,
                "exit_code": completed.returncode,
                "command": _shell_join(command),
                "expected_controls": scenario.expected_controls,
                "observed_controls": observed_controls,
                "log": str(log_path),
                "additional_evidence": [str(output_dir / rel) for rel in scenario.additional_evidence],
                "remediation_if_failed": scenario.remediation_if_failed,
            }
        )

    passed = sum(1 for outcome in outcomes if outcome["status"] == "PASS")
    failed = len(outcomes) - passed
    summary = {
        "total_scenarios": len(outcomes),
        "passed": passed,
        "failed": failed,
        "open_remediations": failed,
    }
    return outcomes, summary


def _write_outcomes_json(
    output_dir: Path,
    issue_id: str,
    executed_at_utc: str,
    outcomes: list[dict[str, object]],
    summary: dict[str, int],
) -> Path:
    payload = {
        "schema_version": 1,
        "kind": "abuse_scenario_suite_outcomes",
        "issue_id": issue_id,
        "spec_under_test": SPEC_UNDER_TEST,
        "compliance_reference": COMPLIANCE_REFERENCE,
        "executed_at_utc": executed_at_utc,
        "summary": summary,
        "scenarios": outcomes,
    }
    path = output_dir / "scenario-outcomes.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_outcomes_markdown(
    output_dir: Path,
    issue_id: str,
    executed_at_utc: str,
    outcomes: list[dict[str, object]],
    summary: dict[str, int],
) -> Path:
    lines = [
        f"# Abuse Scenario Outcomes (Issue {issue_id})",
        "",
        f"- Executed: `{executed_at_utc}`",
        f"- Spec under test: `{SPEC_UNDER_TEST}`",
        f"- Compliance reference: `{COMPLIANCE_REFERENCE}`",
        "",
        "## Summary",
        "",
        f"- Total scenarios: `{summary['total_scenarios']}`",
        f"- Passed: `{summary['passed']}`",
        f"- Failed: `{summary['failed']}`",
        f"- Open remediations: `{summary['open_remediations']}`",
        "",
        "## Scenario Matrix",
        "",
        "| ID | Scenario | Status | Expected controls | Observed controls | Remediation if failed |",
        "|---|---|---|---|---|---|",
    ]
    for outcome in outcomes:
        lines.append(
            "| {scenario_id} | {name} | **{status}** | {expected_controls} | "
            "{observed_controls} | {remediation_if_failed} |".format(**outcome)
        )

    lines.extend(
        [
            "",
            "## Evidence Links",
            "",
        ]
    )
    for outcome in outcomes:
        lines.append(f"- `{outcome['scenario_id']}` log: `{Path(outcome['log']).as_posix()}`")
        for additional in outcome["additional_evidence"]:
            lines.append(f"- `{outcome['scenario_id']}` artifact: `{Path(additional).as_posix()}`")

    lines.append("")
    path = output_dir / "scenario-outcomes.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _write_readme(
    output_dir: Path,
    issue_id: str,
    metadata: dict[str, str],
    executed_at_utc: str,
    outcomes: list[dict[str, object]],
    summary: dict[str, int],
) -> Path:
    lines = [
        f"# Abuse Scenario Suite Evidence (Issue {issue_id})",
        "",
        f"Executed: {executed_at_utc}",
        f"Branch: `{metadata['branch']}`",
        f"Workcell: `{metadata['workcell']}`",
        "",
        "## Execution",
        "",
        "Run from repository root:",
        "",
        "```bash",
        "python3 scripts/security/run_abuse_scenario_suite.py "
        f"--issue-id {issue_id} --output-dir {output_dir.as_posix()}",
        "```",
        "",
        "## Scenario Evidence Files",
        "",
        "| Scenario | Command evidence | Additional artifact(s) |",
        "|---|---|---|",
    ]
    for outcome in outcomes:
        additional = ", ".join(f"`{Path(path).relative_to(output_dir).as_posix()}`" for path in outcome["additional_evidence"])
        if not additional:
            additional = "—"
        lines.append(
            f"| {outcome['scenario_id']} - {outcome['name']} | "
            f"`{Path(outcome['log']).relative_to(output_dir).as_posix()}` | {additional} |"
        )

    lines.extend(
        [
            "",
            "## Run Summary",
            "",
            f"- Executed scenarios: `{summary['total_scenarios']}`",
            f"- Passed: `{summary['passed']}`",
            f"- Failed: `{summary['failed']}`",
            f"- Open remediation items from this run: `{summary['open_remediations']}`",
            "",
            "## Integrity",
            "",
            "SHA-256 checksums for all suite evidence files are stored in:",
            "",
            "- `checksums.sha256`",
            "",
        ]
    )

    readme_path = output_dir / "README.md"
    readme_path.write_text("\n".join(lines), encoding="utf-8")
    return readme_path


def _write_checksums(output_dir: Path) -> Path:
    checksum_lines: list[str] = []
    for file_path in sorted(output_dir.rglob("*")):
        if not file_path.is_file() or file_path.name == "checksums.sha256":
            continue
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        checksum_lines.append(f"{digest}  {file_path.relative_to(output_dir).as_posix()}")

    checksums_path = output_dir / "checksums.sha256"
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return checksums_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run abuse scenarios and emit executable review evidence."
    )
    parser.add_argument(
        "--issue-id",
        default=DEFAULT_ISSUE_ID,
        help=f"Issue id for evidence metadata (default: {DEFAULT_ISSUE_ID})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for logs/reports (defaults to docs/security/evidence/abuse-scenario-suite-<issue-id>)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    issue_id = str(args.issue_id).strip() or DEFAULT_ISSUE_ID
    output_dir = args.output_dir or Path(f"docs/security/evidence/abuse-scenario-suite-{issue_id}")

    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "no-direct-agent-write").mkdir(parents=True, exist_ok=True)

    metadata = _load_manifest_metadata()
    executed_at_utc = _utc_now()
    outcomes, summary = _run_scenarios(output_dir)
    _write_outcomes_json(output_dir, issue_id, executed_at_utc, outcomes, summary)
    _write_outcomes_markdown(output_dir, issue_id, executed_at_utc, outcomes, summary)
    _write_readme(output_dir, issue_id, metadata, executed_at_utc, outcomes, summary)
    _write_checksums(output_dir)

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
