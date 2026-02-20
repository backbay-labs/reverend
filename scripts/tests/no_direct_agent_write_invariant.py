#!/usr/bin/env python3
"""E3-S4: no-direct-agent-write security regression suite."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).resolve().parents[1] / "ml" / "corpus_sync_worker.py"
SPEC = importlib.util.spec_from_file_location("e3_security_corpus_sync_worker", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load module spec from {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

AccessContext = MODULE.AccessContext
run_sync_job = MODULE.run_sync_job
query_audit_log_records = MODULE.query_audit_log_records

REPORT_JSON_NAME = "no-direct-agent-write-invariant.json"
REPORT_MD_NAME = "no-direct-agent-write-invariant.md"


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _write_local_store(path: Path, proposals: list[dict[str, Any]]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "local_proposal_store",
                "proposals": proposals,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


@dataclass(frozen=True)
class InvariantCheckResult:
    check_id: str
    path_type: str
    status: str
    details: str
    evidence: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "path_type": self.path_type,
            "status": self.status,
            "details": self.details,
            "evidence": dict(self.evidence),
        }


def _build_result(
    *,
    check_id: str,
    path_type: str,
    passed: bool,
    details: str,
    evidence: dict[str, Any],
) -> InvariantCheckResult:
    return InvariantCheckResult(
        check_id=check_id,
        path_type=path_type,
        status="PASS" if passed else "FAIL",
        details=details,
        evidence=evidence,
    )


def _check_direct_sync_write_denied() -> InvariantCheckResult:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        local_store = tmp / "local_store.json"
        backend_store = tmp / "backend_store.json"
        state_path = tmp / "state.json"
        audit_path = tmp / "audit.jsonl"

        proposal_id = "p-direct-denied"
        _write_local_store(
            local_store,
            [
                {
                    "proposal_id": proposal_id,
                    "state": "APPROVED",
                    "receipt_id": "r-direct-denied",
                    "program_id": "program:alpha",
                }
            ],
        )

        telemetry = run_sync_job(
            local_store_path=local_store,
            backend_store_path=backend_store,
            state_path=state_path,
            job_id="invariant-direct-sync-denied",
            access_context=AccessContext.from_values(
                principal="agent:observer",
                capabilities={"READ.CORPUS"},
            ),
            audit_path=audit_path,
        )

        deny_events = query_audit_log_records(
            audit_path,
            kind="corpus_access_audit",
            event_type="CAPABILITY_DENIED",
            action="SYNC",
            outcome="DENY",
            target=proposal_id,
            target_type="proposal",
        )
        incidents = query_audit_log_records(
            audit_path,
            kind="corpus_violation_incident",
            event_type="CAPABILITY_DENIED",
            action="SYNC",
            outcome="DENY",
            target=proposal_id,
            target_type="proposal",
        )

        first_error_id = telemetry.errors[0].proposal_id if telemetry.errors else None
        passed = (
            telemetry.synced_count == 0
            and telemetry.error_count == 1
            and first_error_id == proposal_id
            and not backend_store.exists()
            and not state_path.exists()
            and len(deny_events) == 1
            and len(incidents) == 1
        )
        details = (
            "Unauthorized agent write attempt was denied before canonical state mutation."
            if passed
            else "Unauthorized direct write attempt bypassed invariant checks."
        )
        return _build_result(
            check_id="direct_sync_write_capability_denied",
            path_type="direct",
            passed=passed,
            details=details,
            evidence={
                "telemetry": telemetry.to_json(),
                "backend_exists": backend_store.exists(),
                "state_exists": state_path.exists(),
                "deny_events": len(deny_events),
                "incidents": len(incidents),
            },
        )


def _check_indirect_scope_write_denied() -> InvariantCheckResult:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        local_store = tmp / "local_store.json"
        backend_store = tmp / "backend_store.json"
        state_path = tmp / "state.json"
        audit_path = tmp / "audit.jsonl"

        proposal_id = "p-indirect-scope"
        _write_local_store(
            local_store,
            [
                {
                    "proposal_id": proposal_id,
                    "state": "APPROVED",
                    "receipt_id": "r-indirect-scope",
                    "program_id": "program:alpha",
                }
            ],
        )

        telemetry = run_sync_job(
            local_store_path=local_store,
            backend_store_path=backend_store,
            state_path=state_path,
            job_id="invariant-indirect-scope-denied",
            access_context=AccessContext.from_values(
                principal="agent:writer",
                capabilities={"WRITE.CORPUS_SYNC"},
                allowed_program_ids={"program:beta"},
            ),
            audit_path=audit_path,
        )

        deny_events = query_audit_log_records(
            audit_path,
            kind="corpus_access_audit",
            event_type="ACCESS_DENIED",
            action="SYNC",
            outcome="DENY",
            target=proposal_id,
            target_type="proposal",
        )
        incidents = query_audit_log_records(
            audit_path,
            kind="corpus_violation_incident",
            event_type="ACCESS_DENIED",
            action="SYNC",
            outcome="DENY",
            target=proposal_id,
            target_type="proposal",
        )

        first_error_id = telemetry.errors[0].proposal_id if telemetry.errors else None
        passed = (
            telemetry.synced_count == 0
            and telemetry.error_count == 1
            and first_error_id == proposal_id
            and not backend_store.exists()
            and not state_path.exists()
            and len(deny_events) == 1
            and len(incidents) == 1
        )
        details = (
            "Scoped token blocked indirect write path despite write capability grant."
            if passed
            else "Program-scope policy failed to block an indirect write path."
        )
        return _build_result(
            check_id="indirect_sync_scope_denied",
            path_type="indirect",
            passed=passed,
            details=details,
            evidence={
                "telemetry": telemetry.to_json(),
                "backend_exists": backend_store.exists(),
                "state_exists": state_path.exists(),
                "deny_events": len(deny_events),
                "incidents": len(incidents),
            },
        )


def _check_indirect_preflight_bypass_denied() -> InvariantCheckResult:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        local_store = tmp / "local_store.json"
        backend_store = tmp / "backend_store.json"
        state_path = tmp / "state.json"
        audit_path = tmp / "audit.jsonl"

        job_id = "invariant-indirect-preflight-denied"
        _write_local_store(
            local_store,
            [
                {
                    "proposal_id": "p-not-approved",
                    "state": "PROPOSED",
                    "receipt_id": "r-not-approved",
                }
            ],
        )

        telemetry = run_sync_job(
            local_store_path=local_store,
            backend_store_path=backend_store,
            state_path=state_path,
            job_id=job_id,
            access_context=AccessContext.from_values(
                principal="agent:observer",
                capabilities={"READ.CORPUS"},
            ),
            audit_path=audit_path,
        )

        deny_events = query_audit_log_records(
            audit_path,
            kind="corpus_access_audit",
            event_type="CAPABILITY_DENIED",
            action="SYNC",
            outcome="DENY",
            target=job_id,
            target_type="proposal",
        )
        incidents = query_audit_log_records(
            audit_path,
            kind="corpus_violation_incident",
            event_type="CAPABILITY_DENIED",
            action="SYNC",
            outcome="DENY",
            target=job_id,
            target_type="proposal",
        )

        first_error_id = telemetry.errors[0].proposal_id if telemetry.errors else None
        passed = (
            telemetry.approved_total == 0
            and telemetry.synced_count == 0
            and telemetry.error_count == 1
            and first_error_id == job_id
            and not backend_store.exists()
            and not state_path.exists()
            and len(deny_events) == 1
            and len(incidents) == 1
        )
        details = (
            "Preflight guard denied no-approved-proposal bypass attempt before state writes."
            if passed
            else "No-approved-proposal preflight path bypassed write invariant."
        )
        return _build_result(
            check_id="indirect_sync_preflight_bypass_denied",
            path_type="indirect",
            passed=passed,
            details=details,
            evidence={
                "telemetry": telemetry.to_json(),
                "backend_exists": backend_store.exists(),
                "state_exists": state_path.exists(),
                "deny_events": len(deny_events),
                "incidents": len(incidents),
            },
        )


def run_suite() -> dict[str, Any]:
    checks = (
        _check_direct_sync_write_denied(),
        _check_indirect_scope_write_denied(),
        _check_indirect_preflight_bypass_denied(),
    )
    passed_checks = sum(1 for check in checks if check.status == "PASS")
    failed_checks = len(checks) - passed_checks
    status = "PASS" if failed_checks == 0 else "FAIL"

    return {
        "schema_version": 1,
        "kind": "no_direct_agent_write_invariant_report",
        "generated_at_utc": _utc_now(),
        "invariant_id": "NO_DIRECT_AGENT_WRITE",
        "summary": {
            "status": status,
            "total_checks": len(checks),
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
        },
        "checks": [check.to_json() for check in checks],
    }


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# No-Direct-Agent-Write Invariant Report",
        "",
        f"- Generated: `{report['generated_at_utc']}`",
        f"- Invariant: `{report['invariant_id']}`",
        f"- Status: `{summary['status']}`",
        f"- Checks: `{summary['passed_checks']}/{summary['total_checks']}` passed",
        "",
        "| Check ID | Path | Status | Details |",
        "|---|---|---|---|",
    ]
    for check in report["checks"]:
        details = str(check["details"]).replace("|", "\\|")
        lines.append(
            f"| `{check['check_id']}` | `{check['path_type']}` | `{check['status']}` | {details} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_report_bundle(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / REPORT_JSON_NAME
    md_path = output_dir / REPORT_MD_NAME
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    return json_path, md_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run no-direct-agent-write invariant regression suite")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional output directory for JSON/Markdown invariant reports.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = run_suite()

    if args.output_dir is not None:
        json_path, md_path = write_report_bundle(report, args.output_dir)
        print(
            json.dumps(
                {
                    "kind": "no_direct_agent_write_invariant_artifacts",
                    "json_report": str(json_path),
                    "markdown_report": str(md_path),
                    "status": report["summary"]["status"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    return 0 if report["summary"]["failed_checks"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
