#!/usr/bin/env python3
"""Scan completion telemetry anomalies and reopen/flag affected issues."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        return text in {"1", "true", "yes", "y", "on"}
    return False


def as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            try:
                return int(text)
            except Exception:
                return None
    return None


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def load_issues(path: Path) -> list[dict]:
    return read_jsonl(path)


def write_issues(path: Path, issues: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(issue, ensure_ascii=False) + "\n" for issue in issues),
        encoding="utf-8",
    )


def append_events(path: Path, records: list[dict]) -> None:
    if not records:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def classify_anomalies(event: dict) -> list[str]:
    gate_summary = event.get("gate_summary")
    if not isinstance(gate_summary, dict):
        return ["invalid_gate_summary_schema"]

    anomalies: list[str] = []
    completion_classification = str(gate_summary.get("completion_classification") or "").strip().lower()
    explicit_noop = as_bool(gate_summary.get("explicit_noop_justification_present"))
    policy_result = str(gate_summary.get("policy_result") or "").strip().lower()
    policy_block_reason = str(gate_summary.get("policy_block_reason") or "").strip().lower()

    if completion_classification and completion_classification not in {"noop", "code_change"}:
        anomalies.append("invalid_completion_classification")

    if completion_classification == "noop" and not explicit_noop:
        anomalies.append("zero_diff_missing_noop_justification")

    if policy_result == "blocked":
        if policy_block_reason == "missing_manifest_noop_justification":
            anomalies.append("policy_blocked_missing_noop_justification")
        elif policy_block_reason == "blocking_gate_skip_evidence_missing":
            anomalies.append("policy_blocked_blocking_skip_evidence_missing")
        elif policy_block_reason == "blocking_gate_skip_reason_not_allowlisted":
            anomalies.append("policy_blocked_blocking_skip_reason_not_allowlisted")
        else:
            anomalies.append("policy_blocked_unknown")

    skipped_count = as_int(gate_summary.get("blocking_gate_skipped_count"))
    skip_budget = as_int(gate_summary.get("blocking_gate_skip_budget"))
    budget_exceeded = as_bool(gate_summary.get("blocking_gate_budget_exceeded"))
    if (
        skipped_count is not None
        and skip_budget is not None
        and budget_exceeded
        and skipped_count <= skip_budget
    ):
        anomalies.append("invalid_blocking_skip_budget_signal")

    deduped: list[str] = []
    seen: set[str] = set()
    for anomaly in anomalies:
        if anomaly in seen:
            continue
        seen.add(anomaly)
        deduped.append(anomaly)
    return deduped


def wants_auto_reopen(anomalies: list[str]) -> bool:
    reopen_classes = {
        "zero_diff_missing_noop_justification",
        "policy_blocked_missing_noop_justification",
        "policy_blocked_blocking_skip_evidence_missing",
    }
    return any(anomaly in reopen_classes for anomaly in anomalies)


def run(args: argparse.Namespace) -> int:
    events = read_jsonl(args.events_path)
    issues = load_issues(args.issues_path)

    latest_completion_event_by_issue: dict[str, dict] = {}
    completion_event_count = 0
    for event in events:
        if str(event.get("event") or "") != "completion_policy_gate_summary":
            continue
        completion_event_count += 1
        issue_id = str(event.get("issue_id") or "").strip()
        if not issue_id:
            continue
        latest_completion_event_by_issue[issue_id] = event

    issue_index = {str(issue.get("id") or ""): issue for issue in issues if isinstance(issue, dict)}
    mutated = False
    guard_events: list[dict] = []

    findings: list[dict] = []
    reopened = 0
    flagged = 0
    no_action = 0

    for issue_id in sorted(latest_completion_event_by_issue.keys(), key=lambda value: int(value) if value.isdigit() else value):
        completion_event = latest_completion_event_by_issue[issue_id]
        anomalies = classify_anomalies(completion_event)
        if not anomalies:
            continue

        issue_doc = issue_index.get(issue_id)
        status_before = str(issue_doc.get("status") or "") if isinstance(issue_doc, dict) else ""
        status_after = status_before
        action = "none"

        auto_reopen = wants_auto_reopen(anomalies)

        if isinstance(issue_doc, dict):
            if auto_reopen and status_before.lower() == "done" and not args.dry_run:
                issue_doc["status"] = "open"
                status_after = "open"
                action = "auto_reopen"
                reopened += 1
                mutated = True
            elif auto_reopen and status_before.lower() == "done":
                status_after = "open"
                action = "would_auto_reopen"
                no_action += 1
            else:
                tags = issue_doc.get("tags")
                if not isinstance(tags, list):
                    tags = []
                if "needs-human-review" not in tags and not args.dry_run:
                    tags.append("needs-human-review")
                    issue_doc["tags"] = tags
                    mutated = True
                action = "flag_human_review"
                flagged += 1
        else:
            action = "flag_human_review_missing_issue"
            flagged += 1

        finding = {
            "issue_id": issue_id,
            "workcell_id": str(completion_event.get("workcell_id") or ""),
            "proof_path": str(completion_event.get("proof_path") or ""),
            "anomaly_classes": anomalies,
            "recommended_action": "auto_reopen" if auto_reopen else "flag_human_review",
            "applied_action": action,
            "status_before": status_before,
            "status_after": status_after,
        }
        findings.append(finding)

        guard_events.append(
            {
                "timestamp_utc": now_iso(),
                "event": "completion_anomaly_guard_decision",
                "issue_id": issue_id,
                "workcell_id": str(completion_event.get("workcell_id") or ""),
                "proof_path": str(completion_event.get("proof_path") or ""),
                "anomaly_classes": anomalies,
                "recommended_action": finding["recommended_action"],
                "applied_action": action,
                "status_before": status_before,
                "status_after": status_after,
                "dry_run": bool(args.dry_run),
            }
        )

    if mutated and not args.dry_run:
        write_issues(args.issues_path, issues)

    if not args.dry_run:
        append_events(args.events_path, guard_events)

    report = {
        "generated_at_utc": now_iso(),
        "events_path": str(args.events_path),
        "issues_path": str(args.issues_path),
        "dry_run": bool(args.dry_run),
        "scanned_completion_events": completion_event_count,
        "issues_with_completion_events": len(latest_completion_event_by_issue),
        "anomalies_detected": len(findings),
        "actions": {
            "auto_reopened": reopened,
            "flagged_human_review": flagged,
            "no_action": no_action,
        },
        "findings": findings,
    }

    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--events",
        dest="events_path",
        type=Path,
        default=Path(".cyntra/logs/events.jsonl"),
        help="Path to kernel telemetry JSONL events file",
    )
    parser.add_argument(
        "--issues",
        dest="issues_path",
        type=Path,
        default=Path(".beads/issues.jsonl"),
        help="Path to issues JSONL source of truth",
    )
    parser.add_argument(
        "--report",
        dest="report_path",
        type=Path,
        default=Path(".cyntra/logs/completion-anomaly-report.json"),
        help="Path to write anomaly report JSON",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report only; do not mutate issues or append decision events",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(run(parse_args(sys.argv[1:])))
