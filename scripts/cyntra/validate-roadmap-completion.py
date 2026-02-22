#!/usr/bin/env python3
"""Validate roadmap completion consistency across beads, CSV export, and release evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path


FIELDNAMES = [
    "id",
    "issue_type",
    "title",
    "status",
    "epic_id",
    "priority",
    "risk",
    "size",
    "tool_hint",
    "tags",
    "acceptance_criteria",
    "description",
]


REQUIRED_EVIDENCE_FILES = [
    "docs/soak-test-report-1701.md",
    "docs/security/evidence/abuse-scenario-suite-1806/README.md",
    "docs/security/evidence/abuse-scenario-suite-1702/scenario-outcomes.json",
    "docs/security/evidence/abuse-scenario-suite-1702/checksums.sha256",
    "docs/security/evidence/abuse-scenario-suite-1806/checksums.sha256",
    "docs/exit-gate-report.md",
    "docs/go-no-go-decision.md",
    "docs/exit-gate-packet-1704.md",
    "docs/exit-gate-packet-1808.md",
    "docs/evidence/exit-gate-packet-1704/quality-gates.md",
    "docs/evidence/exit-gate-packet-1808/quality-gates.md",
    "docs/evidence/r1-remediation-closure-1800/quality-gates.md",
]


REQUIRED_CHECKSUM_BUNDLES = [
    "docs/security/evidence/abuse-scenario-suite-1702",
    "docs/security/evidence/abuse-scenario-suite-1806",
]


REQUIRED_EXECUTABLE_SCENARIO_LOGS = [
    "scenario-01-no-direct-agent-write.log",
    "scenario-02-allowlist-egress.log",
    "scenario-03-policy-mode-scope.log",
    "scenario-04-provenance-chain.log",
    "scenario-05-receipt-tamper.log",
]

ROADMAP_STATUS_DOC = "docs/audit-remediation-sota-operational-roadmap.md"
ROADMAP_STATUS_PATTERNS = {
    "total": r"Roadmap exportable issues:\s*`?(\d+)`?",
    "done": r"Done:\s*`?(\d+)`?",
    "open": r"Open:\s*`?(\d+)`?",
    "blocked": r"Blocked:\s*`?(\d+)`?",
    "e20_mix": r"E20\s*\(`3100`\s*\+\s*children\):\s*`([^`]+)`",
    "e21_mix": r"E21\s*\(`3200`\s*\+\s*children\):\s*`([^`]+)`",
}


WORKFLOW_PATTERNS: dict[str, str] = {
    "REQUIRED_PYTHON_VERSION pin": r"REQUIRED_PYTHON_VERSION:\s*['\"]?3\.11['\"]?",
    "REQUIRED_JAVA_VERSION pin": r"REQUIRED_JAVA_VERSION:\s*['\"]?21['\"]?",
    "setup-python uses REQUIRED_PYTHON_VERSION": (
        r"uses:\s*actions/setup-python@[^\n]*\n(?:[^\n]*\n){0,10}?"
        r"\s*python-version:\s*\$\{\{\s*env\.REQUIRED_PYTHON_VERSION\s*\}\}"
    ),
    "setup-java uses REQUIRED_JAVA_VERSION": (
        r"uses:\s*actions/setup-java@[^\n]*\n(?:[^\n]*\n){0,12}?"
        r"\s*java-version:\s*\$\{\{\s*env\.REQUIRED_JAVA_VERSION\s*\}\}"
    ),
}


def parse_issue_type(tags: list[str]) -> str:
    for tag in tags:
        if tag.startswith("type:"):
            value = tag.split(":", 1)[1].strip().lower()
            if value == "epic":
                return "Epic"
            if value == "story":
                return "Story"
    return ""


def is_exportable(issue: dict) -> bool:
    tags = [str(tag) for tag in issue.get("tags") or []]
    if "roadmap12w" not in tags:
        return False
    if "merge-conflict" in tags or "escalation" in tags:
        return False
    if parse_issue_type(tags) not in {"Epic", "Story"}:
        return False
    title = str(issue.get("title") or "")
    if title.startswith("[MERGE CONFLICT]") or title.startswith("[ESCALATION]"):
        return False
    return True


def to_row(issue: dict) -> dict[str, str]:
    tags = [str(tag) for tag in issue.get("tags") or []]
    criteria = issue.get("acceptance_criteria") or []
    if isinstance(criteria, list):
        criteria_text = " | ".join(str(item).strip() for item in criteria if str(item).strip())
    else:
        criteria_text = str(criteria).strip()

    return {
        "id": str(issue.get("id") or ""),
        "issue_type": parse_issue_type(tags),
        "title": str(issue.get("title") or ""),
        "status": str(issue.get("status") or "").lower(),
        "epic_id": str(issue.get("dk_parent") or ""),
        "priority": str(issue.get("dk_priority") or ""),
        "risk": str(issue.get("dk_risk") or ""),
        "size": str(issue.get("dk_size") or ""),
        "tool_hint": str(issue.get("dk_tool_hint") or ""),
        "tags": "|".join(tags),
        "acceptance_criteria": criteria_text,
        "description": str(issue.get("description") or ""),
    }


def numeric_id(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 10**12


def load_issues(path: Path, repo_root: Path) -> tuple[list[dict], str]:
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()], str(path.relative_to(repo_root))

    issues_ref = (os.environ.get("CYNTRA_ISSUES_REF") or "HEAD").strip() or "HEAD"
    source = f"{issues_ref}:.beads/issues.jsonl"
    try:
        text = subprocess.check_output(
            ["git", "-C", str(repo_root), "show", source],
            text=True,
        )
    except Exception as exc:
        raise FileNotFoundError(f"unable to read canonical issues from {source}: {exc}") from exc
    return [json.loads(line) for line in text.splitlines() if line.strip()], source


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = []
        for row in csv.DictReader(handle):
            rows.append({name: str(row.get(name) or "") for name in FIELDNAMES})
        return rows


def _parse_checksum_entries(manifest_path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    entries: list[tuple[str, str]] = []
    errors: list[str] = []
    for lineno, raw in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if "  " not in line:
            errors.append(
                f"{manifest_path}: line {lineno} malformed checksum entry (expected '<sha256>  <path>')"
            )
            continue
        digest, rel = line.split("  ", 1)
        digest = digest.strip().lower()
        rel = rel.strip()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            errors.append(f"{manifest_path}: line {lineno} invalid sha256 digest '{digest}'")
            continue
        if not rel:
            errors.append(f"{manifest_path}: line {lineno} has empty file path")
            continue
        entries.append((digest, rel))
    return entries, errors


def _verify_checksum_bundle(repo_root: Path, rel_bundle: str) -> tuple[list[str], int]:
    bundle = repo_root / rel_bundle
    manifest_path = bundle / "checksums.sha256"
    errors: list[str] = []
    verified = 0

    if not bundle.exists():
        return [f"missing evidence bundle directory: {rel_bundle}"], verified
    if not manifest_path.exists():
        return [f"missing checksum manifest: {rel_bundle}/checksums.sha256"], verified

    entries, parse_errors = _parse_checksum_entries(manifest_path)
    errors.extend(parse_errors)
    if not entries:
        errors.append(f"checksum manifest has no valid entries: {rel_bundle}/checksums.sha256")
        return errors, verified

    for digest, rel_path in entries:
        target = bundle / rel_path
        if not target.exists():
            errors.append(f"checksum references missing file: {rel_bundle}/{rel_path}")
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(
                f"checksum mismatch: {rel_bundle}/{rel_path} (expected {digest}, got {actual})"
            )
            continue
        verified += 1

    return errors, verified


def _extract_int(pattern: str, text: str) -> int | None:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _format_status_counts(status_counts: dict[str, int]) -> str:
    return ", ".join(f"{status}={status_counts[status]}" for status in sorted(status_counts))


def validate(repo_root: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    notes: list[str] = []

    issues_path = repo_root / ".beads/issues.jsonl"
    csv_path = repo_root / "docs/backlog-jira-linear.csv"
    workflow_path = repo_root / ".github/workflows/eval.yaml"
    roadmap_status_doc_path = repo_root / ROADMAP_STATUS_DOC

    for required in [csv_path, workflow_path, roadmap_status_doc_path]:
        if not required.exists():
            errors.append(f"missing required file: {required.relative_to(repo_root)}")
    if errors:
        return errors, notes

    try:
        issues, issues_source = load_issues(issues_path, repo_root)
    except Exception as exc:
        errors.append(str(exc))
        return errors, notes

    exportable = [issue for issue in issues if is_exportable(issue)]
    exportable.sort(
        key=lambda issue: (
            0 if parse_issue_type([str(tag) for tag in issue.get("tags") or []]) == "Epic" else 1,
            numeric_id(str(issue.get("id") or "")),
            str(issue.get("id") or ""),
        )
    )

    if not exportable:
        errors.append("no exportable roadmap issues found")
        return errors, notes

    issue_by_id = {str(issue.get("id") or ""): issue for issue in issues}
    stories = [
        issue
        for issue in exportable
        if parse_issue_type([str(tag) for tag in issue.get("tags") or []]) == "Story"
    ]
    epics = [
        issue
        for issue in exportable
        if parse_issue_type([str(tag) for tag in issue.get("tags") or []]) == "Epic"
    ]

    for story in stories:
        sid = str(story.get("id") or "?")
        parent_id = str(story.get("dk_parent") or "")
        if not parent_id:
            errors.append(f"story #{sid} missing dk_parent")
            continue
        parent = issue_by_id.get(parent_id)
        if parent is None:
            errors.append(f"story #{sid} references missing parent #{parent_id}")
            continue
        parent_type = parse_issue_type([str(tag) for tag in parent.get("tags") or []])
        if parent_type != "Epic":
            errors.append(f"story #{sid} parent #{parent_id} is not an epic (type={parent_type or 'unset'})")

    children_by_epic: dict[str, list[dict]] = {}
    for story in stories:
        parent_id = str(story.get("dk_parent") or "")
        if parent_id:
            children_by_epic.setdefault(parent_id, []).append(story)

    for epic in epics:
        epic_id = str(epic.get("id") or "")
        epic_status = str(epic.get("status") or "").lower()
        children = children_by_epic.get(epic_id, [])
        if epic_status == "done":
            unfinished = [
                str(child.get("id") or "?")
                for child in children
                if str(child.get("status") or "").lower() != "done"
            ]
            if unfinished:
                errors.append(f"epic #{epic_id} is done but has unfinished children: {unfinished}")

    expected_rows = [to_row(issue) for issue in exportable]
    expected_ids = [row["id"] for row in expected_rows]
    expected_by_id = {row["id"]: row for row in expected_rows}

    csv_rows = load_csv_rows(csv_path)
    csv_ids = [row["id"] for row in csv_rows]
    csv_by_id = {row["id"]: row for row in csv_rows}

    missing_in_csv = sorted(set(expected_ids) - set(csv_ids), key=numeric_id)
    extra_in_csv = sorted(set(csv_ids) - set(expected_ids), key=numeric_id)
    if missing_in_csv:
        errors.append(f"csv missing roadmap rows: {missing_in_csv}")
    if extra_in_csv:
        errors.append(f"csv has extra rows not in exportable roadmap set: {extra_in_csv}")

    row_mismatch: list[tuple[str, list[str]]] = []
    for issue_id in expected_ids:
        expected = expected_by_id[issue_id]
        actual = csv_by_id.get(issue_id)
        if not actual:
            continue
        mismatched_fields = [
            field for field in FIELDNAMES if str(actual.get(field, "")) != str(expected.get(field, ""))
        ]
        if mismatched_fields:
            row_mismatch.append((issue_id, mismatched_fields))

    if row_mismatch:
        details = [f"{issue_id}:{','.join(fields)}" for issue_id, fields in row_mismatch[:12]]
        errors.append(
            "csv full-row mismatch against .beads canonical rows: "
            + "; ".join(details)
        )

    missing_evidence = [
        rel_path
        for rel_path in REQUIRED_EVIDENCE_FILES
        if not (repo_root / rel_path).exists()
    ]
    if missing_evidence:
        errors.append(f"missing required closure evidence files: {missing_evidence}")

    checksum_verified = 0
    for rel_bundle in REQUIRED_CHECKSUM_BUNDLES:
        bundle_errors, verified = _verify_checksum_bundle(repo_root, rel_bundle)
        checksum_verified += verified
        errors.extend(bundle_errors)
        bundle_path = repo_root / rel_bundle
        for log_name in REQUIRED_EXECUTABLE_SCENARIO_LOGS:
            if not (bundle_path / log_name).exists():
                errors.append(f"missing executable scenario log: {rel_bundle}/{log_name}")

    outcomes_path = repo_root / "docs/security/evidence/abuse-scenario-suite-1702/scenario-outcomes.json"
    abuse_suite_path = repo_root / "docs/security/abuse-scenario-suite.md"
    signoff_path = repo_root / "docs/security/security-signoff-checklist.md"
    if outcomes_path.exists() and abuse_suite_path.exists() and signoff_path.exists():
        try:
            outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))
            runtime_total = int(
                (outcomes.get("summary") or {}).get("total_scenarios")
                or len(outcomes.get("scenarios") or [])
            )
        except Exception as exc:
            errors.append(f"failed to parse scenario outcomes json: {outcomes_path} ({exc})")
            runtime_total = None

        abuse_text = abuse_suite_path.read_text(encoding="utf-8")
        signoff_text = signoff_path.read_text(encoding="utf-8")
        abuse_executed = _extract_int(r"Executed scenarios:\s*`?(\d+)`?", abuse_text)
        signoff_primary = _extract_int(
            r"All\s+(\d+)\s+primary attack scenarios", signoff_text
        )
        signoff_total_documented = _extract_int(
            r"(\d+)\s+total scenarios documented", signoff_text
        )

        if runtime_total is not None and abuse_executed is not None and runtime_total != abuse_executed:
            errors.append(
                f"executable scenario count mismatch: outcomes={runtime_total}, abuse-suite-doc={abuse_executed}"
            )
        if runtime_total is not None and signoff_primary is not None and runtime_total != signoff_primary:
            errors.append(
                f"primary scenario count mismatch: outcomes={runtime_total}, signoff-primary={signoff_primary}"
            )
        if signoff_total_documented is not None and signoff_primary is not None:
            if signoff_total_documented < signoff_primary:
                errors.append(
                    "signoff documented total scenarios is less than primary executable count"
                )

        notes.append(
            "security scenario counts: "
            f"outcomes={runtime_total}, abuse_doc={abuse_executed}, "
            f"signoff_primary={signoff_primary}, signoff_total_documented={signoff_total_documented}"
        )
    else:
        errors.append(
            "missing one or more scenario consistency files: "
            "docs/security/evidence/abuse-scenario-suite-1702/scenario-outcomes.json, "
            "docs/security/abuse-scenario-suite.md, docs/security/security-signoff-checklist.md"
        )

    workflow_text = workflow_path.read_text(encoding="utf-8")
    missing_signals = [
        name
        for name, pattern in WORKFLOW_PATTERNS.items()
        if not re.search(pattern, workflow_text, flags=re.MULTILINE)
    ]
    if missing_signals:
        errors.append(f"eval workflow missing required toolchain parity signals: {missing_signals}")

    status_counts: Counter[str] = Counter(
        str(issue.get("status") or "").lower() for issue in exportable
    )
    done_count = status_counts.get("done", 0)
    open_count = status_counts.get("open", 0)
    blocked_count = status_counts.get("blocked", 0)

    e20_status_counts: Counter[str] = Counter(
        str(issue.get("status") or "").lower()
        for issue in exportable
        if str(issue.get("id") or "") == "3100" or str(issue.get("dk_parent") or "") == "3100"
    )
    e21_status_counts: Counter[str] = Counter(
        str(issue.get("status") or "").lower()
        for issue in exportable
        if str(issue.get("id") or "") == "3200" or str(issue.get("dk_parent") or "") == "3200"
    )

    roadmap_status_text = roadmap_status_doc_path.read_text(encoding="utf-8")

    parsed_values: dict[str, str | int] = {}
    for key, pattern in ROADMAP_STATUS_PATTERNS.items():
        match = re.search(pattern, roadmap_status_text, flags=re.IGNORECASE | re.MULTILINE)
        if not match:
            errors.append(f"{ROADMAP_STATUS_DOC} missing roadmap status claim field: {key}")
            continue
        parsed_values[key] = match.group(1).strip()

    expected_claims = {
        "total": len(exportable),
        "done": done_count,
        "open": open_count,
        "blocked": blocked_count,
        "e20_mix": _format_status_counts(dict(e20_status_counts)),
        "e21_mix": _format_status_counts(dict(e21_status_counts)),
    }
    for key, expected in expected_claims.items():
        actual = parsed_values.get(key)
        if actual is None:
            continue
        if isinstance(expected, int):
            try:
                if int(str(actual)) != expected:
                    errors.append(
                        f"{ROADMAP_STATUS_DOC} claim mismatch for {key}: expected {expected}, found {actual}"
                    )
            except Exception:
                errors.append(
                    f"{ROADMAP_STATUS_DOC} claim for {key} is not an integer: {actual}"
                )
        elif str(actual) != expected:
            errors.append(
                f"{ROADMAP_STATUS_DOC} claim mismatch for {key}: expected '{expected}', found '{actual}'"
            )

    notes.append(
        f"roadmap exportable issues: {len(exportable)} total, done={done_count}, open={open_count}, blocked={blocked_count}"
    )
    notes.append(f"canonical issues source: {issues_source}")
    notes.append(f"E20 status mix: {_format_status_counts(dict(e20_status_counts))}")
    notes.append(f"E21 status mix: {_format_status_counts(dict(e21_status_counts))}")
    notes.append(f"csv parity checked for {len(csv_rows)} rows")
    notes.append(f"required evidence files present: {len(REQUIRED_EVIDENCE_FILES) - len(missing_evidence)}/{len(REQUIRED_EVIDENCE_FILES)}")
    notes.append(f"security checksum entries verified: {checksum_verified}")

    return errors, notes


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    errors, notes = validate(repo_root)

    if errors:
        print("[validate-roadmap] FAILED")
        for item in errors:
            print(f"[validate-roadmap] ERROR: {item}")
        for item in notes:
            print(f"[validate-roadmap] note: {item}")
        return 1

    print("[validate-roadmap] OK")
    for item in notes:
        print(f"[validate-roadmap] {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
