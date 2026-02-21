#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
csv_path="${CYNTRA_BACKLOG_CSV_PATH:-$repo_root/docs/backlog-jira-linear.csv}"
issues_path="${CYNTRA_ISSUES_PATH:-$repo_root/.beads/issues.jsonl}"
issues_ref="${CYNTRA_ISSUES_REF:-HEAD}"

python3 - "$repo_root" "$csv_path" "$issues_path" "$issues_ref" <<'PY'
import csv
import json
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
csv_path = Path(sys.argv[2])
issues_path = Path(sys.argv[3])
issues_ref = sys.argv[4]

fieldnames = [
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


def load_issues() -> tuple[list[dict], str]:
    if issues_path.exists():
        text = issues_path.read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()], str(issues_path)

    source = f"{issues_ref}:.beads/issues.jsonl"
    text = subprocess.check_output(
        ["git", "-C", str(repo_root), "show", source],
        text=True,
    )
    return [json.loads(line) for line in text.splitlines() if line.strip()], source


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
    issue_type = parse_issue_type(tags)
    if issue_type not in {"Epic", "Story"}:
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


issues, source_used = load_issues()
exportable_issues = [issue for issue in issues if is_exportable(issue)]
exportable_issues.sort(
    key=lambda issue: (
        0 if parse_issue_type([str(tag) for tag in issue.get("tags") or []]) == "Epic" else 1,
        numeric_id(str(issue.get("id") or "")),
        str(issue.get("id") or ""),
    )
)

existing_rows: dict[str, dict[str, str]] = {}
if csv_path.exists():
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            issue_id = str(row.get("id") or "")
            if issue_id:
                existing_rows[issue_id] = row

rows: list[dict[str, str]] = []
added_rows = 0
updated_statuses = 0
for issue in exportable_issues:
    issue_id = str(issue.get("id") or "")
    issue_status = str(issue.get("status") or "").lower()
    existing = existing_rows.get(issue_id)
    if existing:
        row = {name: str(existing.get(name) or "") for name in fieldnames}
        if row.get("status", "").lower() != issue_status:
            updated_statuses += 1
        row["id"] = issue_id
        row["status"] = issue_status
    else:
        row = to_row(issue)
        added_rows += 1
    rows.append(row)

csv_path.parent.mkdir(parents=True, exist_ok=True)
with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

status_counts: dict[str, int] = {}
for row in rows:
    status = row["status"] or "unknown"
    status_counts[status] = status_counts.get(status, 0) + 1
status_summary = ", ".join(f"{name}={status_counts[name]}" for name in sorted(status_counts))

try:
    csv_display = str(csv_path.relative_to(repo_root))
except ValueError:
    csv_display = str(csv_path)

print(
    f"[sync-backlog-csv] wrote {len(rows)} roadmap rows to {csv_display} "
    f"from {source_used} (added={added_rows}, status_updates={updated_statuses}, {status_summary})"
)
PY
