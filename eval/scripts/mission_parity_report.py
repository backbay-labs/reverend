#!/usr/bin/env python3
"""Build mission DSL parity artifacts and enforce headless/UI semantic parity."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REQUIRED_FLOWS = ("mission_launch", "checkpoint_resume", "artifact_export")
EPHEMERAL_KEYS = {
    "generated_at",
    "generated_at_utc",
    "updated_at",
    "created_at",
    "timestamp",
    "started_at",
    "finished_at",
    "ui_session_id",
    "export_path",
    "checkpoint_path",
}


@dataclass(frozen=True)
class Mismatch:
    flow: str
    kind: str
    path: str
    headless: Any
    cockpit: Any

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow": self.flow,
            "kind": self.kind,
            "path": self.path,
            "headless": self.headless,
            "cockpit": self.cockpit,
        }


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected top-level JSON object")
    return payload


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key in sorted(value):
            if key in EPHEMERAL_KEYS:
                continue
            normalized[key] = _normalize(value[key])
        return normalized
    if isinstance(value, list):
        items = [_normalize(item) for item in value]
        if all(isinstance(item, dict) for item in items):
            def _sort_key(item: dict[str, Any]) -> tuple[str, str]:
                for candidate in ("artifact_id", "id", "name", "stage_id"):
                    if candidate in item:
                        return candidate, str(item[candidate])
                return "", json.dumps(item, sort_keys=True, separators=(",", ":"))

            return sorted(items, key=_sort_key)
        return items
    return value


def _normalize_artifact_export(flow: Any) -> Any:
    if not isinstance(flow, dict):
        return _normalize(flow)
    normalized = _normalize(flow)
    if not isinstance(normalized, dict):
        return normalized

    artifacts = normalized.get("artifacts")
    if not isinstance(artifacts, list):
        return normalized

    artifact_map: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_id = str(artifact.get("artifact_id") or artifact.get("name") or "").strip()
        if not artifact_id:
            continue
        artifact_map[artifact_id] = {
            "sha256": artifact.get("sha256"),
            "semantic_type": artifact.get("semantic_type"),
            "bytes": artifact.get("bytes", artifact.get("size_bytes")),
        }
    normalized["artifacts"] = artifact_map
    return normalized


def _flow_payload(doc: dict[str, Any], flow: str) -> Any:
    flows = doc.get("flows")
    if isinstance(flows, dict):
        return flows.get(flow)
    return None


def _compare_flow(flow: str, headless: Any, cockpit: Any) -> list[Mismatch]:
    left = _normalize_artifact_export(headless) if flow == "artifact_export" else _normalize(headless)
    right = _normalize_artifact_export(cockpit) if flow == "artifact_export" else _normalize(cockpit)
    if left == right:
        return []
    return [Mismatch(flow=flow, kind="value_mismatch", path=flow, headless=left, cockpit=right)]


def build_report(headless_doc: dict[str, Any], cockpit_doc: dict[str, Any], *, headless_path: Path, cockpit_path: Path) -> dict[str, Any]:
    mismatches: list[Mismatch] = []
    covered_flows: list[str] = []

    for flow in REQUIRED_FLOWS:
        left = _flow_payload(headless_doc, flow)
        right = _flow_payload(cockpit_doc, flow)
        if left is None or right is None:
            mismatches.append(
                Mismatch(
                    flow=flow,
                    kind="missing_flow",
                    path=flow,
                    headless=left is not None,
                    cockpit=right is not None,
                )
            )
            continue
        covered_flows.append(flow)
        mismatches.extend(_compare_flow(flow, left, right))

    output = {
        "schema_version": 1,
        "kind": "mission_dsl_headless_ui_parity_report",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "required_flows": list(REQUIRED_FLOWS),
        "source": {
            "headless_path": str(headless_path),
            "headless_sha256": _sha256(headless_path),
            "cockpit_path": str(cockpit_path),
            "cockpit_sha256": _sha256(cockpit_path),
        },
        "evaluation": {
            "passed": len(mismatches) == 0,
            "covered_flows": covered_flows,
            "mismatch_count": len(mismatches),
        },
        "mismatches": [item.to_dict() for item in mismatches],
    }
    return output


def _render_markdown(report: dict[str, Any]) -> str:
    evaluation = report.get("evaluation", {})
    passed = bool(evaluation.get("passed"))
    lines = [
        "# E25 Mission DSL Headless/UI Parity Report",
        "",
        f"- Status: {'PASS' if passed else 'FAIL'}",
        f"- Required flows: {', '.join(report.get('required_flows', []))}",
        f"- Covered flows: {', '.join(evaluation.get('covered_flows', []))}",
        f"- Mismatch count: {evaluation.get('mismatch_count', 0)}",
        "",
        "## Inputs",
        f"- Headless artifact: `{report['source']['headless_path']}` (sha256={report['source']['headless_sha256']})",
        f"- Cockpit artifact: `{report['source']['cockpit_path']}` (sha256={report['source']['cockpit_sha256']})",
        "",
    ]
    mismatches = report.get("mismatches", [])
    if mismatches:
        lines.append("## Mismatches")
        for row in mismatches:
            lines.append(
                f"- `{row.get('flow')}` `{row.get('kind')}`: path=`{row.get('path')}`"
            )
    else:
        lines.append("## Mismatches")
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and enforce headless/UI mission parity report.")
    parser.add_argument("--headless", type=Path, required=True, help="Headless mission output JSON")
    parser.add_argument("--cockpit", type=Path, required=True, help="Cockpit mission output JSON")
    parser.add_argument("--output-json", type=Path, required=True, help="Output parity JSON report")
    parser.add_argument("--output-md", type=Path, required=True, help="Output parity markdown report")
    parser.add_argument("--fail-on-mismatch", action="store_true", help="Exit non-zero when semantic mismatches are found")
    args = parser.parse_args(argv)

    try:
        headless_doc = _load_json(args.headless)
        cockpit_doc = _load_json(args.cockpit)
        report = build_report(
            headless_doc,
            cockpit_doc,
            headless_path=args.headless,
            cockpit_path=args.cockpit,
        )
    except Exception as exc:
        print(f"[mission-parity] ERROR: {exc}")
        return 1

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output_md.write_text(_render_markdown(report), encoding="utf-8")

    if args.fail_on_mismatch and not bool(report.get("evaluation", {}).get("passed")):
        print("[mission-parity] FAIL: semantic parity mismatches detected")
        return 1

    print("[mission-parity] OK: parity report generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
