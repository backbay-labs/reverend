#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GateRule:
    metric_name: str
    operator: str
    threshold: float
    severity: str
    action: str


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_gate_rules(thresholds: dict[str, Any]) -> list[GateRule]:
    gates = thresholds.get("gates") or {}
    rules: list[GateRule] = []
    for metric_name, raw in gates.items():
        if not isinstance(raw, dict):
            continue
        rules.append(
            GateRule(
                metric_name=metric_name,
                operator=str(raw.get("operator", "==")),
                threshold=float(raw.get("threshold", 0.0)),
                severity=str(raw.get("severity", "warning")),
                action=str(raw.get("action", "Investigate and remediate.")),
            )
        )
    return rules


def _compare(observed: float, operator: str, threshold: float) -> bool:
    if operator == ">=":
        return observed >= threshold
    if operator == "<=":
        return observed <= threshold
    if operator == "==":
        return math.isclose(observed, threshold, rel_tol=0.0, abs_tol=1e-9)
    raise ValueError(f"unsupported operator: {operator}")


def _load_runs(artifacts_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    runs: list[dict[str, Any]] = []
    source_artifacts: list[dict[str, Any]] = []
    for path in sorted(artifacts_dir.glob("*.json")):
        payload = _load_json(path)
        run_id = str(payload.get("run_id", path.stem))
        timestamp = str(payload.get("timestamp", ""))
        metrics = payload.get("metrics") or {}
        if not isinstance(metrics, dict):
            metrics = {}
        runs.append(
            {
                "run_id": run_id,
                "timestamp": timestamp,
                "commit_sha": payload.get("commit_sha"),
                "metrics": metrics,
            }
        )
        source_artifacts.append(
            {
                "path": str(path),
                "run_id": run_id,
                "timestamp": timestamp,
                "sha256": _sha256(path),
            }
        )

    runs.sort(key=lambda r: (str(r.get("timestamp", "")), str(r.get("run_id", ""))))
    return runs, source_artifacts


def _build_alerts(current_run: dict[str, Any], rules: list[GateRule]) -> list[dict[str, Any]]:
    metrics = current_run.get("metrics") or {}
    alerts: list[dict[str, Any]] = []
    for rule in rules:
        raw_value = metrics.get(rule.metric_name)
        if raw_value is None:
            alerts.append(
                {
                    "metric_name": rule.metric_name,
                    "status": "missing",
                    "severity": rule.severity,
                    "action": rule.action,
                }
            )
            continue
        observed = float(raw_value)
        passed = _compare(observed, rule.operator, rule.threshold)
        if passed:
            continue
        alerts.append(
            {
                "metric_name": rule.metric_name,
                "operator": rule.operator,
                "threshold": rule.threshold,
                "observed": observed,
                "status": "breach",
                "severity": rule.severity,
                "action": rule.action,
                "run_id": current_run.get("run_id"),
            }
        )
    return alerts


def _build_trend(runs: list[dict[str, Any]], rules: list[GateRule]) -> dict[str, Any]:
    trend: dict[str, Any] = {}
    for rule in rules:
        history = []
        for run in runs:
            metrics = run.get("metrics") or {}
            if rule.metric_name in metrics:
                history.append(
                    {
                        "run_id": run.get("run_id"),
                        "timestamp": run.get("timestamp"),
                        "value": float(metrics[rule.metric_name]),
                    }
                )
        delta = 0.0
        if len(history) >= 2:
            delta = history[-1]["value"] - history[-2]["value"]
        trend[rule.metric_name] = {
            "history": history,
            "delta": round(delta, 10),
        }
    return trend


def _write_markdown(path: Path, dashboard: dict[str, Any], alerts: dict[str, Any]) -> None:
    current = dashboard.get("current_run") or {}
    lines = [
        "# MVP Gate Dashboard",
        "",
        "## Gate Status",
        "",
        f"- Current run: `{current.get('run_id', 'unknown')}`",
        f"- Status: `{current.get('status', 'unknown')}`",
        f"- Run count: `{dashboard.get('run_count', 0)}`",
        "",
        "## Alerts",
        "",
    ]
    alert_list = alerts.get("alerts") or []
    if not alert_list:
        lines.append("- No active breaches.")
    else:
        for alert in alert_list:
            lines.append(
                f"- `{alert.get('metric_name')}`: {alert.get('status')} "
                f"(severity: {alert.get('severity')}) -> {alert.get('action')}"
            )

    lines.extend(["", "## Source Artifacts", ""])
    for artifact in dashboard.get("source_artifacts") or []:
        lines.append(
            f"- `{artifact.get('run_id')}`: {artifact.get('path')} "
            f"(sha256={artifact.get('sha256')})"
        )
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build MVP gate dashboard from run artifacts.")
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--thresholds", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--fail-on-breach", action="store_true")
    args = parser.parse_args(argv)

    thresholds = _load_json(args.thresholds)
    rules = _parse_gate_rules(thresholds)
    runs, source_artifacts = _load_runs(args.artifacts_dir)

    if not runs:
        raise SystemExit("no run artifacts found")

    current_run = runs[-1]
    alerts_list = _build_alerts(current_run, rules)
    current_run_status = "passed" if not alerts_list else "failed"
    trend = _build_trend(runs, rules)

    dashboard = {
        "schema_version": 1,
        "run_count": len(runs),
        "current_run": {
            "run_id": current_run.get("run_id"),
            "timestamp": current_run.get("timestamp"),
            "commit_sha": current_run.get("commit_sha"),
            "status": current_run_status,
            "metrics": current_run.get("metrics") or {},
        },
        "trend": trend,
        "source_artifacts": source_artifacts,
    }
    alerts = {
        "schema_version": 1,
        "current_run_id": current_run.get("run_id"),
        "alerts": alerts_list,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "dashboard.json").write_text(
        json.dumps(dashboard, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "alerts.json").write_text(
        json.dumps(alerts, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_markdown(args.output_dir / "dashboard.md", dashboard, alerts)

    if args.fail_on_breach and alerts_list:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
