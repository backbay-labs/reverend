#!/usr/bin/env python3
"""Build reliability SLO artifacts from soak output and enforce thresholds.

Outputs:
  - machine-readable JSON report
  - markdown summary report

Exit codes:
  0 - report built and thresholds passed (or fail-on-breach disabled)
  1 - thresholds breached with --fail-on-breach
  2 - invalid input or processing error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SloRule:
    metric_name: str
    operator: str
    threshold: float
    severity: str
    description: str


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_rules(payload: dict[str, Any]) -> list[SloRule]:
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        return []

    rules: list[SloRule] = []
    for metric_name, raw in metrics.items():
        if not isinstance(raw, dict):
            continue
        rules.append(
            SloRule(
                metric_name=str(metric_name),
                operator=str(raw.get("operator", "==")),
                threshold=float(raw.get("threshold", 0.0)),
                severity=str(raw.get("severity", "warning")),
                description=str(raw.get("description", "")),
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


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _compute_metrics(soak: dict[str, Any]) -> tuple[dict[str, float], dict[str, int]]:
    iterations_raw = soak.get("iterations")
    iterations = iterations_raw if isinstance(iterations_raw, list) else []

    declared_iterations = int(_float((soak.get("soak_test") or {}).get("iterations"), 0.0))
    observed_iterations = len(iterations)
    total_iterations = observed_iterations if observed_iterations > 0 else declared_iterations
    denominator = total_iterations if total_iterations > 0 else 1

    completed_iterations = 0
    successful_completions = 0
    deadlock_iterations = 0
    fallback_iterations = 0
    error_iterations = 0

    for row in iterations:
        if not isinstance(row, dict):
            continue
        reliability = row.get("reliability")
        if not isinstance(reliability, dict):
            reliability = {}

        has_metrics = isinstance(row.get("metrics"), dict) and bool(row.get("metrics"))
        has_error_field = isinstance(row.get("error"), dict)

        completed = bool(reliability.get("completed", has_metrics and not has_error_field))
        deadlock = bool(reliability.get("deadlock", False))
        fallback = bool(reliability.get("fallback_applied", False))
        error = bool(reliability.get("error", has_error_field))

        if completed:
            completed_iterations += 1
        if deadlock:
            deadlock_iterations += 1
        if fallback:
            fallback_iterations += 1
        if error:
            error_iterations += 1
        if completed and not deadlock and not error:
            successful_completions += 1

    rates = {
        "deadlock_rate": round(deadlock_iterations / denominator, 6),
        "fallback_rate": round(fallback_iterations / denominator, 6),
        "error_rate": round(error_iterations / denominator, 6),
        "successful_completion_slo": round(successful_completions / denominator, 6),
    }
    counts = {
        "total_iterations": total_iterations,
        "completed_iterations": completed_iterations,
        "successful_completions": successful_completions,
        "deadlock_iterations": deadlock_iterations,
        "fallback_iterations": fallback_iterations,
        "error_iterations": error_iterations,
    }
    return rates, counts


def _evaluate(metrics: dict[str, float], rules: list[SloRule]) -> list[dict[str, Any]]:
    breaches: list[dict[str, Any]] = []
    for rule in rules:
        observed = metrics.get(rule.metric_name)
        if observed is None:
            breaches.append(
                {
                    "metric_name": rule.metric_name,
                    "status": "missing",
                    "severity": rule.severity,
                    "description": rule.description,
                }
            )
            continue
        passed = _compare(observed, rule.operator, rule.threshold)
        if passed:
            continue
        breaches.append(
            {
                "metric_name": rule.metric_name,
                "status": "breach",
                "operator": rule.operator,
                "threshold": rule.threshold,
                "observed": observed,
                "severity": rule.severity,
                "description": rule.description,
            }
        )
    return breaches


def _write_markdown(
    path: Path,
    *,
    source_path: Path,
    source_sha256: str,
    metrics: dict[str, float],
    counts: dict[str, int],
    rules: list[SloRule],
    breaches: list[dict[str, Any]],
) -> None:
    status = "PASS" if not breaches else "FAIL"
    lines = [
        "# Reliability SLO Report",
        "",
        "## Overview",
        "",
        f"- Source soak report: `{source_path}`",
        f"- Source SHA256: `{source_sha256}`",
        f"- Status: `{status}`",
        "",
        "## Reliability Metrics",
        "",
        "| Metric | Observed |",
        "| --- | ---: |",
        f"| deadlock_rate | {metrics.get('deadlock_rate', 0.0):.6f} |",
        f"| fallback_rate | {metrics.get('fallback_rate', 0.0):.6f} |",
        f"| error_rate | {metrics.get('error_rate', 0.0):.6f} |",
        f"| successful_completion_slo | {metrics.get('successful_completion_slo', 0.0):.6f} |",
        "",
        "## Iteration Counts",
        "",
        "| Counter | Value |",
        "| --- | ---: |",
        f"| total_iterations | {counts.get('total_iterations', 0)} |",
        f"| completed_iterations | {counts.get('completed_iterations', 0)} |",
        f"| successful_completions | {counts.get('successful_completions', 0)} |",
        f"| deadlock_iterations | {counts.get('deadlock_iterations', 0)} |",
        f"| fallback_iterations | {counts.get('fallback_iterations', 0)} |",
        f"| error_iterations | {counts.get('error_iterations', 0)} |",
        "",
        "## Threshold Evaluation",
        "",
        "| Metric | Rule | Status |",
        "| --- | --- | --- |",
    ]

    for rule in rules:
        observed = metrics.get(rule.metric_name)
        if observed is None:
            lines.append(
                f"| {rule.metric_name} | `{rule.operator} {rule.threshold}` | MISSING |"
            )
            continue
        rule_status = "PASS" if _compare(observed, rule.operator, rule.threshold) else "FAIL"
        lines.append(
            f"| {rule.metric_name} | `{rule.operator} {rule.threshold}` | {rule_status} (observed={observed:.6f}) |"
        )

    lines.extend(["", "## Breaches", ""])
    if not breaches:
        lines.append("- No SLO breaches.")
    else:
        for breach in breaches:
            lines.append(
                f"- `{breach.get('metric_name')}`: {breach.get('status')}"
                f" (severity: {breach.get('severity', 'unknown')})"
            )

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build reliability SLO report from soak artifact.")
    parser.add_argument("--soak-report", type=Path, required=True, help="Input soak report JSON")
    parser.add_argument("--thresholds", type=Path, required=True, help="SLO threshold config JSON")
    parser.add_argument("--output-json", type=Path, required=True, help="Output reliability JSON report")
    parser.add_argument("--output-md", type=Path, required=True, help="Output reliability markdown report")
    parser.add_argument("--fail-on-breach", action="store_true", help="Return non-zero when thresholds breach")
    args = parser.parse_args(argv)

    try:
        soak_report = _load_json(args.soak_report)
        thresholds = _load_json(args.thresholds)
    except Exception as exc:
        print(f"[reliability] ERROR: {exc}")
        return 2

    rules = _parse_rules(thresholds)
    metrics, counts = _compute_metrics(soak_report)
    breaches = _evaluate(metrics, rules)

    output = {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "soak_report_path": str(args.soak_report),
            "soak_report_sha256": _sha256(args.soak_report),
            "thresholds_path": str(args.thresholds),
            "thresholds_sha256": _sha256(args.thresholds),
        },
        "metrics": metrics,
        "counts": counts,
        "thresholds": {
            "schema_version": int(_float(thresholds.get("schema_version"), 1.0)),
            "metrics": thresholds.get("metrics") if isinstance(thresholds.get("metrics"), dict) else {},
        },
        "evaluation": {
            "passed": len(breaches) == 0,
            "breaches": breaches,
        },
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(
        args.output_md,
        source_path=args.soak_report,
        source_sha256=output["source"]["soak_report_sha256"],
        metrics=metrics,
        counts=counts,
        rules=rules,
        breaches=breaches,
    )

    if args.fail_on_breach and breaches:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
