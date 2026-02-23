#!/usr/bin/env python3
"""Build query SLO artifacts from smoke metrics and enforce thresholds.

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
import time
from pathlib import Path
from typing import Any

from check_regression import check_metrics, load_json


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _metric_value(value: float | None) -> str:
    if value is None:
        return "MISSING"
    return f"{value:.6f}"


def _threshold_value(operator: str, threshold: float) -> str:
    return f"{operator} {threshold:.6f}"


def _write_markdown(
    path: Path,
    *,
    metrics_path: Path,
    metrics_sha256: str,
    thresholds_path: Path,
    thresholds_sha256: str,
    results: list[dict[str, Any]],
    passed: bool,
) -> None:
    status = "PASS" if passed else "FAIL"
    lines = [
        "# Query SLO Report",
        "",
        "## Overview",
        "",
        f"- Source smoke metrics: `{metrics_path}`",
        f"- Smoke metrics SHA256: `{metrics_sha256}`",
        f"- Threshold config: `{thresholds_path}`",
        f"- Threshold config SHA256: `{thresholds_sha256}`",
        f"- Status: `{status}`",
        "",
        "## Threshold Evaluation",
        "",
        "| Area | Metric | Rule | Observed | Baseline | Delta | Status |",
        "| --- | --- | --- | ---: | ---: | ---: | --- |",
    ]

    for result in sorted(results, key=lambda row: (str(row["area"]), str(row["name"]))):
        observed = result["current"]
        baseline = result["baseline"]
        delta = result["delta"]
        if observed is None:
            delta_str = "N/A"
        elif delta is None:
            delta_str = "N/A"
        else:
            delta_str = f"{float(delta):+.6f}"
        lines.append(
            f"| {result['area']} | {result['name']} | "
            f"`{_threshold_value(str(result['operator']), float(result['threshold']))}` | "
            f"{_metric_value(observed if isinstance(observed, (int, float)) else None)} | "
            f"{float(baseline):.6f} | {delta_str} | "
            f"{'PASS' if result['passed'] else 'FAIL'} |"
        )

    lines.extend(["", "## Breaches", ""])
    breaches = [result for result in results if not result.get("passed")]
    if not breaches:
        lines.append("- No query SLO breaches.")
    else:
        for breach in sorted(breaches, key=lambda row: (str(row["area"]), str(row["name"]))):
            if breach.get("current") is None:
                lines.append(f"- `{breach['area']}/{breach['name']}`: metric missing from smoke output.")
            else:
                lines.append(
                    f"- `{breach['area']}/{breach['name']}`: observed "
                    f"{float(breach['current']):.6f} not "
                    f"{_threshold_value(str(breach['operator']), float(breach['threshold']))}."
                )

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build query SLO report from smoke metrics.")
    parser.add_argument("--metrics", type=Path, required=True, help="Input smoke metrics JSON")
    parser.add_argument("--thresholds", type=Path, required=True, help="Input query SLO threshold JSON")
    parser.add_argument("--output-json", type=Path, required=True, help="Output query SLO JSON report")
    parser.add_argument("--output-md", type=Path, required=True, help="Output query SLO markdown report")
    parser.add_argument("--fail-on-breach", action="store_true", help="Return non-zero when thresholds breach")
    args = parser.parse_args(argv)

    try:
        thresholds_doc = load_json(args.thresholds)
        results, all_passed = check_metrics(args.metrics, args.thresholds)
    except Exception as exc:
        print(f"[query-slo] ERROR: {exc}")
        return 2

    result_rows: list[dict[str, Any]] = [
        {
            "area": result.area,
            "name": result.name,
            "current": result.current,
            "baseline": result.baseline,
            "operator": result.operator,
            "threshold": result.threshold,
            "delta": result.delta,
            "passed": result.passed,
        }
        for result in results
    ]

    output = {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": {
            "metrics_path": str(args.metrics),
            "metrics_sha256": _sha256(args.metrics),
            "thresholds_path": str(args.thresholds),
            "thresholds_sha256": _sha256(args.thresholds),
        },
        "thresholds": {
            "schema_version": int(thresholds_doc.get("schema_version", 0) or 0),
            "kind": str(thresholds_doc.get("kind", "")),
            "description": str(thresholds_doc.get("description", "")),
        },
        "evaluation": {
            "passed": all_passed,
            "total_metrics": len(result_rows),
            "passed_metrics": sum(1 for row in result_rows if row["passed"]),
            "failed_metrics": sum(1 for row in result_rows if not row["passed"]),
        },
        "results": result_rows,
    }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(
        args.output_md,
        metrics_path=args.metrics,
        metrics_sha256=output["source"]["metrics_sha256"],
        thresholds_path=args.thresholds,
        thresholds_sha256=output["source"]["thresholds_sha256"],
        results=result_rows,
        passed=all_passed,
    )

    if args.fail_on_breach and not all_passed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
