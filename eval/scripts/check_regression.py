#!/usr/bin/env python3
"""Check smoke metrics for regression against baseline snapshot.

Exit codes:
  0 - All metrics pass (no regression)
  1 - Regression detected (metrics below threshold)
  2 - Error (missing files, invalid JSON, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MetricResult:
    area: str
    name: str
    current: float
    baseline: float
    threshold: float
    passed: bool

    @property
    def delta(self) -> float:
        return self.current - self.baseline


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to load {path}: {exc}") from exc


def check_metrics(
    current_path: Path,
    baseline_path: Path,
) -> tuple[list[MetricResult], bool]:
    """Compare current metrics against baseline thresholds.

    Returns:
        Tuple of (list of results, overall pass/fail)
    """
    current = load_json(current_path)
    baseline = load_json(baseline_path)

    if current.get("schema_version") != 1:
        raise ValueError("current metrics has unsupported schema_version")
    baseline_version = baseline.get("schema_version")
    if baseline_version not in (1, 2):
        raise ValueError("baseline has unsupported schema_version")

    current_metrics = current.get("metrics", {})
    baseline_metrics = baseline.get("metrics", {})

    results: list[MetricResult] = []
    all_passed = True

    for area, area_thresholds in baseline_metrics.items():
        current_area = current_metrics.get(area, {})

        for metric_name, threshold_info in area_thresholds.items():
            if not isinstance(threshold_info, dict):
                continue

            # Support both schema v1 (baseline key) and v2 (value key)
            baseline_value = threshold_info.get("value", threshold_info.get("baseline", 0.0))
            min_threshold = threshold_info.get("min_threshold", baseline_value)

            current_value = current_area.get(metric_name)
            if current_value is None:
                # Metric missing from current run - treat as 0
                current_value = 0.0

            passed = current_value >= min_threshold
            if not passed:
                all_passed = False

            results.append(
                MetricResult(
                    area=area,
                    name=metric_name,
                    current=current_value,
                    baseline=baseline_value,
                    threshold=min_threshold,
                    passed=passed,
                )
            )

    return results, all_passed


def format_results(results: list[MetricResult], verbose: bool = False) -> str:
    lines: list[str] = []

    areas: dict[str, list[MetricResult]] = {}
    for r in results:
        areas.setdefault(r.area, []).append(r)

    for area in sorted(areas.keys()):
        lines.append(f"\n[{area}]")
        for r in sorted(areas[area], key=lambda x: x.name):
            status = "PASS" if r.passed else "FAIL"
            delta_str = f"{r.delta:+.4f}" if r.delta != 0 else "0"
            lines.append(
                f"  {r.name}: {r.current:.4f} (baseline: {r.baseline:.4f}, "
                f"threshold: {r.threshold:.4f}, delta: {delta_str}) [{status}]"
            )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check metrics for regression")
    parser.add_argument(
        "--current",
        type=Path,
        default=Path("eval/output/smoke/metrics.json"),
        help="Path to current metrics JSON",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("eval/snapshots/baseline.json"),
        help="Path to baseline snapshot JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write results JSON to this path (optional)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output",
    )
    args = parser.parse_args(argv)

    try:
        results, all_passed = check_metrics(args.current, args.baseline)
    except ValueError as exc:
        print(f"[regression] ERROR: {exc}", file=sys.stderr)
        return 2

    print("[regression] Smoke metrics regression check")
    print(format_results(results, verbose=args.verbose))

    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)

    if all_passed:
        print(f"\n[regression] PASSED ({passed_count}/{total_count} metrics OK)")
    else:
        failed = [r for r in results if not r.passed]
        print(f"\n[regression] FAILED ({len(failed)} metric(s) below threshold)")
        for r in failed:
            print(f"  - {r.area}/{r.name}: {r.current:.4f} < {r.threshold:.4f}")

    if args.output:
        output_data = {
            "schema_version": 1,
            "passed": all_passed,
            "results": [
                {
                    "area": r.area,
                    "name": r.name,
                    "current": r.current,
                    "baseline": r.baseline,
                    "threshold": r.threshold,
                    "delta": r.delta,
                    "passed": r.passed,
                }
                for r in results
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(output_data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[regression] wrote {args.output}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
