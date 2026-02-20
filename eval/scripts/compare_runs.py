#!/usr/bin/env python3
"""Compare current smoke metrics against a previous run.

Used for nightly regression detection by comparing against the previous
nightly baseline rather than the static snapshot.

Exit codes:
  0 - All metrics within tolerance (no regression)
  1 - Regression detected (metric dropped beyond tolerance)
  2 - Error (missing files, invalid JSON, etc.)
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ComparisonResult:
    area: str
    name: str
    current: float
    previous: float
    tolerance: float
    passed: bool

    @property
    def delta(self) -> float:
        return self.current - self.previous

    @property
    def regression(self) -> bool:
        return self.delta < -self.tolerance


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to load {path}: {exc}") from exc


def compare_runs(
    current_path: Path,
    previous_path: Path,
    tolerance: float = 0.05,
) -> tuple[list[ComparisonResult], bool]:
    """Compare current metrics against previous run.

    Args:
        current_path: Path to current metrics JSON
        previous_path: Path to previous metrics JSON
        tolerance: Max acceptable drop (absolute) before flagging regression

    Returns:
        Tuple of (list of results, overall pass/fail)
    """
    current = load_json(current_path)
    previous = load_json(previous_path)

    if current.get("schema_version") != 1:
        raise ValueError("current metrics has unsupported schema_version")
    if previous.get("schema_version") != 1:
        raise ValueError("previous metrics has unsupported schema_version")

    current_metrics = current.get("metrics", {})
    previous_metrics = previous.get("metrics", {})

    results: list[ComparisonResult] = []
    all_passed = True

    for area, area_metrics in previous_metrics.items():
        current_area = current_metrics.get(area, {})

        for metric_name, prev_value in area_metrics.items():
            if not isinstance(prev_value, (int, float)):
                continue

            curr_value = current_area.get(metric_name)
            if curr_value is None:
                curr_value = 0.0
            if not isinstance(curr_value, (int, float)):
                continue

            delta = curr_value - prev_value
            passed = delta >= -tolerance

            if not passed:
                all_passed = False

            results.append(
                ComparisonResult(
                    area=area,
                    name=metric_name,
                    current=curr_value,
                    previous=prev_value,
                    tolerance=tolerance,
                    passed=passed,
                )
            )

    return results, all_passed


def format_results(results: list[ComparisonResult]) -> str:
    lines: list[str] = []

    areas: dict[str, list[ComparisonResult]] = {}
    for r in results:
        areas.setdefault(r.area, []).append(r)

    for area in sorted(areas.keys()):
        lines.append(f"\n[{area}]")
        for r in sorted(areas[area], key=lambda x: x.name):
            status = "OK" if r.passed else "REGRESSED"
            delta_str = f"{r.delta:+.4f}"
            lines.append(
                f"  {r.name}: {r.current:.4f} (prev: {r.previous:.4f}, "
                f"delta: {delta_str}, tolerance: {r.tolerance:.4f}) [{status}]"
            )

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare smoke metrics between runs")
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to current metrics JSON",
    )
    parser.add_argument(
        "--previous",
        type=Path,
        required=True,
        help="Path to previous metrics JSON",
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.05,
        help="Max acceptable metric drop (default: 0.05)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write comparison results JSON to this path (optional)",
    )
    args = parser.parse_args(argv)

    if not args.previous.exists():
        print("[compare] No previous baseline found, skipping comparison")
        return 0

    try:
        results, all_passed = compare_runs(
            args.current, args.previous, args.tolerance
        )
    except ValueError as exc:
        print(f"[compare] ERROR: {exc}", file=sys.stderr)
        return 2

    print("[compare] Nightly-to-nightly comparison")
    print(f"[compare] Tolerance: {args.tolerance:.4f}")
    print(format_results(results))

    passed_count = sum(1 for r in results if r.passed)
    total_count = len(results)

    if all_passed:
        print(f"\n[compare] PASSED ({passed_count}/{total_count} metrics within tolerance)")
    else:
        regressed = [r for r in results if not r.passed]
        print(f"\n[compare] REGRESSED ({len(regressed)} metric(s) dropped beyond tolerance)")
        for r in regressed:
            print(f"  - {r.area}/{r.name}: {r.delta:+.4f} (limit: -{r.tolerance:.4f})")

    if args.output:
        output_data = {
            "schema_version": 1,
            "passed": all_passed,
            "tolerance": args.tolerance,
            "current_file": str(args.current),
            "previous_file": str(args.previous),
            "results": [
                {
                    "area": r.area,
                    "name": r.name,
                    "current": r.current,
                    "previous": r.previous,
                    "delta": r.delta,
                    "tolerance": r.tolerance,
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
        print(f"[compare] wrote {args.output}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
