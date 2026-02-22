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
from hashlib import sha256
from pathlib import Path


@dataclass
class MetricResult:
    area: str
    name: str
    current: float | None
    baseline: float
    operator: str
    threshold: float
    passed: bool

    @property
    def delta(self) -> float | None:
        if self.current is None:
            return None
        return self.current - self.baseline


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to load {path}: {exc}") from exc


def _coerce_numeric(value: object, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid numeric value for {field_name}: {value!r}")
    return float(value)


def _format_metric_value(value: float | None) -> str:
    if value is None:
        return "missing"
    return f"{value:.4f}"


def _build_promoted_baseline(
    *,
    current_doc: dict,
    source_path: Path,
    promote_areas: list[str],
    relevance_drop_tolerance: float,
    latency_tolerance_ratio: float,
) -> dict:
    if current_doc.get("schema_version") != 1:
        raise ValueError("current metrics has unsupported schema_version")
    current_metrics = current_doc.get("metrics")
    if not isinstance(current_metrics, dict):
        raise ValueError("current metrics document missing top-level 'metrics' object")

    selected_areas = promote_areas or ["real_target"]
    promoted_metrics: dict[str, dict] = {}
    for area in sorted(selected_areas):
        area_metrics = current_metrics.get(area)
        if not isinstance(area_metrics, dict):
            raise ValueError(f"cannot promote area {area!r}: missing or invalid metrics area")

        promoted_area: dict[str, dict] = {}
        for metric_name, metric_value in sorted(area_metrics.items(), key=lambda item: item[0]):
            if isinstance(metric_value, bool) or not isinstance(metric_value, (int, float)):
                continue
            numeric_value = float(metric_value)

            if metric_name.startswith("latency_") and metric_name.endswith("_ms"):
                max_threshold = numeric_value * (1.0 + latency_tolerance_ratio)
                promoted_area[metric_name] = {
                    "value": round(numeric_value, 6),
                    "operator": "<=",
                    "max_threshold": round(max_threshold, 6),
                }
            else:
                min_threshold = max(numeric_value - relevance_drop_tolerance, 0.0)
                promoted_area[metric_name] = {
                    "value": round(numeric_value, 6),
                    "operator": ">=",
                    "min_threshold": round(min_threshold, 6),
                }

        if not promoted_area:
            raise ValueError(f"cannot promote area {area!r}: no numeric metrics found")
        promoted_metrics[area] = promoted_area

    return {
        "schema_version": 3,
        "kind": "deterministic_eval_baseline_snapshot",
        "description": "Promoted baseline snapshot from smoke metrics",
        "source_current_file": str(source_path),
        "source_current_sha256": sha256(
            json.dumps(current_doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "source_current_schema_version": int(current_doc.get("schema_version", 0) or 0),
        "promote_areas": sorted(selected_areas),
        "tolerances": {
            "relevance_drop_tolerance": round(relevance_drop_tolerance, 6),
            "latency_tolerance_ratio": round(latency_tolerance_ratio, 6),
        },
        "metrics": promoted_metrics,
    }


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
    if baseline_version not in (1, 2, 3):
        raise ValueError("baseline has unsupported schema_version")

    current_metrics = current.get("metrics", {})
    baseline_metrics = baseline.get("metrics", {})
    if not isinstance(current_metrics, dict):
        raise ValueError("current metrics payload missing top-level metrics object")
    if not isinstance(baseline_metrics, dict):
        raise ValueError("baseline payload missing top-level metrics object")

    results: list[MetricResult] = []
    all_passed = True

    for area in sorted(baseline_metrics.keys()):
        area_thresholds = baseline_metrics[area]
        if not isinstance(area_thresholds, dict):
            continue
        current_area = current_metrics.get(area, {})
        if not isinstance(current_area, dict):
            current_area = {}

        for metric_name in sorted(area_thresholds.keys()):
            threshold_info = area_thresholds[metric_name]
            if not isinstance(threshold_info, dict):
                continue

            # Support both schema v1 (baseline key) and v2 (value key)
            baseline_value = _coerce_numeric(
                threshold_info.get("value", threshold_info.get("baseline", 0.0)),
                field_name=f"{area}/{metric_name}.value",
            )
            operator = str(threshold_info.get("operator", ">=")).strip() or ">="
            if operator not in (">=", "<="):
                raise ValueError(
                    f"invalid operator for {area}/{metric_name}: {operator!r} (expected '>=' or '<=')"
                )

            if operator == "<=":
                threshold = _coerce_numeric(
                    threshold_info.get("max_threshold", baseline_value),
                    field_name=f"{area}/{metric_name}.max_threshold",
                )
            else:
                threshold = _coerce_numeric(
                    threshold_info.get("min_threshold", baseline_value),
                    field_name=f"{area}/{metric_name}.min_threshold",
                )

            current_raw = current_area.get(metric_name)
            current_value: float | None
            if isinstance(current_raw, bool) or not isinstance(current_raw, (int, float)):
                current_value = None
            else:
                current_value = float(current_raw)

            if current_value is None:
                passed = False
            elif operator == "<=":
                passed = current_value <= threshold
            else:
                passed = current_value >= threshold
            if not passed:
                all_passed = False

            results.append(
                MetricResult(
                    area=area,
                    name=metric_name,
                    current=current_value,
                    baseline=baseline_value,
                    operator=operator,
                    threshold=threshold,
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
            if r.delta is None:
                delta_str = "N/A"
            elif r.delta == 0:
                delta_str = "0"
            else:
                delta_str = f"{r.delta:+.4f}"
            lines.append(
                f"  {r.name}: {_format_metric_value(r.current)} (baseline: {r.baseline:.4f}, "
                f"threshold: {r.operator} {r.threshold:.4f}, delta: {delta_str}) [{status}]"
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
    parser.add_argument(
        "--promote-baseline",
        type=Path,
        default=None,
        help="Promote --current metrics into a deterministic baseline snapshot and exit",
    )
    parser.add_argument(
        "--promote-area",
        action="append",
        default=None,
        help="Metric area to include when promoting a baseline (repeatable, default: real_target)",
    )
    parser.add_argument(
        "--relevance-drop-tolerance",
        type=float,
        default=0.05,
        help="Absolute tolerance for non-latency promoted metrics (default: 0.05)",
    )
    parser.add_argument(
        "--latency-tolerance-ratio",
        type=float,
        default=0.20,
        help="Relative tolerance for promoted latency metrics (default: 0.20 -> +20%%)",
    )
    args = parser.parse_args(argv)

    if args.promote_baseline is not None:
        if args.relevance_drop_tolerance < 0:
            print("[regression] ERROR: --relevance-drop-tolerance must be >= 0", file=sys.stderr)
            return 2
        if args.latency_tolerance_ratio < 0:
            print("[regression] ERROR: --latency-tolerance-ratio must be >= 0", file=sys.stderr)
            return 2
        try:
            promoted = _build_promoted_baseline(
                current_doc=load_json(args.current),
                source_path=args.current,
                promote_areas=args.promote_area or [],
                relevance_drop_tolerance=args.relevance_drop_tolerance,
                latency_tolerance_ratio=args.latency_tolerance_ratio,
            )
        except ValueError as exc:
            print(f"[regression] ERROR: {exc}", file=sys.stderr)
            return 2
        args.promote_baseline.parent.mkdir(parents=True, exist_ok=True)
        args.promote_baseline.write_text(
            json.dumps(promoted, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"[regression] promoted baseline -> {args.promote_baseline}")
        return 0

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
            if r.current is None:
                print(f"  - {r.area}/{r.name}: missing metric")
            else:
                print(
                    f"  - {r.area}/{r.name}: {r.current:.4f} not {r.operator} {r.threshold:.4f}"
                )

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
                    "operator": r.operator,
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
