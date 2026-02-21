#!/usr/bin/env python3
"""Soak test runner: repeated smoke evaluation with performance and stability tracking.

Runs the smoke evaluation suite N times (configurable), captures wall-clock
timing per iteration, and generates a report with performance statistics
and metric stability analysis.

Exit codes:
  0 - Soak test passed (all iterations stable, no regressions)
  1 - Stability or regression issue detected
  2 - Error (missing files, invalid JSON, etc.)
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys
import time
from hashlib import sha256
from pathlib import Path

import datasets


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _compute_similarity_metrics(dataset_dir: Path) -> dict:
    corpus = json.loads((dataset_dir / "corpus.json").read_text(encoding="utf-8"))
    queries = json.loads((dataset_dir / "queries.json").read_text(encoding="utf-8"))

    functions = corpus["functions"]
    function_tokens = {
        fn["id"]: _tokens(f"{fn.get('name', '')} {fn.get('text', '')}")
        for fn in functions
    }

    recall_at_1_hits = 0
    mrr_total = 0.0
    total = 0

    for query in queries["queries"]:
        total += 1
        q_tokens = _tokens(query["text"])
        gt = query["ground_truth_id"]

        scored = []
        for fn in functions:
            fid = fn["id"]
            score = _jaccard(q_tokens, function_tokens[fid])
            scored.append((score, fid))

        scored.sort(key=lambda item: (-item[0], item[1]))
        ranked_ids = [fid for _, fid in scored]

        if ranked_ids and ranked_ids[0] == gt:
            recall_at_1_hits += 1

        try:
            rank = ranked_ids.index(gt) + 1
        except ValueError:
            rank = None

        if rank:
            mrr_total += 1.0 / rank

    recall_at_1 = recall_at_1_hits / total if total else 0.0
    mrr = mrr_total / total if total else 0.0

    return {
        "queries": total,
        "recall@1": round(recall_at_1, 6),
        "mrr": round(mrr, 6),
    }


def _predict_type(var_name: str) -> str:
    name = var_name.strip().lower()
    if name.startswith("is_") or name.startswith("has_"):
        return "bool"
    if name in {"ok", "valid"}:
        return "bool"
    if name in {"len", "length", "count", "size"}:
        return "size_t"
    if name in {"buf", "buffer", "data"}:
        return "uint8_t*"
    if name in {"name", "str", "string"}:
        return "char*"
    return "int"


def _compute_type_metrics(dataset_dir: Path) -> dict:
    cases_doc = json.loads((dataset_dir / "cases.json").read_text(encoding="utf-8"))
    cases = cases_doc["cases"]

    total = 0
    correct = 0
    for case in cases:
        total += 1
        predicted = _predict_type(case["var"])
        if predicted == case["ground_truth"]:
            correct += 1

    accuracy = correct / total if total else 0.0
    return {"cases": total, "accuracy": round(accuracy, 6)}


def _compute_diff_metrics(dataset_dir: Path) -> dict:
    left_doc = json.loads((dataset_dir / "left.json").read_text(encoding="utf-8"))
    right_doc = json.loads((dataset_dir / "right.json").read_text(encoding="utf-8"))
    gt_doc = json.loads((dataset_dir / "ground_truth.json").read_text(encoding="utf-8"))

    left_functions = left_doc["functions"]
    right_functions = right_doc["functions"]

    right_by_name: dict[str, list[str]] = {}
    for fn in right_functions:
        right_by_name.setdefault(fn["name"], []).append(fn["id"])
    for ids in right_by_name.values():
        ids.sort()

    predicted: dict[str, str] = {}
    for fn in left_functions:
        candidates = right_by_name.get(fn["name"], [])
        if candidates:
            predicted[fn["id"]] = candidates[0]

    gt_matches = gt_doc["matches"]
    total = len(gt_matches)
    correct = 0
    for match in gt_matches:
        if predicted.get(match["left_id"]) == match["right_id"]:
            correct += 1

    match_rate = correct / total if total else 0.0
    coverage = len(predicted) / len(left_functions) if left_functions else 0.0
    return {
        "pairs": total,
        "match_rate": round(match_rate, 6),
        "coverage": round(coverage, 6),
    }


def _run_one_iteration(data_root: Path, seed: int) -> tuple[dict, float]:
    """Run a single smoke evaluation iteration. Returns (metrics, elapsed_seconds)."""
    random.seed(seed)

    start = time.monotonic()
    metrics = {
        "diff": _compute_diff_metrics(data_root / "toy-diff-v1"),
        "similarity": _compute_similarity_metrics(data_root / "toy-similarity-v1"),
        "type": _compute_type_metrics(data_root / "toy-type-v1"),
    }
    elapsed = time.monotonic() - start

    return metrics, elapsed


def _percentile(sorted_values: list[float], p: float) -> float:
    """Compute percentile from sorted values (linear interpolation)."""
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)


def _compute_stats(values: list[float]) -> dict:
    """Compute summary statistics for a list of values."""
    n = len(values)
    if n == 0:
        return {"count": 0, "mean": 0, "stddev": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}

    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n if n > 1 else 0.0
    stddev = math.sqrt(variance)
    sorted_vals = sorted(values)

    return {
        "count": n,
        "mean": round(mean, 6),
        "stddev": round(stddev, 6),
        "min": round(sorted_vals[0], 6),
        "max": round(sorted_vals[-1], 6),
        "p50": round(_percentile(sorted_vals, 50), 6),
        "p95": round(_percentile(sorted_vals, 95), 6),
        "p99": round(_percentile(sorted_vals, 99), 6),
    }


def _lockfile_sha256(lockfile: Path) -> str:
    return sha256(lockfile.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Soak test runner")
    parser.add_argument(
        "--iterations",
        type=int,
        default=10,
        help="Number of soak iterations (default: 10)",
    )
    parser.add_argument(
        "--lockfile",
        type=Path,
        default=datasets.DEFAULT_LOCKFILE,
        help=f"Path to dataset lockfile (default: {datasets.DEFAULT_LOCKFILE})",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=datasets.DEFAULT_DATA_ROOT,
        help=f"Materialized dataset root (default: {datasets.DEFAULT_DATA_ROOT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("eval/output/soak/report.json"),
        help="Path to soak test report output JSON",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("eval/snapshots/baseline.json"),
        help="Path to baseline snapshot for regression checks",
    )
    parser.add_argument(
        "--stability-tolerance",
        type=float,
        default=0.01,
        help="Max metric stddev before flagging instability (default: 0.01)",
    )
    args = parser.parse_args(argv)

    # Materialize datasets
    try:
        datasets.materialize_datasets(args.lockfile, args.data_root)
    except ValueError as exc:
        print(f"[soak] ERROR: dataset materialization failed: {exc}", file=sys.stderr)
        return 2

    iterations = args.iterations
    print(f"[soak] Starting soak test ({iterations} iterations)")

    # Run iterations
    all_iterations: list[dict] = []
    timing_values: list[float] = []
    metric_series: dict[str, dict[str, list[float]]] = {}

    for i in range(iterations):
        seed = i
        metrics, elapsed = _run_one_iteration(args.data_root, seed)
        timing_values.append(elapsed)

        iteration_record = {
            "iteration": i,
            "seed": seed,
            "elapsed_seconds": round(elapsed, 6),
            "metrics": metrics,
        }
        all_iterations.append(iteration_record)

        # Accumulate metric values for stability analysis
        for area, area_metrics in metrics.items():
            if area not in metric_series:
                metric_series[area] = {}
            for metric_name, value in area_metrics.items():
                if not isinstance(value, (int, float)):
                    continue
                if metric_name not in metric_series[area]:
                    metric_series[area][metric_name] = []
                metric_series[area][metric_name].append(float(value))

        status = f"iter {i+1}/{iterations}: {elapsed*1000:.1f}ms"
        print(f"[soak]   {status}")

    # Compute performance statistics
    perf_stats = _compute_stats(timing_values)
    print(f"\n[soak] Performance: mean={perf_stats['mean']*1000:.1f}ms "
          f"p50={perf_stats['p50']*1000:.1f}ms "
          f"p95={perf_stats['p95']*1000:.1f}ms "
          f"p99={perf_stats['p99']*1000:.1f}ms")

    # Compute stability analysis
    stability_results: dict[str, dict[str, dict]] = {}
    stability_issues: list[str] = []

    for area in sorted(metric_series.keys()):
        stability_results[area] = {}
        for metric_name in sorted(metric_series[area].keys()):
            values = metric_series[area][metric_name]
            stats = _compute_stats(values)
            stable = stats["stddev"] <= args.stability_tolerance

            stability_results[area][metric_name] = {
                "stats": stats,
                "stable": stable,
            }

            if not stable:
                stability_issues.append(
                    f"{area}/{metric_name}: stddev={stats['stddev']:.6f} "
                    f"> tolerance={args.stability_tolerance:.4f}"
                )

    # Check for regressions against baseline
    regression_results: list[dict] = []
    regression_issues: list[str] = []

    if args.baseline.exists():
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            baseline_metrics = baseline.get("metrics", {})

            for area, area_metrics in baseline_metrics.items():
                for metric_name, threshold_info in area_metrics.items():
                    if not isinstance(threshold_info, dict):
                        continue

                    baseline_value = threshold_info.get("value", 0.0)
                    min_threshold = threshold_info.get("min_threshold", baseline_value)

                    if area in metric_series and metric_name in metric_series[area]:
                        series = metric_series[area][metric_name]
                        worst = min(series)
                        mean_val = sum(series) / len(series)
                        passed = worst >= min_threshold

                        result = {
                            "area": area,
                            "name": metric_name,
                            "baseline": baseline_value,
                            "threshold": min_threshold,
                            "worst": round(worst, 6),
                            "mean": round(mean_val, 6),
                            "passed": passed,
                        }
                        regression_results.append(result)

                        if not passed:
                            regression_issues.append(
                                f"{area}/{metric_name}: worst={worst:.4f} "
                                f"< threshold={min_threshold:.4f}"
                            )
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"[soak] WARNING: could not load baseline: {exc}", file=sys.stderr)

    # Print stability summary
    print(f"\n[soak] Stability analysis ({iterations} iterations):")
    for area in sorted(stability_results.keys()):
        print(f"\n  [{area}]")
        for metric_name, result in sorted(stability_results[area].items()):
            stats = result["stats"]
            status = "STABLE" if result["stable"] else "UNSTABLE"
            print(f"    {metric_name}: mean={stats['mean']:.6f} "
                  f"stddev={stats['stddev']:.6f} "
                  f"range=[{stats['min']:.6f}, {stats['max']:.6f}] [{status}]")

    # Print regression summary
    if regression_results:
        print(f"\n[soak] Regression check (worst-case across {iterations} iterations):")
        for r in regression_results:
            status = "PASS" if r["passed"] else "FAIL"
            print(f"  {r['area']}/{r['name']}: worst={r['worst']:.4f} "
                  f"threshold={r['threshold']:.4f} [{status}]")

    # Overall verdict
    all_stable = len(stability_issues) == 0
    all_passing = len(regression_issues) == 0
    overall_passed = all_stable and all_passing

    # Build report
    report = {
        "schema_version": 1,
        "soak_test": {
            "iterations": iterations,
            "stability_tolerance": args.stability_tolerance,
            "datasets_lock_sha256": _lockfile_sha256(args.lockfile),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "overall": {
            "passed": overall_passed,
            "stability_passed": all_stable,
            "regression_passed": all_passing,
        },
        "performance": {
            "timing_seconds": perf_stats,
            "timing_ms": {
                k: round(v * 1000, 3) if isinstance(v, float) else v
                for k, v in perf_stats.items()
            },
        },
        "stability": stability_results,
        "regression": regression_results,
        "iterations": all_iterations,
    }

    if stability_issues:
        report["stability_issues"] = stability_issues
    if regression_issues:
        report["regression_issues"] = regression_issues

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n[soak] wrote {args.output}")

    if overall_passed:
        print(f"[soak] PASSED (stable={all_stable}, regression={all_passing})")
    else:
        if stability_issues:
            print(f"[soak] STABILITY ISSUES ({len(stability_issues)}):")
            for issue in stability_issues:
                print(f"  - {issue}")
        if regression_issues:
            print(f"[soak] REGRESSION ISSUES ({len(regression_issues)}):")
            for issue in regression_issues:
                print(f"  - {issue}")

    return 0 if overall_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
