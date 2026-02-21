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
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_TRIAGE_STOCK_DEFAULTS = {
    "entrypoint": 0.45,
    "hotspot": 0.30,
    "unknown": 0.55,
}
_TRIAGE_CURRENT_DEFAULTS = {
    "entrypoint": 0.30,
    "hotspot": 0.25,
    "unknown": 0.65,
}


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


def _compute_triage_non_toy_metrics(
    benchmark_path: Path,
    *,
    stock_entrypoint_threshold: float,
    stock_hotspot_threshold: float,
    stock_unknown_threshold: float,
    current_entrypoint_threshold: float,
    current_hotspot_threshold: float,
    current_unknown_threshold: float,
) -> dict:
    from scripts.ml.local_embedding_pipeline import (
        evaluate_triage_benchmark,
        load_triage_benchmark,
    )

    benchmark = load_triage_benchmark(benchmark_path)
    cases = benchmark["cases"]

    stock_report = evaluate_triage_benchmark(
        cases,
        entrypoint_threshold=stock_entrypoint_threshold,
        hotspot_threshold=stock_hotspot_threshold,
        unknown_threshold=stock_unknown_threshold,
    )
    current_report = evaluate_triage_benchmark(
        cases,
        entrypoint_threshold=current_entrypoint_threshold,
        hotspot_threshold=current_hotspot_threshold,
        unknown_threshold=current_unknown_threshold,
    )

    stock_metrics = stock_report["metrics"]
    current_metrics = current_report["metrics"]

    stock_macro_f1 = float(stock_metrics.get("macro_f1", 0.0))
    current_macro_f1 = float(current_metrics.get("macro_f1", 0.0))
    stock_entrypoint_recall = float(stock_metrics["entrypoint"]["recall"])
    current_entrypoint_recall = float(current_metrics["entrypoint"]["recall"])
    stock_hotspot_recall = float(stock_metrics["hotspot"]["recall"])
    current_hotspot_recall = float(current_metrics["hotspot"]["recall"])
    stock_unknown_precision = float(stock_metrics["unknown"]["precision"])
    current_unknown_precision = float(current_metrics["unknown"]["precision"])

    return {
        "cases": int(stock_report["counts"]["cases"]),
        "stock_macro_f1": round(stock_macro_f1, 6),
        "current_macro_f1": round(current_macro_f1, 6),
        "macro_f1_delta": round(current_macro_f1 - stock_macro_f1, 6),
        "stock_entrypoint_recall": round(stock_entrypoint_recall, 6),
        "current_entrypoint_recall": round(current_entrypoint_recall, 6),
        "entrypoint_recall_delta": round(current_entrypoint_recall - stock_entrypoint_recall, 6),
        "stock_hotspot_recall": round(stock_hotspot_recall, 6),
        "current_hotspot_recall": round(current_hotspot_recall, 6),
        "hotspot_recall_delta": round(current_hotspot_recall - stock_hotspot_recall, 6),
        "stock_unknown_precision": round(stock_unknown_precision, 6),
        "current_unknown_precision": round(current_unknown_precision, 6),
        "unknown_precision_delta": round(current_unknown_precision - stock_unknown_precision, 6),
    }


def _run_one_iteration(
    data_root: Path,
    seed: int,
    *,
    non_toy_benchmark: Path | None = None,
    stock_thresholds: dict[str, float] | None = None,
    current_thresholds: dict[str, float] | None = None,
) -> tuple[dict, float]:
    """Run a single smoke evaluation iteration. Returns (metrics, elapsed_seconds)."""
    random.seed(seed)

    start = time.monotonic()
    metrics = {
        "diff": _compute_diff_metrics(data_root / "toy-diff-v1"),
        "similarity": _compute_similarity_metrics(data_root / "toy-similarity-v1"),
        "type": _compute_type_metrics(data_root / "toy-type-v1"),
    }
    if non_toy_benchmark is not None and stock_thresholds is not None and current_thresholds is not None:
        metrics["triage_non_toy"] = _compute_triage_non_toy_metrics(
            non_toy_benchmark,
            stock_entrypoint_threshold=stock_thresholds["entrypoint"],
            stock_hotspot_threshold=stock_thresholds["hotspot"],
            stock_unknown_threshold=stock_thresholds["unknown"],
            current_entrypoint_threshold=current_thresholds["entrypoint"],
            current_hotspot_threshold=current_thresholds["hotspot"],
            current_unknown_threshold=current_thresholds["unknown"],
        )
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
    parser.add_argument(
        "--disable-non-toy-slice",
        action="store_true",
        help="Disable non-toy triage benchmark slice execution",
    )
    parser.add_argument(
        "--non-toy-benchmark",
        type=Path,
        default=Path("datasets/data/triage-curated-v2026.02.1/benchmark.json"),
        help="Path to non-toy triage benchmark slice",
    )
    parser.add_argument(
        "--stock-entrypoint-threshold",
        type=float,
        default=_TRIAGE_STOCK_DEFAULTS["entrypoint"],
        help="Stock baseline entrypoint threshold for non-toy triage slice",
    )
    parser.add_argument(
        "--stock-hotspot-threshold",
        type=float,
        default=_TRIAGE_STOCK_DEFAULTS["hotspot"],
        help="Stock baseline hotspot threshold for non-toy triage slice",
    )
    parser.add_argument(
        "--stock-unknown-threshold",
        type=float,
        default=_TRIAGE_STOCK_DEFAULTS["unknown"],
        help="Stock baseline unknown threshold for non-toy triage slice",
    )
    parser.add_argument(
        "--current-entrypoint-threshold",
        type=float,
        default=_TRIAGE_CURRENT_DEFAULTS["entrypoint"],
        help="Current implementation entrypoint threshold for non-toy triage slice",
    )
    parser.add_argument(
        "--current-hotspot-threshold",
        type=float,
        default=_TRIAGE_CURRENT_DEFAULTS["hotspot"],
        help="Current implementation hotspot threshold for non-toy triage slice",
    )
    parser.add_argument(
        "--current-unknown-threshold",
        type=float,
        default=_TRIAGE_CURRENT_DEFAULTS["unknown"],
        help="Current implementation unknown threshold for non-toy triage slice",
    )
    args = parser.parse_args(argv)

    # Materialize datasets
    try:
        datasets.materialize_datasets(args.lockfile, args.data_root)
    except ValueError as exc:
        print(f"[soak] ERROR: dataset materialization failed: {exc}", file=sys.stderr)
        return 2

    non_toy_benchmark: Path | None = None
    stock_thresholds: dict[str, float] | None = None
    current_thresholds: dict[str, float] | None = None
    if not args.disable_non_toy_slice:
        non_toy_benchmark = args.non_toy_benchmark
        if not non_toy_benchmark.exists():
            print(
                f"[soak] ERROR: non-toy benchmark missing: {non_toy_benchmark}",
                file=sys.stderr,
            )
            return 2
        stock_thresholds = {
            "entrypoint": args.stock_entrypoint_threshold,
            "hotspot": args.stock_hotspot_threshold,
            "unknown": args.stock_unknown_threshold,
        }
        current_thresholds = {
            "entrypoint": args.current_entrypoint_threshold,
            "hotspot": args.current_hotspot_threshold,
            "unknown": args.current_unknown_threshold,
        }

    iterations = args.iterations
    print(f"[soak] Starting soak test ({iterations} iterations)")

    # Run iterations
    all_iterations: list[dict] = []
    timing_values: list[float] = []
    metric_series: dict[str, dict[str, list[float]]] = {}

    for i in range(iterations):
        seed = i
        metrics, elapsed = _run_one_iteration(
            args.data_root,
            seed,
            non_toy_benchmark=non_toy_benchmark,
            stock_thresholds=stock_thresholds,
            current_thresholds=current_thresholds,
        )
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
    if non_toy_benchmark is not None and stock_thresholds is not None and current_thresholds is not None:
        report["non_toy_slice"] = {
            "enabled": True,
            "benchmark_path": str(non_toy_benchmark),
            "stock_thresholds": stock_thresholds,
            "current_thresholds": current_thresholds,
            "reproduction": {
                "command": (
                    "python3 eval/scripts/run_soak.py "
                    f"--iterations {iterations} "
                    f"--output {args.output} "
                    f"--non-toy-benchmark {non_toy_benchmark}"
                )
            },
        }
    else:
        report["non_toy_slice"] = {"enabled": False}

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
