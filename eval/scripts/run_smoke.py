#!/usr/bin/env python3
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
import importlib.util


def _require_env(name: str, expected_value: str) -> None:
    actual = os.environ.get(name)
    if actual != expected_value:
        raise ValueError(f"{name} must be set to '{expected_value}' (got {actual!r})")


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union


def _compute_similarity_metrics(dataset_dir: Path) -> dict:
    corpus = json.loads((dataset_dir / "corpus.json").read_text(encoding="utf-8"))
    queries = json.loads((dataset_dir / "queries.json").read_text(encoding="utf-8"))

    functions = corpus["functions"]
    function_tokens = {fn["id"]: _tokens(f"{fn.get('name', '')} {fn.get('text', '')}") for fn in functions}

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
    return {
        "cases": total,
        "accuracy": round(accuracy, 6),
    }


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
        left_id = match["left_id"]
        right_id = match["right_id"]
        if predicted.get(left_id) == right_id:
            correct += 1

    match_rate = correct / total if total else 0.0
    coverage = len(predicted) / len(left_functions) if left_functions else 0.0
    return {
        "pairs": total,
        "match_rate": round(match_rate, 6),
        "coverage": round(coverage, 6),
    }


def _lockfile_sha256(lockfile: Path) -> str:
    return sha256(lockfile.read_bytes()).hexdigest()


def _file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _percentile(sorted_values: list[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    bounded = min(max(percentile, 0.0), 100.0)
    n = len(sorted_values)
    k = (n - 1) * (bounded / 100.0)
    floor_idx = math.floor(k)
    ceil_idx = math.ceil(k)
    if floor_idx == ceil_idx:
        return sorted_values[int(k)]
    return (sorted_values[floor_idx] * (ceil_idx - k)) + (sorted_values[ceil_idx] * (k - floor_idx))


def _rank_ids_by_similarity(
    query_tokens: set[str],
    function_ids: list[str],
    function_tokens: dict[str, set[str]],
) -> list[str]:
    scored = [(_jaccard(query_tokens, function_tokens[function_id]), function_id) for function_id in function_ids]
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [function_id for _, function_id in scored]


def _compute_real_target_slice_metrics(
    benchmark_path: Path,
    *,
    top_k: int,
    warmup_runs: int,
    measure_runs: int,
) -> tuple[dict, list[float]]:
    benchmark_doc = json.loads(benchmark_path.read_text(encoding="utf-8"))
    raw_functions = benchmark_doc.get("functions")
    if not isinstance(raw_functions, list) or not raw_functions:
        raise ValueError(f"real-target benchmark must contain a non-empty 'functions' list: {benchmark_path}")

    function_ids: list[str] = []
    function_tokens: dict[str, set[str]] = {}
    for row in raw_functions:
        if not isinstance(row, dict):
            raise ValueError(f"real-target benchmark function rows must be objects: {benchmark_path}")
        function_id = str(row.get("id") or "").strip()
        if not function_id:
            raise ValueError(f"real-target benchmark row missing id: {benchmark_path}")
        if function_id in function_tokens:
            raise ValueError(f"duplicate function id {function_id!r} in {benchmark_path}")
        text = f"{row.get('name', '')} {row.get('text', '')}"
        function_ids.append(function_id)
        function_tokens[function_id] = _tokens(text)

    query_ids = list(function_ids)
    query_total = len(query_ids)
    recall_at_1_hits = 0
    recall_at_k_hits = 0
    mrr_total = 0.0
    latency_samples_ms: list[float] = []

    for query_id in query_ids:
        query_tokens = function_tokens[query_id]
        ranked_ids_for_relevance: list[str] = []

        for _ in range(max(warmup_runs, 0)):
            _rank_ids_by_similarity(query_tokens, function_ids, function_tokens)

        run_count = max(measure_runs, 1)
        for run_index in range(run_count):
            started_at_ns = time.perf_counter_ns()
            ranked_ids = _rank_ids_by_similarity(query_tokens, function_ids, function_tokens)
            elapsed_ms = (time.perf_counter_ns() - started_at_ns) / 1_000_000.0
            latency_samples_ms.append(elapsed_ms)
            if run_index == 0:
                ranked_ids_for_relevance = ranked_ids

        if ranked_ids_for_relevance and ranked_ids_for_relevance[0] == query_id:
            recall_at_1_hits += 1
        if query_id in ranked_ids_for_relevance[:top_k]:
            recall_at_k_hits += 1
        try:
            rank = ranked_ids_for_relevance.index(query_id) + 1
        except ValueError:
            rank = None
        if rank:
            mrr_total += 1.0 / rank

    sorted_latencies = sorted(latency_samples_ms)
    recall_at_1 = (recall_at_1_hits / query_total) if query_total else 0.0
    recall_at_k = (recall_at_k_hits / query_total) if query_total else 0.0
    mrr = (mrr_total / query_total) if query_total else 0.0
    metrics = {
        "queries": query_total,
        "corpus_size": len(function_ids),
        "top_k": top_k,
        "mrr": round(mrr, 6),
        "recall@1": round(recall_at_1, 6),
        f"recall@{top_k}": round(recall_at_k, 6),
        "latency_p50_ms": round(_percentile(sorted_latencies, 50.0), 6),
        "latency_p95_ms": round(_percentile(sorted_latencies, 95.0), 6),
    }
    return metrics, latency_samples_ms


def _load_real_target_manifest(manifest_path: Path) -> dict:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to load real-target manifest {manifest_path}: {exc}") from exc

    if manifest.get("schema_version") != 1:
        raise ValueError("real-target manifest schema_version must be 1")
    if manifest.get("kind") != "real_target_benchmark_manifest":
        raise ValueError("real-target manifest kind must be 'real_target_benchmark_manifest'")
    slices = manifest.get("slices")
    if not isinstance(slices, list) or not slices:
        raise ValueError("real-target manifest must include a non-empty 'slices' list")
    return manifest


def _compute_real_target_metrics(
    *,
    manifest_path: Path,
    data_root: Path,
) -> tuple[dict, list[dict], list[dict], set[str], dict]:
    manifest = _load_real_target_manifest(manifest_path)
    slices = manifest["slices"]

    slice_results: list[dict] = []
    benchmark_slices: list[dict] = []
    dataset_names: set[str] = set()
    all_latency_samples: list[float] = []
    total_queries = 0
    total_corpus_size = 0
    weighted_mrr = 0.0
    weighted_recall_at_1 = 0.0
    weighted_recall_at_k = 0.0
    top_k_values: set[int] = set()

    for entry in sorted(slices, key=lambda item: str(item.get("slice_id") or "")):
        if not isinstance(entry, dict):
            raise ValueError(f"real-target manifest slices must be objects: {manifest_path}")

        slice_id = str(entry.get("slice_id") or "").strip()
        dataset_name = str(entry.get("dataset") or "").strip()
        benchmark_file = str(entry.get("benchmark_file") or "").strip()
        if not slice_id:
            raise ValueError("real-target manifest slice missing slice_id")
        if not dataset_name:
            raise ValueError(f"real-target manifest slice {slice_id!r} missing dataset")
        if not benchmark_file:
            raise ValueError(f"real-target manifest slice {slice_id!r} missing benchmark_file")

        top_k = int(entry.get("top_k", 5))
        if top_k <= 0:
            raise ValueError(f"real-target manifest slice {slice_id!r} has invalid top_k={top_k}")
        warmup_runs = int(entry.get("warmup_runs", 1))
        measure_runs = int(entry.get("measure_runs", 3))

        dataset_dir = data_root / dataset_name
        benchmark_path = dataset_dir / benchmark_file
        if not benchmark_path.exists():
            raise ValueError(f"real-target benchmark file missing: {benchmark_path}")

        metrics, latency_samples = _compute_real_target_slice_metrics(
            benchmark_path,
            top_k=top_k,
            warmup_runs=warmup_runs,
            measure_runs=measure_runs,
        )

        query_count = int(metrics.get("queries", 0))
        top_k_key = f"recall@{top_k}"
        total_queries += query_count
        total_corpus_size += int(metrics.get("corpus_size", 0))
        weighted_mrr += float(metrics.get("mrr", 0.0)) * query_count
        weighted_recall_at_1 += float(metrics.get("recall@1", 0.0)) * query_count
        weighted_recall_at_k += float(metrics.get(top_k_key, 0.0)) * query_count
        top_k_values.add(top_k)
        all_latency_samples.extend(latency_samples)
        dataset_names.add(dataset_name)

        slice_results.append(
            {
                "slice_id": slice_id,
                "dataset": dataset_name,
                "benchmark_file": benchmark_file,
                "benchmark_sha256": _file_sha256(benchmark_path),
                "warmup_runs": warmup_runs,
                "measure_runs": max(measure_runs, 1),
                "metrics": metrics,
            }
        )
        benchmark_slices.append(
            {
                "slice_id": slice_id,
                "dataset": dataset_name,
                "kind": "real_target",
                "benchmark_file": benchmark_file,
                "top_k": top_k,
            }
        )

    if len(top_k_values) != 1:
        raise ValueError("real-target manifest slices must use a single shared top_k for aggregation")
    aggregated_top_k = next(iter(top_k_values))
    top_k_key = f"recall@{aggregated_top_k}"
    latency_sorted = sorted(all_latency_samples)
    aggregated_metrics = {
        "slice_count": len(slice_results),
        "queries": total_queries,
        "corpus_size": total_corpus_size,
        "top_k": aggregated_top_k,
        "mrr": round((weighted_mrr / total_queries) if total_queries else 0.0, 6),
        "recall@1": round((weighted_recall_at_1 / total_queries) if total_queries else 0.0, 6),
        top_k_key: round((weighted_recall_at_k / total_queries) if total_queries else 0.0, 6),
        "latency_p50_ms": round(_percentile(latency_sorted, 50.0), 6),
        "latency_p95_ms": round(_percentile(latency_sorted, 95.0), 6),
    }
    harness_meta = {
        "schema_version": manifest["schema_version"],
        "kind": manifest["kind"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": _file_sha256(manifest_path),
    }
    return aggregated_metrics, slice_results, benchmark_slices, dataset_names, harness_meta


def _collect_dataset_revisions(lockfile: Path, dataset_names: set[str]) -> dict[str, dict]:
    lock = datasets.load_lockfile(lockfile)
    entries = lock.get("datasets", {})
    revisions: dict[str, dict] = {}
    for dataset_name in sorted(dataset_names):
        raw = entries.get(dataset_name)
        if not isinstance(raw, dict):
            raise ValueError(f"dataset {dataset_name!r} is missing from lockfile")
        source = raw.get("source", {}) if isinstance(raw.get("source"), dict) else {}
        files = raw.get("files", {}) if isinstance(raw.get("files"), dict) else {}
        revisions[dataset_name] = {
            "version": str(raw.get("version", "unversioned")),
            "source_path": source.get("path"),
            "files": {
                rel: {"bytes": int(meta.get("bytes", 0)), "sha256": str(meta.get("sha256", ""))}
                for rel, meta in sorted(files.items(), key=lambda item: item[0])
                if isinstance(meta, dict)
            },
        }
    return revisions


def _load_spec_review_runner():
    module_path = Path(__file__).resolve().parent / "spec_review_benchmark.py"
    spec = importlib.util.spec_from_file_location("e9_spec_review_benchmark", module_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"failed to load spec-review benchmark module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    runner = getattr(module, "run_spec_review_benchmark", None)
    if runner is None:
        raise ValueError("spec-review benchmark module missing run_spec_review_benchmark")
    return runner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic smoke evaluation runner")
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
        default=Path("eval/output/smoke/metrics.json"),
        help="Path to metrics output JSON",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Integer seed (default: $EVAL_SEED or 0)",
    )
    parser.add_argument(
        "--real-target-manifest",
        type=Path,
        default=Path("eval/reports/e23/real_target_manifest.json"),
        help="Path to pinned real-target benchmark slice manifest",
    )
    parser.add_argument(
        "--disable-real-target-slices",
        action="store_true",
        help="Disable real-target benchmark slices",
    )
    args = parser.parse_args(argv)

    try:
        _require_env("PYTHONHASHSEED", "0")
        _require_env("TZ", "UTC")
        _require_env("LC_ALL", "C")
        _require_env("LANG", "C")
    except ValueError as exc:
        print(f"[smoke] ERROR: {exc}", file=sys.stderr)
        print("[smoke] Hint: run via `bash eval/run_smoke.sh` to apply deterministic env.", file=sys.stderr)
        return 2

    seed = args.seed
    if seed is None:
        seed = int(os.environ.get("EVAL_SEED", "0"))

    random.seed(seed)

    try:
        datasets.materialize_datasets(args.lockfile, args.data_root)
    except ValueError as exc:
        print(f"[smoke] ERROR: dataset materialization failed: {exc}", file=sys.stderr)
        return 2

    spec_review_dir = Path("eval/fixtures/spec-review-v1")
    spec_review_expected = spec_review_dir / "expected.json"
    try:
        run_spec_review_benchmark = _load_spec_review_runner()
        spec_review = run_spec_review_benchmark(
            analysis_path=spec_review_dir / "analysis.json",
            decisions_path=spec_review_dir / "review_decisions.json",
            expected_path=spec_review_expected if spec_review_expected.exists() else None,
        )
    except ValueError as exc:
        print(f"[smoke] ERROR: spec-review benchmark failed: {exc}", file=sys.stderr)
        return 2

    if spec_review.get("passed") != 1.0:
        detail = spec_review.get("detail") if isinstance(spec_review.get("detail"), dict) else {}
        print("[smoke] ERROR: spec-review benchmark did not match expected snapshot", file=sys.stderr)
        print(f"[smoke] spec_packet_hash={detail.get('spec_packet_hash')}", file=sys.stderr)
        print(f"[smoke] review_packet_hash={detail.get('review_packet_hash')}", file=sys.stderr)
        print(f"[smoke] verdict={detail.get('review_verdict')}", file=sys.stderr)
        return 2

    benchmark_slices = [
        {"slice_id": "toy-diff-v1", "dataset": "toy-diff-v1", "kind": "toy"},
        {"slice_id": "toy-similarity-v1", "dataset": "toy-similarity-v1", "kind": "toy"},
        {"slice_id": "toy-type-v1", "dataset": "toy-type-v1", "kind": "toy"},
        {"slice_id": "spec-review-v1", "dataset": "eval/fixtures/spec-review-v1", "kind": "fixture"},
    ]
    dataset_names_for_revision: set[str] = {"toy-diff-v1", "toy-similarity-v1", "toy-type-v1"}
    real_target_harness: dict[str, object] = {"enabled": False}
    real_target_slices: list[dict] = []
    real_target_metrics: dict[str, object] | None = None

    if not args.disable_real_target_slices:
        try:
            (
                real_target_metrics,
                real_target_slices,
                real_target_benchmark_slices,
                real_target_dataset_names,
                harness_meta,
            ) = _compute_real_target_metrics(
                manifest_path=args.real_target_manifest,
                data_root=args.data_root,
            )
        except ValueError as exc:
            print(f"[smoke] ERROR: real-target benchmark failed: {exc}", file=sys.stderr)
            return 2
        benchmark_slices.extend(real_target_benchmark_slices)
        dataset_names_for_revision |= real_target_dataset_names
        real_target_harness = {
            "enabled": True,
            **harness_meta,
            "slice_count": len(real_target_slices),
        }

    try:
        dataset_revisions = _collect_dataset_revisions(args.lockfile, dataset_names_for_revision)
    except ValueError as exc:
        print(f"[smoke] ERROR: failed to collect dataset revisions: {exc}", file=sys.stderr)
        return 2

    metrics = {
        "schema_version": 1,
        "seed": seed,
        "datasets_lock_sha256": _lockfile_sha256(args.lockfile),
        "benchmark_slices": benchmark_slices,
        "dataset_revisions": dataset_revisions,
        "real_target_harness": real_target_harness,
        "metrics": {
            "diff": _compute_diff_metrics(args.data_root / "toy-diff-v1"),
            "similarity": _compute_similarity_metrics(args.data_root / "toy-similarity-v1"),
            "type": _compute_type_metrics(args.data_root / "toy-type-v1"),
            "spec_review": {k: v for k, v in spec_review.items() if isinstance(v, (int, float))},
        },
    }
    if real_target_metrics is not None:
        metrics["metrics"]["real_target"] = real_target_metrics
        metrics["real_target_slices"] = real_target_slices

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.output.parent / "spec_review_detail.json").write_text(
        json.dumps(spec_review.get("detail", {}), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[smoke] wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
