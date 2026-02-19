#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from hashlib import sha256
from pathlib import Path

import datasets


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

    metrics = {
        "schema_version": 1,
        "seed": seed,
        "datasets_lock_sha256": _lockfile_sha256(args.lockfile),
        "metrics": {
            "diff": _compute_diff_metrics(args.data_root / "toy-diff-v1"),
            "similarity": _compute_similarity_metrics(args.data_root / "toy-similarity-v1"),
            "type": _compute_type_metrics(args.data_root / "toy-type-v1"),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[smoke] wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
