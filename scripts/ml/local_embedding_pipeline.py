#!/usr/bin/env python3
"""ML-301: local embedding pipeline and deterministic similarity adapter baseline.

This module provides:
1. A deterministic local embedding/index pipeline for a corpus slice.
2. A baseline retrieval adapter API that returns deterministic top-k matches.
3. Build/runtime stats persisted alongside index artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


@dataclass(frozen=True)
class FunctionRecord:
    """Minimal function record used for embedding and retrieval."""

    function_id: str
    name: str
    text: str

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "FunctionRecord":
        function_id = str(raw.get("id") or raw.get("function_id") or "").strip()
        if not function_id:
            raise ValueError("function record missing required id/function_id")
        name = str(raw.get("name") or "").strip()
        text = str(raw.get("text") or "").strip()
        return cls(function_id=function_id, name=name, text=text)


@dataclass(frozen=True)
class SearchResult:
    """Single retrieval hit."""

    function_id: str
    name: str
    score: float


@dataclass(frozen=True)
class IndexBuildStats:
    """Pipeline and index build statistics."""

    corpus_size: int
    vector_dimension: int
    total_feature_tokens: int
    avg_non_zero_dimensions: float
    embedding_runtime_ms: float
    index_build_runtime_ms: float
    pipeline_runtime_ms: float


@dataclass(frozen=True)
class _IndexedRecord:
    record: FunctionRecord
    vector: tuple[float, ...]
    norm: float
    non_zero_dimensions: int
    features: tuple[tuple[str, int], ...]


def _now_ns() -> int:
    return time.perf_counter_ns()


def _ms(start_ns: int, end_ns: int) -> float:
    return round((end_ns - start_ns) / 1_000_000.0, 3)


class LocalEmbeddingPipeline:
    """Deterministic local embedding builder (feature hashing)."""

    def __init__(self, vector_dimension: int = 128):
        if vector_dimension <= 0:
            raise ValueError("vector_dimension must be > 0")
        self.vector_dimension = vector_dimension

    def tokenize(self, text: str) -> list[str]:
        return _TOKEN_RE.findall(text.lower())

    def _token_bucket_weight(self, token: str) -> tuple[int, float]:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:8], "big") % self.vector_dimension
        sign = -1.0 if digest[8] & 1 else 1.0
        # Add deterministic mild weighting so repeated words are less dominant.
        magnitude = 1.0 + (digest[9] / 255.0) * 0.25
        return bucket, sign * magnitude

    def _embed_tokens(self, tokens: Iterable[str]) -> tuple[tuple[float, ...], float, int]:
        raw = [0.0] * self.vector_dimension
        for token in tokens:
            bucket, weight = self._token_bucket_weight(token)
            raw[bucket] += weight

        norm = math.sqrt(sum(value * value for value in raw))
        non_zero = sum(1 for value in raw if value != 0.0)
        if norm == 0.0:
            return tuple(raw), 0.0, non_zero

        normalized = tuple(value / norm for value in raw)
        return normalized, 1.0, non_zero

    def embed_text(self, text: str) -> tuple[float, ...]:
        vector, _, _ = self._embed_tokens(self.tokenize(text))
        return vector

    def build_index(self, records: list[FunctionRecord]) -> "EmbeddingIndex":
        pipeline_start = _now_ns()
        embedding_start = _now_ns()

        indexed_records: list[_IndexedRecord] = []
        total_feature_tokens = 0
        non_zero_accumulator = 0

        for record in records:
            material = f"{record.name} {record.text}".strip()
            tokens = self.tokenize(material)
            total_feature_tokens += len(tokens)

            token_counts = Counter(tokens)
            vector, norm, non_zero = self._embed_tokens(tokens)
            non_zero_accumulator += non_zero

            indexed_records.append(
                _IndexedRecord(
                    record=record,
                    vector=vector,
                    norm=norm,
                    non_zero_dimensions=non_zero,
                    features=tuple(sorted(token_counts.items(), key=lambda item: item[0])),
                )
            )

        embedding_end = _now_ns()

        # Baseline index is in-memory list storage; timing is still explicitly recorded.
        index_build_start = embedding_end
        index_build_end = _now_ns()
        pipeline_end = _now_ns()

        corpus_size = len(indexed_records)
        avg_non_zero = (non_zero_accumulator / corpus_size) if corpus_size else 0.0
        stats = IndexBuildStats(
            corpus_size=corpus_size,
            vector_dimension=self.vector_dimension,
            total_feature_tokens=total_feature_tokens,
            avg_non_zero_dimensions=round(avg_non_zero, 3),
            embedding_runtime_ms=_ms(embedding_start, embedding_end),
            index_build_runtime_ms=_ms(index_build_start, index_build_end),
            pipeline_runtime_ms=_ms(pipeline_start, pipeline_end),
        )
        return EmbeddingIndex(
            vector_dimension=self.vector_dimension,
            indexed_records=indexed_records,
            stats=stats,
        )


class EmbeddingIndex:
    """In-memory vector index with persisted artifact support."""

    def __init__(
        self,
        vector_dimension: int,
        indexed_records: list[_IndexedRecord],
        stats: IndexBuildStats,
    ):
        self.vector_dimension = vector_dimension
        self._records = indexed_records
        self._stats = stats

    @property
    def stats(self) -> IndexBuildStats:
        return self._stats

    def search(self, query_text: str, top_k: int, pipeline: LocalEmbeddingPipeline) -> list[SearchResult]:
        if top_k <= 0:
            return []

        query_vector, query_norm, _ = pipeline._embed_tokens(pipeline.tokenize(query_text))
        if query_norm == 0.0:
            return []

        scored: list[SearchResult] = []
        for indexed in self._records:
            if indexed.norm == 0.0:
                score = 0.0
            else:
                score = sum(a * b for a, b in zip(query_vector, indexed.vector))
            scored.append(
                SearchResult(
                    function_id=indexed.record.function_id,
                    name=indexed.record.name,
                    score=score,
                )
            )

        # Deterministic ordering: primary by score, secondary by function_id.
        scored.sort(key=lambda item: (-item.score, item.function_id))
        return scored[: min(top_k, len(scored))]

    def save(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        stats_doc = {
            "schema_version": 1,
            "kind": "ml301_local_embedding_stats",
            **asdict(self._stats),
        }
        (output_dir / "stats.json").write_text(
            json.dumps(stats_doc, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        index_doc = {
            "schema_version": 1,
            "kind": "ml301_local_embedding_index",
            "vector_dimension": self.vector_dimension,
            "records": [
                {
                    "function_id": indexed.record.function_id,
                    "name": indexed.record.name,
                    "text": indexed.record.text,
                    "vector": indexed.vector,
                    "norm": indexed.norm,
                    "non_zero_dimensions": indexed.non_zero_dimensions,
                }
                for indexed in self._records
            ],
        }
        (output_dir / "index.json").write_text(
            json.dumps(index_doc, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        features_path = output_dir / "features.jsonl"
        with features_path.open("w", encoding="utf-8") as handle:
            for indexed in self._records:
                feature_doc = {
                    "function_id": indexed.record.function_id,
                    "name": indexed.record.name,
                    "features": [
                        {"token": token, "count": count}
                        for token, count in indexed.features
                    ],
                }
                handle.write(json.dumps(feature_doc, sort_keys=True) + "\n")

    @classmethod
    def load(cls, index_dir: Path) -> "EmbeddingIndex":
        index_doc = json.loads((index_dir / "index.json").read_text(encoding="utf-8"))
        stats_doc = json.loads((index_dir / "stats.json").read_text(encoding="utf-8"))

        if index_doc.get("schema_version") != 1:
            raise ValueError("unsupported index schema_version")
        if stats_doc.get("schema_version") != 1:
            raise ValueError("unsupported stats schema_version")

        vector_dimension = int(index_doc["vector_dimension"])
        indexed_records: list[_IndexedRecord] = []
        for raw in index_doc.get("records", []):
            record = FunctionRecord(
                function_id=str(raw["function_id"]),
                name=str(raw.get("name", "")),
                text=str(raw.get("text", "")),
            )
            vector = tuple(float(v) for v in raw["vector"])
            if len(vector) != vector_dimension:
                raise ValueError("index vector length mismatch")
            indexed_records.append(
                _IndexedRecord(
                    record=record,
                    vector=vector,
                    norm=float(raw.get("norm", 0.0)),
                    non_zero_dimensions=int(raw.get("non_zero_dimensions", 0)),
                    features=tuple(),
                )
            )

        stats = IndexBuildStats(
            corpus_size=int(stats_doc["corpus_size"]),
            vector_dimension=int(stats_doc["vector_dimension"]),
            total_feature_tokens=int(stats_doc["total_feature_tokens"]),
            avg_non_zero_dimensions=float(stats_doc["avg_non_zero_dimensions"]),
            embedding_runtime_ms=float(stats_doc["embedding_runtime_ms"]),
            index_build_runtime_ms=float(stats_doc["index_build_runtime_ms"]),
            pipeline_runtime_ms=float(stats_doc["pipeline_runtime_ms"]),
        )
        return cls(vector_dimension=vector_dimension, indexed_records=indexed_records, stats=stats)


class BaselineSimilarityAdapter:
    """Baseline retrieval API wrapper around EmbeddingIndex."""

    def __init__(self, pipeline: LocalEmbeddingPipeline, index: EmbeddingIndex):
        self._pipeline = pipeline
        self._index = index

    @property
    def build_stats(self) -> IndexBuildStats:
        return self._index.stats

    def top_k(self, query_text: str, top_k: int = 5) -> list[SearchResult]:
        return self._index.search(query_text=query_text, top_k=top_k, pipeline=self._pipeline)


def load_corpus(corpus_path: Path) -> list[FunctionRecord]:
    doc = json.loads(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "functions" not in doc:
        raise ValueError("corpus must be an object with a 'functions' array")
    functions = doc["functions"]
    if not isinstance(functions, list):
        raise ValueError("'functions' must be an array")
    return [FunctionRecord.from_json(raw) for raw in functions]


def evaluate_queries(adapter: BaselineSimilarityAdapter, queries_path: Path, top_k: int) -> dict[str, Any]:
    doc = json.loads(queries_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("queries"), list):
        raise ValueError("queries document must contain a 'queries' array")

    queries = doc["queries"]
    total = 0
    recall_hits = 0
    mrr_total = 0.0
    results: list[dict[str, Any]] = []

    for query in queries:
        text = str(query.get("text") or "")
        gt = str(query.get("ground_truth_id") or "")
        hits = adapter.top_k(text, top_k=top_k)

        total += 1
        ranked_ids = [item.function_id for item in hits]
        if ranked_ids and ranked_ids[0] == gt:
            recall_hits += 1

        rank = None
        for idx, function_id in enumerate(ranked_ids, start=1):
            if function_id == gt:
                rank = idx
                mrr_total += 1.0 / idx
                break

        results.append(
            {
                "query": text,
                "ground_truth_id": gt,
                "rank": rank,
                "top_k": [
                    {"function_id": hit.function_id, "name": hit.name, "score": round(hit.score, 6)}
                    for hit in hits
                ],
            }
        )

    recall_at_1 = (recall_hits / total) if total else 0.0
    mrr = (mrr_total / total) if total else 0.0
    return {
        "queries": total,
        "recall@1": round(recall_at_1, 6),
        "mrr": round(mrr, 6),
        "results": results,
    }


def _build_command(args: argparse.Namespace) -> int:
    pipeline = LocalEmbeddingPipeline(vector_dimension=args.vector_dimension)
    records = load_corpus(args.corpus)
    index = pipeline.build_index(records)
    index.save(args.output_dir)

    print(f"[ml301] built index at {args.output_dir}")
    print(json.dumps({"stats": asdict(index.stats)}, indent=2, sort_keys=True))
    return 0


def _search_command(args: argparse.Namespace) -> int:
    index = EmbeddingIndex.load(args.index_dir)
    pipeline = LocalEmbeddingPipeline(vector_dimension=index.vector_dimension)
    adapter = BaselineSimilarityAdapter(pipeline=pipeline, index=index)
    hits = adapter.top_k(args.query, top_k=args.top_k)

    output = {
        "query": args.query,
        "top_k": args.top_k,
        "results": [
            {"function_id": hit.function_id, "name": hit.name, "score": round(hit.score, 6)}
            for hit in hits
        ],
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def _evaluate_command(args: argparse.Namespace) -> int:
    index = EmbeddingIndex.load(args.index_dir)
    pipeline = LocalEmbeddingPipeline(vector_dimension=index.vector_dimension)
    adapter = BaselineSimilarityAdapter(pipeline=pipeline, index=index)
    metrics = evaluate_queries(adapter, args.queries, top_k=args.top_k)
    metrics["build_stats"] = asdict(adapter.build_stats)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ML-301 local embedding and retrieval baseline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build local embedding index from corpus JSON")
    build_parser.add_argument("--corpus", type=Path, required=True, help="Path to corpus JSON")
    build_parser.add_argument("--output-dir", type=Path, required=True, help="Directory for index artifacts")
    build_parser.add_argument("--vector-dimension", type=int, default=128, help="Embedding vector dimension")
    build_parser.set_defaults(func=_build_command)

    search_parser = subparsers.add_parser("search", help="Query top-k functions from index")
    search_parser.add_argument("--index-dir", type=Path, required=True, help="Directory containing index artifacts")
    search_parser.add_argument("--query", type=str, required=True, help="Search query text")
    search_parser.add_argument("--top-k", type=int, default=5, help="Top-k result count")
    search_parser.set_defaults(func=_search_command)

    eval_parser = subparsers.add_parser("evaluate", help="Evaluate retrieval metrics against query set")
    eval_parser.add_argument("--index-dir", type=Path, required=True, help="Directory containing index artifacts")
    eval_parser.add_argument("--queries", type=Path, required=True, help="Path to queries JSON")
    eval_parser.add_argument("--top-k", type=int, default=10, help="Top-k result count")
    eval_parser.add_argument("--output", type=Path, default=None, help="Optional metrics output JSON")
    eval_parser.set_defaults(func=_evaluate_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
