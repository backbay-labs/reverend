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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


@dataclass(frozen=True)
class EvidenceRef:
    """Stable evidence reference for a function-level result."""

    evidence_ref_id: str
    kind: str
    description: str
    uri: str
    confidence: float | None = None

    @classmethod
    def from_json(cls, raw: Mapping[str, Any], *, function_id: str) -> "EvidenceRef":
        base_id = str(raw.get("evidence_ref_id") or raw.get("id") or "").strip()
        kind = str(raw.get("kind") or raw.get("type") or "OTHER").strip().upper() or "OTHER"
        description = str(raw.get("description") or "").strip()
        uri = str(raw.get("uri") or "").strip()
        confidence_raw = raw.get("confidence")
        confidence = float(confidence_raw) if confidence_raw is not None else None

        if not description:
            description = f"{kind} evidence for {function_id}"
        if not uri:
            uri = f"local-index://evidence/{function_id}/{kind.lower()}"
        if not base_id:
            seed = f"{function_id}:{kind}:{uri}:{description}"
            digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
            base_id = f"evidence:{digest}"

        return cls(
            evidence_ref_id=base_id,
            kind=kind,
            description=description,
            uri=uri,
            confidence=confidence,
        )

    def to_json(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "evidence_ref_id": self.evidence_ref_id,
            "kind": self.kind,
            "description": self.description,
            "uri": self.uri,
        }
        if self.confidence is not None:
            doc["confidence"] = self.confidence
        return doc


@dataclass(frozen=True)
class FunctionRecord:
    """Minimal function record used for embedding and retrieval."""

    function_id: str
    name: str
    text: str
    provenance: tuple[tuple[str, str], ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "FunctionRecord":
        function_id = str(raw.get("id") or raw.get("function_id") or "").strip()
        if not function_id:
            raise ValueError("function record missing required id/function_id")
        name = str(raw.get("name") or "").strip()
        text = str(raw.get("text") or "").strip()
        provenance = cls._parse_provenance(raw, function_id)
        evidence_refs = cls._parse_evidence_refs(raw, function_id)
        return cls(
            function_id=function_id,
            name=name,
            text=text,
            provenance=provenance,
            evidence_refs=evidence_refs,
        )

    @staticmethod
    def _parse_provenance(raw: Mapping[str, Any], function_id: str) -> tuple[tuple[str, str], ...]:
        provenance_raw = raw.get("provenance")
        if isinstance(provenance_raw, Mapping):
            items = [
                (str(key).strip(), str(value).strip())
                for key, value in provenance_raw.items()
                if str(key).strip()
            ]
            if items:
                return tuple(sorted(items, key=lambda item: item[0]))

        fallback = {
            "source": str(raw.get("source") or "local_corpus"),
            "receipt_id": str(raw.get("receipt_id") or f"receipt:{function_id}"),
            "record_id": function_id,
        }
        return tuple(sorted(fallback.items(), key=lambda item: item[0]))

    @staticmethod
    def _parse_evidence_refs(raw: Mapping[str, Any], function_id: str) -> tuple[EvidenceRef, ...]:
        refs_raw = raw.get("evidence_refs")
        refs: list[EvidenceRef] = []
        if isinstance(refs_raw, list):
            for item in refs_raw:
                if isinstance(item, Mapping):
                    refs.append(EvidenceRef.from_json(item, function_id=function_id))

        if refs:
            return tuple(refs)

        default_ref = EvidenceRef.from_json(
            {
                "kind": "TEXT_FEATURE",
                "description": f"Feature-hash token evidence for {function_id}",
                "uri": f"local-index://features/{function_id}",
            },
            function_id=function_id,
        )
        return (default_ref,)

    def provenance_map(self) -> dict[str, str]:
        return dict(self.provenance)

    def to_json(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "name": self.name,
            "text": self.text,
            "provenance": self.provenance_map(),
            "evidence_refs": [ref.to_json() for ref in self.evidence_refs],
        }


@dataclass(frozen=True)
class SearchResult:
    """Single retrieval hit."""

    function_id: str
    name: str
    score: float


@dataclass(frozen=True)
class EvidenceDerivedFeatures:
    """Evidence/receipt-derived feature vector used by the reranker."""

    evidence_count: int
    evidence_kind_score: float
    confidence_mean: float
    query_overlap: float
    receipt_signal: float


class EvidenceWeightedReranker:
    """Deterministic reranker that boosts hits backed by stronger evidence."""

    _KIND_WEIGHTS = {
        "CALLSITE": 1.0,
        "XREF": 0.9,
        "CONSTANT": 0.8,
        "STRING": 0.75,
        "TEXT_FEATURE": 0.45,
        "OTHER": 0.4,
    }

    def __init__(
        self,
        *,
        query_overlap_weight: float = 0.18,
        evidence_kind_weight: float = 0.08,
        confidence_weight: float = 0.05,
        evidence_count_weight: float = 0.04,
        receipt_weight: float = 0.03,
        default_confidence: float = 0.5,
    ):
        self._query_overlap_weight = query_overlap_weight
        self._evidence_kind_weight = evidence_kind_weight
        self._confidence_weight = confidence_weight
        self._evidence_count_weight = evidence_count_weight
        self._receipt_weight = receipt_weight
        self._default_confidence = default_confidence

    def rerank(
        self,
        *,
        query_text: str,
        hits: list[SearchResult],
        index: "EmbeddingIndex",
        top_k: int,
    ) -> list[SearchResult]:
        if top_k <= 0 or not hits:
            return []

        reranked: list[SearchResult] = []
        for hit in hits:
            record = index.get_record(hit.function_id)
            features = self._derive_features(query_text=query_text, record=record)
            rerank_score = hit.score + self._feature_bonus(features)
            reranked.append(
                SearchResult(
                    function_id=hit.function_id,
                    name=hit.name,
                    score=rerank_score,
                )
            )

        reranked.sort(key=lambda item: (-item.score, item.function_id))
        return reranked[: min(top_k, len(reranked))]

    def _derive_features(
        self,
        *,
        query_text: str,
        record: FunctionRecord | None,
    ) -> EvidenceDerivedFeatures:
        if record is None:
            return EvidenceDerivedFeatures(
                evidence_count=0,
                evidence_kind_score=0.0,
                confidence_mean=0.0,
                query_overlap=0.0,
                receipt_signal=0.0,
            )

        query_tokens = set(_TOKEN_RE.findall(query_text.lower()))
        evidence_count = len(record.evidence_refs)
        if evidence_count == 0:
            return EvidenceDerivedFeatures(
                evidence_count=0,
                evidence_kind_score=0.0,
                confidence_mean=0.0,
                query_overlap=0.0,
                receipt_signal=self._receipt_signal(record),
            )

        weighted_kind_total = 0.0
        confidence_total = 0.0
        overlap_scores: list[float] = []
        for ref in record.evidence_refs:
            kind_weight = self._KIND_WEIGHTS.get(ref.kind, self._KIND_WEIGHTS["OTHER"])
            confidence = ref.confidence if ref.confidence is not None else self._default_confidence
            bounded_confidence = min(max(confidence, 0.0), 1.0)

            weighted_kind_total += kind_weight * bounded_confidence
            confidence_total += bounded_confidence

            if query_tokens:
                evidence_tokens = set(
                    _TOKEN_RE.findall(f"{ref.kind} {ref.description} {ref.uri}".lower())
                )
                if evidence_tokens:
                    overlap_scores.append(len(query_tokens & evidence_tokens) / len(query_tokens))

        evidence_kind_score = weighted_kind_total / evidence_count
        confidence_mean = confidence_total / evidence_count
        query_overlap = max(overlap_scores) if overlap_scores else 0.0
        return EvidenceDerivedFeatures(
            evidence_count=evidence_count,
            evidence_kind_score=evidence_kind_score,
            confidence_mean=confidence_mean,
            query_overlap=query_overlap,
            receipt_signal=self._receipt_signal(record),
        )

    def _feature_bonus(self, features: EvidenceDerivedFeatures) -> float:
        evidence_count_norm = min(features.evidence_count, 4) / 4.0
        bonus = (
            self._query_overlap_weight * features.query_overlap
            + self._evidence_kind_weight * features.evidence_kind_score
            + self._confidence_weight * features.confidence_mean
            + self._evidence_count_weight * evidence_count_norm
            + self._receipt_weight * features.receipt_signal
        )
        return min(max(bonus, 0.0), 0.35)

    @staticmethod
    def _receipt_signal(record: FunctionRecord) -> float:
        receipt_id = dict(record.provenance).get("receipt_id", "")
        if not receipt_id:
            return 0.0
        return 1.0 if receipt_id.startswith("receipt:") and receipt_id.count(":") >= 2 else 0.5


@dataclass(frozen=True)
class RankedSearchResult:
    """Ranked semantic search hit enriched with provenance and evidence."""

    rank: int
    function_id: str
    name: str
    score: float
    provenance: tuple[tuple[str, str], ...]
    evidence_refs: tuple[EvidenceRef, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "function_id": self.function_id,
            "name": self.name,
            "score": round(self.score, 6),
            "provenance": dict(self.provenance),
            "evidence_refs": [ref.to_json() for ref in self.evidence_refs],
        }


@dataclass(frozen=True)
class SearchLatencyMetric:
    """Latency metric emitted for semantic search interactions."""

    mode: str
    latency_ms: float
    top_k: int
    result_count: int
    query_chars: int
    query_tokens: int
    timestamp_utc: str
    seed_function_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "latency_ms": round(self.latency_ms, 3),
            "top_k": self.top_k,
            "result_count": self.result_count,
            "query_chars": self.query_chars,
            "query_tokens": self.query_tokens,
            "timestamp_utc": self.timestamp_utc,
            "seed_function_id": self.seed_function_id,
        }


@dataclass(frozen=True)
class SemanticSearchResponse:
    """Search service response for panel and API consumers."""

    mode: str
    query_text: str
    top_k: int
    results: tuple[RankedSearchResult, ...]
    metrics: SearchLatencyMetric
    seed_function_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "query": {
                "mode": self.mode,
                "text": self.query_text,
                "top_k": self.top_k,
                "seed_function_id": self.seed_function_id,
            },
            "results": [result.to_json() for result in self.results],
            "metrics": self.metrics.to_json(),
        }


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
        self._record_by_id = {
            indexed.record.function_id: indexed.record for indexed in indexed_records
        }
        self._stats = stats

    @property
    def stats(self) -> IndexBuildStats:
        return self._stats

    def get_record(self, function_id: str) -> FunctionRecord | None:
        return self._record_by_id.get(function_id)

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
                    **indexed.record.to_json(),
                    "id": indexed.record.function_id,
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
            record = FunctionRecord.from_json(raw)
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


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class SemanticSearchQueryService:
    """Intent and similar-function query service with latency instrumentation."""

    MODE_INTENT = "intent"
    MODE_SIMILAR_FUNCTION = "similar-function"

    def __init__(
        self,
        adapter: BaselineSimilarityAdapter,
        index: EmbeddingIndex,
        reranker: EvidenceWeightedReranker | None = None,
    ):
        self._adapter = adapter
        self._index = index
        self._reranker = reranker

    def search_intent(self, query_text: str, top_k: int = 5) -> SemanticSearchResponse:
        normalized = query_text.strip()
        start = _now_ns()
        hits = self._adapter.top_k(normalized, top_k=top_k)
        reranked_hits = self._rerank_or_fallback(
            query_text=normalized,
            hits=hits,
            top_k=top_k,
        )
        latency_ms = _ms(start, _now_ns())
        return self._build_response(
            mode=self.MODE_INTENT,
            query_text=normalized,
            top_k=top_k,
            raw_hits=reranked_hits,
            latency_ms=latency_ms,
            seed_function_id=None,
        )

    def search_similar_function(self, function_id: str, top_k: int = 5) -> SemanticSearchResponse:
        seed_record = self._index.get_record(function_id)
        if seed_record is None:
            raise ValueError(f"unknown function id: {function_id}")

        query_text = f"{seed_record.name} {seed_record.text}".strip()
        start = _now_ns()
        raw_hits = self._adapter.top_k(query_text, top_k=top_k + 1)
        filtered_hits = [item for item in raw_hits if item.function_id != function_id][:top_k]
        reranked_hits = self._rerank_or_fallback(
            query_text=query_text,
            hits=filtered_hits,
            top_k=top_k,
        )
        latency_ms = _ms(start, _now_ns())
        return self._build_response(
            mode=self.MODE_SIMILAR_FUNCTION,
            query_text=query_text,
            top_k=top_k,
            raw_hits=reranked_hits,
            latency_ms=latency_ms,
            seed_function_id=function_id,
        )

    def _rerank_or_fallback(
        self,
        *,
        query_text: str,
        hits: list[SearchResult],
        top_k: int,
    ) -> list[SearchResult]:
        if self._reranker is None or not hits:
            return hits[: min(top_k, len(hits))]
        try:
            return self._reranker.rerank(
                query_text=query_text,
                hits=hits,
                index=self._index,
                top_k=top_k,
            )
        except Exception:
            return hits[: min(top_k, len(hits))]

    def _build_response(
        self,
        *,
        mode: str,
        query_text: str,
        top_k: int,
        raw_hits: list[SearchResult],
        latency_ms: float,
        seed_function_id: str | None,
    ) -> SemanticSearchResponse:
        ranked: list[RankedSearchResult] = []
        for rank, hit in enumerate(raw_hits, start=1):
            record = self._index.get_record(hit.function_id)
            provenance = record.provenance if record else ()
            evidence_refs = record.evidence_refs if record else ()
            ranked.append(
                RankedSearchResult(
                    rank=rank,
                    function_id=hit.function_id,
                    name=hit.name,
                    score=hit.score,
                    provenance=provenance,
                    evidence_refs=evidence_refs,
                )
            )

        metrics = SearchLatencyMetric(
            mode=mode,
            latency_ms=latency_ms,
            top_k=top_k,
            result_count=len(ranked),
            query_chars=len(query_text),
            query_tokens=len(_TOKEN_RE.findall(query_text.lower())),
            timestamp_utc=_utc_now(),
            seed_function_id=seed_function_id,
        )
        return SemanticSearchResponse(
            mode=mode,
            query_text=query_text,
            top_k=top_k,
            results=tuple(ranked),
            metrics=metrics,
            seed_function_id=seed_function_id,
        )


def render_search_panel(response: SemanticSearchResponse) -> dict[str, Any]:
    """Build panel payload used by the in-tool semantic search UI."""
    return {
        "panel": {
            "id": "semantic-search",
            "title": "Semantic Search",
            "query_mode": response.mode,
            "query_text": response.query_text,
            "seed_function_id": response.seed_function_id,
            "result_count": len(response.results),
        },
        "results": [result.to_json() for result in response.results],
        "metrics": response.metrics.to_json(),
    }


def _append_latency_metric(telemetry_path: Path | None, metric: SearchLatencyMetric) -> None:
    if telemetry_path is None:
        return
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "schema_version": 1,
        "kind": "semantic_search_latency",
        **metric.to_json(),
    }
    with telemetry_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _run_semantic_search(
    *,
    service: SemanticSearchQueryService,
    mode: str,
    query: str | None,
    function_id: str | None,
    top_k: int,
) -> SemanticSearchResponse:
    if mode == SemanticSearchQueryService.MODE_INTENT:
        if not query:
            raise ValueError("--query is required when --mode=intent")
        return service.search_intent(query, top_k=top_k)
    if mode == SemanticSearchQueryService.MODE_SIMILAR_FUNCTION:
        if not function_id:
            raise ValueError("--function-id is required when --mode=similar-function")
        return service.search_similar_function(function_id, top_k=top_k)
    raise ValueError(f"unsupported mode: {mode}")


def load_corpus(corpus_path: Path) -> list[FunctionRecord]:
    doc = json.loads(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "functions" not in doc:
        raise ValueError("corpus must be an object with a 'functions' array")
    functions = doc["functions"]
    if not isinstance(functions, list):
        raise ValueError("'functions' must be an array")
    return [FunctionRecord.from_json(raw) for raw in functions]


def evaluate_queries(
    adapter: BaselineSimilarityAdapter,
    queries_path: Path,
    top_k: int,
    *,
    index: EmbeddingIndex | None = None,
    reranker: EvidenceWeightedReranker | None = None,
) -> dict[str, Any]:
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
        if reranker is not None and index is not None:
            try:
                hits = reranker.rerank(query_text=text, hits=hits, index=index, top_k=top_k)
            except Exception:
                hits = hits[: min(top_k, len(hits))]

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


def compare_eval_ordering(
    baseline_metrics: Mapping[str, Any],
    candidate_metrics: Mapping[str, Any],
    *,
    top_k: int,
) -> dict[str, Any]:
    baseline_results = baseline_metrics.get("results")
    candidate_results = candidate_metrics.get("results")
    if not isinstance(baseline_results, list) or not isinstance(candidate_results, list):
        raise ValueError("evaluate metrics missing list-valued 'results'")

    baseline_by_query = {
        str(item.get("query")): item for item in baseline_results if isinstance(item, Mapping)
    }
    candidate_by_query = {
        str(item.get("query")): item for item in candidate_results if isinstance(item, Mapping)
    }

    improved = 0
    worsened = 0
    unchanged = 0
    rank_deltas: list[float] = []

    for query_text, baseline_row in baseline_by_query.items():
        candidate_row = candidate_by_query.get(query_text)
        if candidate_row is None:
            continue

        baseline_rank = baseline_row.get("rank")
        candidate_rank = candidate_row.get("rank")
        baseline_rank_num = int(baseline_rank) if isinstance(baseline_rank, int) else top_k + 1
        candidate_rank_num = int(candidate_rank) if isinstance(candidate_rank, int) else top_k + 1

        delta = baseline_rank_num - candidate_rank_num
        rank_deltas.append(float(delta))
        if delta > 0:
            improved += 1
        elif delta < 0:
            worsened += 1
        else:
            unchanged += 1

    total = improved + worsened + unchanged
    mrr_delta = float(candidate_metrics.get("mrr", 0.0)) - float(baseline_metrics.get("mrr", 0.0))
    recall_delta = float(candidate_metrics.get("recall@1", 0.0)) - float(
        baseline_metrics.get("recall@1", 0.0)
    )

    return {
        "queries_compared": total,
        "ordering_improved_queries": improved,
        "ordering_worsened_queries": worsened,
        "ordering_unchanged_queries": unchanged,
        "mean_rank_delta": round((sum(rank_deltas) / total), 6) if total else 0.0,
        "mrr_delta": round(mrr_delta, 6),
        "recall@1_delta": round(recall_delta, 6),
        "improves_against_baseline": bool(
            total > 0 and improved > 0 and worsened == 0 and mrr_delta >= 0.0 and recall_delta >= 0.0
        ),
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
    reranker = None if args.disable_reranker else EvidenceWeightedReranker()
    service = SemanticSearchQueryService(adapter=adapter, index=index, reranker=reranker)
    response = _run_semantic_search(
        service=service,
        mode=args.mode,
        query=args.query,
        function_id=args.function_id,
        top_k=args.top_k,
    )
    _append_latency_metric(args.telemetry_path, response.metrics)
    print(json.dumps(response.to_json(), indent=2, sort_keys=True))
    return 0


def _panel_command(args: argparse.Namespace) -> int:
    index = EmbeddingIndex.load(args.index_dir)
    pipeline = LocalEmbeddingPipeline(vector_dimension=index.vector_dimension)
    adapter = BaselineSimilarityAdapter(pipeline=pipeline, index=index)
    reranker = None if args.disable_reranker else EvidenceWeightedReranker()
    service = SemanticSearchQueryService(adapter=adapter, index=index, reranker=reranker)
    response = _run_semantic_search(
        service=service,
        mode=args.mode,
        query=args.query,
        function_id=args.function_id,
        top_k=args.top_k,
    )
    _append_latency_metric(args.telemetry_path, response.metrics)
    panel = render_search_panel(response)
    print(json.dumps(panel, indent=2, sort_keys=True))
    return 0


def _evaluate_command(args: argparse.Namespace) -> int:
    index = EmbeddingIndex.load(args.index_dir)
    pipeline = LocalEmbeddingPipeline(vector_dimension=index.vector_dimension)
    adapter = BaselineSimilarityAdapter(pipeline=pipeline, index=index)
    baseline_metrics = evaluate_queries(adapter, args.queries, top_k=args.top_k)
    if args.disable_reranker:
        metrics = dict(baseline_metrics)
        metrics["reranker"] = {
            "enabled": False,
            "name": "evidence_weighted_v1",
            "status": "disabled",
        }
    else:
        reranker = EvidenceWeightedReranker()
        reranked_metrics = evaluate_queries(
            adapter,
            args.queries,
            top_k=args.top_k,
            index=index,
            reranker=reranker,
        )
        metrics = dict(reranked_metrics)
        metrics["baseline"] = baseline_metrics
        metrics["comparison"] = compare_eval_ordering(
            baseline_metrics,
            reranked_metrics,
            top_k=args.top_k,
        )
        metrics["reranker"] = {
            "enabled": True,
            "name": "evidence_weighted_v1",
            "status": "applied",
        }
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
    search_parser.add_argument(
        "--mode",
        type=str,
        default=SemanticSearchQueryService.MODE_INTENT,
        choices=[SemanticSearchQueryService.MODE_INTENT, SemanticSearchQueryService.MODE_SIMILAR_FUNCTION],
        help="Search mode: intent text query or similar-function lookup",
    )
    search_parser.add_argument("--query", type=str, default=None, help="Intent query text (required for mode=intent)")
    search_parser.add_argument(
        "--function-id",
        type=str,
        default=None,
        help="Function id seed (required for mode=similar-function)",
    )
    search_parser.add_argument("--top-k", type=int, default=5, help="Top-k result count")
    search_parser.add_argument(
        "--telemetry-path",
        type=Path,
        default=None,
        help="Optional JSONL path for latency telemetry events",
    )
    search_parser.add_argument(
        "--disable-reranker",
        action="store_true",
        help="Skip evidence-weighted reranking and return baseline ordering only",
    )
    search_parser.set_defaults(func=_search_command)

    panel_parser = subparsers.add_parser("panel", help="Render semantic search panel payload")
    panel_parser.add_argument("--index-dir", type=Path, required=True, help="Directory containing index artifacts")
    panel_parser.add_argument(
        "--mode",
        type=str,
        default=SemanticSearchQueryService.MODE_INTENT,
        choices=[SemanticSearchQueryService.MODE_INTENT, SemanticSearchQueryService.MODE_SIMILAR_FUNCTION],
        help="Search mode: intent text query or similar-function lookup",
    )
    panel_parser.add_argument("--query", type=str, default=None, help="Intent query text (required for mode=intent)")
    panel_parser.add_argument(
        "--function-id",
        type=str,
        default=None,
        help="Function id seed (required for mode=similar-function)",
    )
    panel_parser.add_argument("--top-k", type=int, default=5, help="Top-k result count")
    panel_parser.add_argument(
        "--telemetry-path",
        type=Path,
        default=None,
        help="Optional JSONL path for latency telemetry events",
    )
    panel_parser.add_argument(
        "--disable-reranker",
        action="store_true",
        help="Skip evidence-weighted reranking and return baseline ordering only",
    )
    panel_parser.set_defaults(func=_panel_command)

    eval_parser = subparsers.add_parser("evaluate", help="Evaluate retrieval metrics against query set")
    eval_parser.add_argument("--index-dir", type=Path, required=True, help="Directory containing index artifacts")
    eval_parser.add_argument("--queries", type=Path, required=True, help="Path to queries JSON")
    eval_parser.add_argument("--top-k", type=int, default=10, help="Top-k result count")
    eval_parser.add_argument("--output", type=Path, default=None, help="Optional metrics output JSON")
    eval_parser.add_argument(
        "--disable-reranker",
        action="store_true",
        help="Skip evidence-weighted reranking and evaluate baseline only",
    )
    eval_parser.set_defaults(func=_evaluate_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
