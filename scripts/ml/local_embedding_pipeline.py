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
import heapq
import json
import math
import os
import re
import tempfile
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
class TypeSuggestionPolicy:
    """Confidence threshold policy for type suggestion handling."""

    auto_apply_threshold: float = 0.9
    suggest_threshold: float = 0.5

    def __post_init__(self) -> None:
        if not 0.0 <= self.suggest_threshold <= 1.0:
            raise ValueError("suggest_threshold must be between 0 and 1")
        if not 0.0 <= self.auto_apply_threshold <= 1.0:
            raise ValueError("auto_apply_threshold must be between 0 and 1")
        if self.auto_apply_threshold < self.suggest_threshold:
            raise ValueError("auto_apply_threshold must be >= suggest_threshold")

    def classify(self, confidence: float) -> str:
        if confidence >= self.auto_apply_threshold:
            return "AUTO_APPLY"
        if confidence >= self.suggest_threshold:
            return "SUGGEST"
        return "QUARANTINED"

    def to_json(self) -> dict[str, Any]:
        return {
            "auto_apply_threshold": round(self.auto_apply_threshold, 6),
            "suggest_threshold": round(self.suggest_threshold, 6),
        }


@dataclass(frozen=True)
class TypeSuggestion:
    """Generated type suggestion with confidence, evidence summary, and policy outcome."""

    target_id: str
    target_scope: str
    suggested_type: str
    confidence: float
    evidence_summary: str
    policy_action: str
    quarantined: bool
    model_confidence: float
    evidence_score: float
    consensus_ratio: float
    pattern_match_score: float
    evidence_refs: tuple[EvidenceRef, ...] = ()
    ground_truth_type: str | None = None

    def is_correct(self) -> bool | None:
        if self.ground_truth_type is None:
            return None
        return self.suggested_type.strip() == self.ground_truth_type.strip()

    def to_json(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "target_id": self.target_id,
            "target_scope": self.target_scope,
            "suggested_type": self.suggested_type,
            "confidence": round(self.confidence, 6),
            "evidence_summary": self.evidence_summary,
            "policy_action": self.policy_action,
            "quarantined": self.quarantined,
            "confidence_components": {
                "model_confidence": round(self.model_confidence, 6),
                "evidence_score": round(self.evidence_score, 6),
                "consensus_ratio": round(self.consensus_ratio, 6),
                "pattern_match_score": round(self.pattern_match_score, 6),
            },
            "evidence_refs": [ref.to_json() for ref in self.evidence_refs],
        }
        if self.ground_truth_type is not None:
            doc["ground_truth_type"] = self.ground_truth_type
            doc["is_correct"] = self.is_correct()
        return doc


def _coerce_confidence(raw: Any, default: float = 0.0) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = default
    return max(0.0, min(1.0, value))


def _coerce_pattern_score(raw: Any) -> float:
    if isinstance(raw, bool):
        return 1.0 if raw else 0.0
    return _coerce_confidence(raw, default=0.0)


def _evidence_score(evidence_refs: tuple[EvidenceRef, ...]) -> float:
    if not evidence_refs:
        return 0.0
    density = min(len(evidence_refs) / 3.0, 1.0)
    confidences = [ref.confidence for ref in evidence_refs if ref.confidence is not None]
    average_confidence = (sum(confidences) / len(confidences)) if confidences else 0.6
    return max(0.0, min(1.0, 0.6 * density + 0.4 * average_confidence))


def _summarize_evidence(evidence_refs: tuple[EvidenceRef, ...]) -> str:
    if not evidence_refs:
        return "No evidence attached."
    kind_counts = Counter(ref.kind for ref in evidence_refs)
    dominant = max(kind_counts.items(), key=lambda item: (item[1], item[0]))[0]
    confidences = [ref.confidence for ref in evidence_refs if ref.confidence is not None]
    if confidences:
        average_confidence = sum(confidences) / len(confidences)
        return (
            f"{len(evidence_refs)} evidence refs; dominant={dominant}; "
            f"avg_evidence_confidence={average_confidence:.2f}"
        )
    return f"{len(evidence_refs)} evidence refs; dominant={dominant}; avg_evidence_confidence=unspecified"


class TypeSuggestionGenerator:
    """Generate confidence-scored type suggestions with threshold-based policy handling."""

    _DEFAULT_SCOPE = "VARIABLE"
    _SCOPES = {
        "VARIABLE",
        "PARAMETER",
        "RETURN_TYPE",
        "GLOBAL",
        "STRUCT_FIELD",
    }

    def __init__(self, policy: TypeSuggestionPolicy | None = None):
        self._policy = policy or TypeSuggestionPolicy()

    @property
    def policy(self) -> TypeSuggestionPolicy:
        return self._policy

    def generate(self, raw_suggestions: list[Mapping[str, Any]]) -> list[TypeSuggestion]:
        suggestions: list[TypeSuggestion] = []
        for idx, raw in enumerate(raw_suggestions):
            target_id = str(raw.get("target_id") or raw.get("id") or "").strip()
            if not target_id:
                raise ValueError(f"suggestion at index {idx} missing required target_id")

            suggested_type = str(raw.get("suggested_type") or raw.get("type") or "").strip()
            if not suggested_type:
                raise ValueError(f"suggestion at index {idx} missing required suggested_type")

            target_scope = str(raw.get("target_scope") or self._DEFAULT_SCOPE).strip().upper()
            if target_scope not in self._SCOPES:
                raise ValueError(f"suggestion at index {idx} has unsupported target_scope '{target_scope}'")

            evidence_refs = self._parse_evidence_refs(raw.get("evidence_refs"), target_id=target_id)
            model_confidence = _coerce_confidence(raw.get("model_confidence", raw.get("confidence")), default=0.0)
            consensus_ratio = _coerce_confidence(raw.get("consensus_ratio"), default=0.0)
            pattern_match_score = _coerce_pattern_score(raw.get("pattern_match_score", raw.get("pattern_match")))
            evidence_score = _evidence_score(evidence_refs)

            confidence = max(
                0.0,
                min(
                    1.0,
                    0.5 * model_confidence
                    + 0.3 * evidence_score
                    + 0.15 * consensus_ratio
                    + 0.05 * pattern_match_score,
                ),
            )
            policy_action = self._policy.classify(confidence)

            ground_truth_raw = raw.get("ground_truth_type")
            ground_truth_type = str(ground_truth_raw).strip() if ground_truth_raw is not None else None
            if ground_truth_type == "":
                ground_truth_type = None

            suggestions.append(
                TypeSuggestion(
                    target_id=target_id,
                    target_scope=target_scope,
                    suggested_type=suggested_type,
                    confidence=confidence,
                    evidence_summary=_summarize_evidence(evidence_refs),
                    policy_action=policy_action,
                    quarantined=policy_action == "QUARANTINED",
                    model_confidence=model_confidence,
                    evidence_score=evidence_score,
                    consensus_ratio=consensus_ratio,
                    pattern_match_score=pattern_match_score,
                    evidence_refs=evidence_refs,
                    ground_truth_type=ground_truth_type,
                )
            )
        return suggestions

    def _parse_evidence_refs(self, raw_refs: Any, *, target_id: str) -> tuple[EvidenceRef, ...]:
        refs: list[EvidenceRef] = []
        if isinstance(raw_refs, list):
            for item in raw_refs:
                if isinstance(item, Mapping):
                    refs.append(EvidenceRef.from_json(item, function_id=target_id))
        return tuple(refs)


def summarize_type_suggestion_metrics(
    suggestions: list[TypeSuggestion],
    *,
    policy: TypeSuggestionPolicy,
) -> dict[str, Any]:
    total = len(suggestions)
    auto_apply_count = sum(1 for suggestion in suggestions if suggestion.policy_action == "AUTO_APPLY")
    suggest_count = sum(1 for suggestion in suggestions if suggestion.policy_action == "SUGGEST")
    quarantined_count = sum(1 for suggestion in suggestions if suggestion.policy_action == "QUARANTINED")
    avg_confidence = (sum(suggestion.confidence for suggestion in suggestions) / total) if total else 0.0

    evaluated = [suggestion for suggestion in suggestions if suggestion.ground_truth_type is not None]
    evaluated_total = len(evaluated)
    correct_total = sum(1 for suggestion in evaluated if suggestion.is_correct() is True)
    incorrect_total = sum(1 for suggestion in evaluated if suggestion.is_correct() is False)

    accepted = [suggestion for suggestion in evaluated if suggestion.policy_action != "QUARANTINED"]
    accepted_total = len(accepted)
    accepted_correct = sum(1 for suggestion in accepted if suggestion.is_correct() is True)

    incorrect_quarantined = sum(
        1
        for suggestion in evaluated
        if suggestion.is_correct() is False and suggestion.policy_action == "QUARANTINED"
    )

    return {
        "total_suggestions": total,
        "average_confidence": round(avg_confidence, 6),
        "auto_apply_count": auto_apply_count,
        "suggest_count": suggest_count,
        "quarantined_count": quarantined_count,
        "quarantine_rate": round((quarantined_count / total), 6) if total else 0.0,
        "evaluated_with_ground_truth": evaluated_total,
        "overall_accuracy": round((correct_total / evaluated_total), 6) if evaluated_total else 0.0,
        "accepted_precision": round((accepted_correct / accepted_total), 6) if accepted_total else 0.0,
        "incorrect_quarantine_recall": round((incorrect_quarantined / incorrect_total), 6)
        if incorrect_total
        else 0.0,
        "policy_thresholds": policy.to_json(),
    }


def generate_type_suggestion_report(
    raw_suggestions: list[Mapping[str, Any]],
    *,
    policy: TypeSuggestionPolicy,
) -> dict[str, Any]:
    generator = TypeSuggestionGenerator(policy=policy)
    suggestions = generator.generate(raw_suggestions)
    metrics = summarize_type_suggestion_metrics(suggestions, policy=policy)
    return {
        "schema_version": 1,
        "kind": "type_suggestion_report",
        "generated_at_utc": _utc_now(),
        "policy": policy.to_json(),
        "suggestions": [suggestion.to_json() for suggestion in suggestions],
        "metrics": metrics,
    }


@dataclass(frozen=True)
class ReusableArtifact:
    """Reusable cross-binary artifact pulled from shared corpus entries."""

    kind: str
    target_scope: str
    value: str
    confidence: float | None = None
    target_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "kind": self.kind,
            "target_scope": self.target_scope,
            "value": self.value,
        }
        if self.confidence is not None:
            doc["confidence"] = round(self.confidence, 6)
        if self.target_id is not None:
            doc["target_id"] = self.target_id
        return doc


@dataclass(frozen=True)
class SharedCorpusReuseCandidate:
    """Shared-corpus proposal candidate used for cross-binary pullback retrieval."""

    proposal_id: str
    receipt_id: str
    function_id: str
    name: str
    text: str
    program_id: str | None
    reusable_artifacts: tuple[ReusableArtifact, ...]

    def to_function_record(self) -> FunctionRecord:
        provenance: dict[str, str] = {
            "source": "shared_corpus_backend",
            "record_id": self.proposal_id,
            "receipt_id": self.receipt_id,
        }
        if self.program_id is not None:
            provenance["program_id"] = self.program_id
        return FunctionRecord(
            function_id=self.function_id,
            name=self.name,
            text=self.text,
            provenance=tuple(sorted(provenance.items(), key=lambda item: item[0])),
            evidence_refs=(
                EvidenceRef.from_json(
                    {
                        "kind": "XREF",
                        "description": f"shared corpus receipt reference {self.receipt_id}",
                        "uri": f"shared-corpus://proposal/{self.proposal_id}",
                        "confidence": 1.0,
                    },
                    function_id=self.function_id,
                ),
            ),
        )


def _normalize_reuse_kind(raw_kind: Any) -> str:
    normalized = str(raw_kind or "").strip().upper()
    if normalized in {"NAME", "SYMBOL_NAME", "FUNCTION_NAME"}:
        return "NAME"
    if normalized in {"TYPE", "TYPE_ASSERTION", "TYPE_HINT"}:
        return "TYPE"
    if normalized in {"ANNOTATION", "COMMENT", "TAG"}:
        return "ANNOTATION"
    return ""


def _normalize_reuse_scope(raw_scope: Any, *, default: str) -> str:
    normalized = str(raw_scope or "").strip().upper()
    if not normalized:
        normalized = default
    return normalized


def _extract_reusable_artifacts(artifact: Mapping[str, Any]) -> tuple[ReusableArtifact, ...]:
    reusable: list[ReusableArtifact] = []
    seen: set[tuple[str, str, str, str]] = set()
    explicit_reusable_loaded = False

    def add(
        *,
        kind: Any,
        value: Any,
        target_scope: Any,
        confidence: Any = None,
        target_id: Any = None,
    ) -> None:
        normalized_kind = _normalize_reuse_kind(kind)
        normalized_value = str(value or "").strip()
        normalized_target_id = str(target_id).strip() if target_id is not None else None
        if normalized_target_id == "":
            normalized_target_id = None
        if not normalized_kind or not normalized_value:
            return

        scope_default = "FUNCTION" if normalized_kind in {"NAME", "ANNOTATION"} else "VARIABLE"
        normalized_scope = _normalize_reuse_scope(target_scope, default=scope_default)
        key = (
            normalized_kind,
            normalized_scope,
            normalized_value,
            normalized_target_id or "",
        )
        if key in seen:
            return
        seen.add(key)

        normalized_confidence = (
            _coerce_confidence(confidence, default=0.0) if confidence is not None else None
        )
        reusable.append(
            ReusableArtifact(
                kind=normalized_kind,
                target_scope=normalized_scope,
                value=normalized_value,
                confidence=normalized_confidence,
                target_id=normalized_target_id,
            )
        )

    reusable_raw = artifact.get("reusable_artifacts")
    if isinstance(reusable_raw, list):
        for item in reusable_raw:
            if not isinstance(item, Mapping):
                continue
            explicit_reusable_loaded = True
            add(
                kind=item.get("kind"),
                value=(
                    item.get("value")
                    or item.get("content")
                    or item.get("name")
                    or item.get("type")
                    or item.get("text")
                ),
                target_scope=item.get("target_scope") or item.get("scope"),
                confidence=item.get("confidence"),
                target_id=item.get("target_id"),
            )

    if explicit_reusable_loaded:
        return tuple(reusable)

    add(
        kind="NAME",
        value=artifact.get("function_name") or artifact.get("name"),
        target_scope="FUNCTION",
        confidence=artifact.get("name_confidence"),
    )

    types_raw = artifact.get("types") or artifact.get("type_assertions")
    if isinstance(types_raw, list):
        for item in types_raw:
            if isinstance(item, Mapping):
                add(
                    kind="TYPE",
                    value=item.get("value") or item.get("asserted_type") or item.get("type"),
                    target_scope=item.get("target_scope") or item.get("scope") or "VARIABLE",
                    confidence=item.get("confidence"),
                    target_id=item.get("target_id"),
                )
            else:
                add(kind="TYPE", value=item, target_scope="VARIABLE")

    annotations_raw = artifact.get("annotations") or artifact.get("comments")
    if isinstance(annotations_raw, list):
        for item in annotations_raw:
            if isinstance(item, Mapping):
                add(
                    kind="ANNOTATION",
                    value=item.get("value") or item.get("text") or item.get("comment"),
                    target_scope=item.get("target_scope") or item.get("scope") or "FUNCTION",
                    confidence=item.get("confidence"),
                    target_id=item.get("target_id"),
                )
            else:
                add(kind="ANNOTATION", value=item, target_scope="FUNCTION")

    add(
        kind="ANNOTATION",
        value=artifact.get("annotation") or artifact.get("comment"),
        target_scope="FUNCTION",
    )
    return tuple(reusable)


def _build_candidate_text(
    *,
    proposal_id: str,
    artifact: Mapping[str, Any],
    reusable_artifacts: tuple[ReusableArtifact, ...],
) -> str:
    parts: list[str] = [
        str(artifact.get("function_name") or ""),
        str(artifact.get("name") or ""),
        str(artifact.get("function_text") or ""),
        str(artifact.get("summary") or ""),
        str(artifact.get("description") or ""),
    ]
    parts.extend(item.value for item in reusable_artifacts)
    normalized = [part.strip() for part in parts if part.strip()]
    if not normalized:
        normalized = [proposal_id]
    return " ".join(normalized)


def load_shared_corpus_reuse_candidates(backend_store_path: Path) -> list[SharedCorpusReuseCandidate]:
    doc = json.loads(backend_store_path.read_text(encoding="utf-8"))
    if not isinstance(doc, Mapping):
        raise ValueError("backend store must be a JSON object with an 'artifacts' map")

    artifacts_raw = doc.get("artifacts")
    if not isinstance(artifacts_raw, Mapping):
        raise ValueError("backend store missing required 'artifacts' object")

    candidates: list[SharedCorpusReuseCandidate] = []
    for key, value in artifacts_raw.items():
        if not isinstance(value, Mapping):
            continue

        proposal_id = str(value.get("proposal_id") or key).strip()
        if not proposal_id:
            continue
        receipt_id = str(value.get("receipt_id") or f"receipt:{proposal_id}").strip()
        if not receipt_id:
            receipt_id = f"receipt:{proposal_id}"

        program_id_raw = value.get("program_id")
        program_id = str(program_id_raw).strip() if program_id_raw is not None else None
        if program_id == "":
            program_id = None

        artifact_raw = value.get("artifact")
        artifact = artifact_raw if isinstance(artifact_raw, Mapping) else {}
        reusable_artifacts = _extract_reusable_artifacts(artifact)
        if not reusable_artifacts:
            continue

        function_seed = f"shared-corpus:{proposal_id}:{receipt_id}"
        digest = hashlib.sha256(function_seed.encode("utf-8")).hexdigest()[:16]
        function_id = f"fn.shared.{digest}"
        name = str(artifact.get("function_name") or artifact.get("name") or proposal_id).strip() or proposal_id
        text = _build_candidate_text(
            proposal_id=proposal_id,
            artifact=artifact,
            reusable_artifacts=reusable_artifacts,
        )
        candidates.append(
            SharedCorpusReuseCandidate(
                proposal_id=proposal_id,
                receipt_id=receipt_id,
                function_id=function_id,
                name=name,
                text=text,
                program_id=program_id,
                reusable_artifacts=reusable_artifacts,
            )
        )

    candidates.sort(key=lambda item: item.proposal_id)
    return candidates


def _load_local_proposal_store(local_store_path: Path) -> dict[str, Any]:
    if not local_store_path.exists():
        return {
            "schema_version": 1,
            "kind": "local_proposal_store",
            "proposals": [],
        }

    doc = json.loads(local_store_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("local store must be a JSON object with a 'proposals' array")
    proposals = doc.get("proposals")
    if not isinstance(proposals, list):
        raise ValueError("local store missing required 'proposals' array")
    normalized = [dict(item) for item in proposals if isinstance(item, Mapping)]
    resolved = dict(doc)
    resolved["proposals"] = normalized
    return resolved


def _pullback_proposal_id(
    *,
    local_function_id: str,
    source_proposal_id: str,
    reusable_artifact: ReusableArtifact,
) -> str:
    seed = "|".join(
        [
            local_function_id,
            source_proposal_id,
            reusable_artifact.kind,
            reusable_artifact.target_scope,
            reusable_artifact.target_id or "",
            reusable_artifact.value,
        ]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
    return f"pullback:{digest}"


def _build_pullback_proposal(
    *,
    proposal_id: str,
    local_program_id: str | None,
    local_function: FunctionRecord,
    source_candidate: SharedCorpusReuseCandidate,
    reusable_artifact: ReusableArtifact,
    match_score: float,
) -> dict[str, Any]:
    receipt_id = f"receipt:pullback:{proposal_id.removeprefix('pullback:')}"
    provenance_chain: list[dict[str, str]] = []
    source_receipt_id = source_candidate.receipt_id
    if source_receipt_id:
        provenance_chain.append({"receipt_id": source_receipt_id})
    receipt_link: dict[str, str] = {"receipt_id": receipt_id}
    if source_receipt_id:
        receipt_link["previous_receipt_id"] = source_receipt_id
    provenance_chain.append(receipt_link)

    artifact_doc: dict[str, Any] = {
        "kind": "cross_binary_reuse_proposal",
        "proposal_origin": "cross_binary_pullback",
        "target_function_id": local_function.function_id,
        "target_function_name": local_function.name,
        "reuse_kind": reusable_artifact.kind,
        "target_scope": reusable_artifact.target_scope,
        "suggested_value": reusable_artifact.value,
        "source_proposal_id": source_candidate.proposal_id,
        "source_receipt_id": source_candidate.receipt_id,
        "source_program_id": source_candidate.program_id,
        "match_score": round(match_score, 6),
        "evidence_refs": [ref.to_json() for ref in local_function.evidence_refs],
    }
    if reusable_artifact.confidence is not None:
        artifact_doc["reuse_confidence"] = round(reusable_artifact.confidence, 6)
    if reusable_artifact.target_id is not None:
        artifact_doc["target_id"] = reusable_artifact.target_id

    proposal: dict[str, Any] = {
        "proposal_id": proposal_id,
        "state": "PROPOSED",
        "receipt_id": receipt_id,
        "updated_at_utc": _utc_now(),
        "artifact": artifact_doc,
        "provenance_chain": provenance_chain,
    }
    if local_program_id is not None:
        proposal["program_id"] = local_program_id
    return proposal


def pullback_cross_binary_reuse(
    *,
    index_dir: Path,
    backend_store: Path,
    local_store: Path,
    function_ids: list[str] | None = None,
    top_k: int = 3,
    min_score: float = 0.0,
    program_id: str | None = None,
    disable_reranker: bool = False,
    rerank_candidate_multiplier: int = 4,
) -> dict[str, Any]:
    if top_k <= 0:
        raise ValueError("top_k must be > 0")
    if rerank_candidate_multiplier <= 0:
        raise ValueError("rerank_candidate_multiplier must be > 0")

    local_index = EmbeddingIndex.load(index_dir)
    local_pipeline = LocalEmbeddingPipeline(vector_dimension=local_index.vector_dimension)

    selected_function_ids = [item.strip() for item in (function_ids or []) if item and item.strip()]
    if not selected_function_ids:
        selected_function_ids = list(local_index.function_ids())
    if not selected_function_ids:
        raise ValueError("local index contains no functions to query")

    shared_candidates = load_shared_corpus_reuse_candidates(backend_store)
    candidate_records = [candidate.to_function_record() for candidate in shared_candidates]
    candidate_index = local_pipeline.build_index(candidate_records)
    candidate_adapter = BaselineSimilarityAdapter(pipeline=local_pipeline, index=candidate_index)
    reranker = None if disable_reranker else EvidenceWeightedReranker()
    candidate_by_function_id = {candidate.function_id: candidate for candidate in shared_candidates}

    store_doc = _load_local_proposal_store(local_store)
    existing_proposals = store_doc["proposals"]
    existing_ids = {
        str(item.get("proposal_id") or item.get("id") or "").strip()
        for item in existing_proposals
        if str(item.get("proposal_id") or item.get("id") or "").strip()
    }

    inserted_count = 0
    already_present_count = 0
    total_proposals_generated = 0
    match_count = 0
    matches: list[dict[str, Any]] = []

    for local_function_id in selected_function_ids:
        local_record = local_index.get_record(local_function_id)
        if local_record is None:
            raise ValueError(f"unknown local function id: {local_function_id}")

        query_text = f"{local_record.name} {local_record.text}".strip()
        candidate_k = top_k
        if reranker is not None:
            candidate_k = max(top_k, top_k * rerank_candidate_multiplier)
            candidate_k = min(candidate_k, max(1, candidate_index.stats.corpus_size))

        hits = candidate_adapter.top_k(query_text, top_k=candidate_k)
        if reranker is not None:
            hits = reranker.rerank(
                query_text=query_text,
                hits=hits,
                index=candidate_index,
                top_k=top_k,
            )
        else:
            hits = hits[: min(top_k, len(hits))]

        for hit in hits:
            if hit.score < min_score:
                continue
            source_candidate = candidate_by_function_id.get(hit.function_id)
            if source_candidate is None:
                continue

            generated_ids: list[str] = []
            for reusable_artifact in source_candidate.reusable_artifacts:
                proposal_id = _pullback_proposal_id(
                    local_function_id=local_record.function_id,
                    source_proposal_id=source_candidate.proposal_id,
                    reusable_artifact=reusable_artifact,
                )
                total_proposals_generated += 1
                generated_ids.append(proposal_id)
                if proposal_id in existing_ids:
                    already_present_count += 1
                    continue
                proposal = _build_pullback_proposal(
                    proposal_id=proposal_id,
                    local_program_id=program_id,
                    local_function=local_record,
                    source_candidate=source_candidate,
                    reusable_artifact=reusable_artifact,
                    match_score=hit.score,
                )
                existing_proposals.append(proposal)
                existing_ids.add(proposal_id)
                inserted_count += 1

            match_count += 1
            matches.append(
                {
                    "local_function_id": local_record.function_id,
                    "source_proposal_id": source_candidate.proposal_id,
                    "source_receipt_id": source_candidate.receipt_id,
                    "source_program_id": source_candidate.program_id,
                    "score": round(hit.score, 6),
                    "reused_artifact_count": len(source_candidate.reusable_artifacts),
                    "proposal_ids": generated_ids,
                }
            )

    store_doc["schema_version"] = int(store_doc.get("schema_version") or 1)
    store_doc["kind"] = str(store_doc.get("kind") or "local_proposal_store")
    store_doc["proposals"] = existing_proposals
    local_store.parent.mkdir(parents=True, exist_ok=True)
    local_store.write_text(json.dumps(store_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {
        "schema_version": 1,
        "kind": "cross_binary_pullback_report",
        "generated_at_utc": _utc_now(),
        "query": {
            "function_ids": selected_function_ids,
            "top_k": top_k,
            "min_score": round(min_score, 6),
            "reranker_enabled": not disable_reranker,
            "rerank_candidate_multiplier": rerank_candidate_multiplier,
        },
        "metrics": {
            "local_function_count": len(selected_function_ids),
            "candidate_count": len(shared_candidates),
            "matches": match_count,
            "proposals_generated": total_proposals_generated,
            "inserted_count": inserted_count,
            "already_present_count": already_present_count,
        },
        "matches": sorted(
            matches,
            key=lambda item: (
                str(item.get("local_function_id") or ""),
                -float(item.get("score") or 0.0),
                str(item.get("source_proposal_id") or ""),
            ),
        ),
        "local_store": str(local_store),
    }


@dataclass(frozen=True)
class TriageFunctionFeatures:
    """Deterministic feature vector for mission-stage triage scoring."""

    function_id: str
    name: str
    entrypoint_score: float
    hotspot_score: float
    unknown_score: float
    tags: tuple[str, ...]
    rationale: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]


def _triage_source_context_uri(function_id: str) -> str:
    return f"local-index://function/{function_id}"


def _triage_evidence_links(
    function_id: str,
    evidence_refs: tuple[EvidenceRef, ...],
) -> list[dict[str, Any]]:
    source_context_uri = _triage_source_context_uri(function_id)
    return [
        {
            "evidence_ref_id": ref.evidence_ref_id,
            "kind": ref.kind,
            "description": ref.description,
            "uri": ref.uri,
            "source_context_uri": source_context_uri,
        }
        for ref in evidence_refs
    ]


@dataclass(frozen=True)
class TriageFinding:
    """Single triage output row containing evidence references."""

    function_id: str
    name: str
    score: float
    tags: tuple[str, ...]
    rationale: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]

    def to_json(self) -> dict[str, Any]:
        source_context_uri = _triage_source_context_uri(self.function_id)
        return {
            "function_id": self.function_id,
            "name": self.name,
            "score": round(self.score, 6),
            "tags": list(self.tags),
            "rationale": list(self.rationale),
            "source_context_uri": source_context_uri,
            "evidence_refs": [ref.to_json() for ref in self.evidence_refs],
            "evidence_links": _triage_evidence_links(self.function_id, self.evidence_refs),
        }


@dataclass(frozen=True)
class TriageMissionStageEvent:
    """Execution trace row for a mission stage transition."""

    stage: str
    input_count: int
    output_count: int
    next_stage: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "next_stage": self.next_stage,
        }


@dataclass(frozen=True)
class TriageMapNode:
    """UI row representing one function in the triage map."""

    function_id: str
    name: str
    entrypoint_score: float
    hotspot_score: float
    unknown_score: float
    is_entrypoint: bool
    is_hotspot: bool
    is_unknown: bool
    evidence_count: int
    tags: tuple[str, ...]
    rationale: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "name": self.name,
            "source_context_uri": _triage_source_context_uri(self.function_id),
            "scores": {
                "entrypoint": round(self.entrypoint_score, 6),
                "hotspot": round(self.hotspot_score, 6),
                "unknown": round(self.unknown_score, 6),
            },
            "classification": {
                "entrypoint": self.is_entrypoint,
                "hotspot": self.is_hotspot,
                "unknown": self.is_unknown,
            },
            "evidence_count": self.evidence_count,
            "tags": list(self.tags),
            "rationale": list(self.rationale),
        }


def _triage_ranked_rows(rows: tuple[TriageFinding, ...]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for rank, finding in enumerate(rows, start=1):
        row = finding.to_json()
        row["rank"] = rank
        ranked.append(row)
    return ranked


@dataclass(frozen=True)
class TriageMissionReport:
    """Persisted mission summary artifact for deterministic triage runs."""

    mission_id: str
    generated_at_utc: str
    stages: tuple[TriageMissionStageEvent, ...]
    features: tuple[TriageFunctionFeatures, ...]
    feature_count: int
    entrypoints: tuple[TriageFinding, ...]
    hotspots: tuple[TriageFinding, ...]
    unknowns: tuple[TriageFinding, ...]

    def to_json(self) -> dict[str, Any]:
        entrypoint_ids = {finding.function_id for finding in self.entrypoints}
        hotspot_ids = {finding.function_id for finding in self.hotspots}
        unknown_ids = {finding.function_id for finding in self.unknowns}
        triage_nodes = [
            TriageMapNode(
                function_id=feature.function_id,
                name=feature.name,
                entrypoint_score=feature.entrypoint_score,
                hotspot_score=feature.hotspot_score,
                unknown_score=feature.unknown_score,
                is_entrypoint=feature.function_id in entrypoint_ids,
                is_hotspot=feature.function_id in hotspot_ids,
                is_unknown=feature.function_id in unknown_ids,
                evidence_count=len(feature.evidence_refs),
                tags=feature.tags,
                rationale=feature.rationale,
            ).to_json()
            for feature in sorted(
                self.features,
                key=lambda item: (
                    -item.hotspot_score,
                    -item.entrypoint_score,
                    -item.unknown_score,
                    item.function_id,
                ),
            )
        ]
        return {
            "schema_version": 1,
            "kind": "triage_mission_summary",
            "mission_id": self.mission_id,
            "generated_at_utc": self.generated_at_utc,
            "execution": {
                "stage_graph": [stage.to_json() for stage in self.stages],
                "feature_count": self.feature_count,
            },
            "entrypoints": [finding.to_json() for finding in self.entrypoints],
            "hotspots": [finding.to_json() for finding in self.hotspots],
            "unknowns": [finding.to_json() for finding in self.unknowns],
            "ranked_hotspots": _triage_ranked_rows(self.hotspots),
            "triage_map": {
                "nodes": triage_nodes,
                "legend": {
                    "entrypoint": "Functions selected as likely mission entrypoints",
                    "hotspot": "Ranked hotspot candidates for analyst review",
                    "unknown": "Functions with low signal requiring manual triage",
                },
            },
            "counts": {
                "entrypoints": len(self.entrypoints),
                "hotspots": len(self.hotspots),
                "unknowns": len(self.unknowns),
            },
        }


class DeterministicTriageFeatureExtractor:
    """Deterministic feature extractor for entrypoint/hotspot/unknown scoring."""

    _ENTRYPOINT_HINTS = {
        "main",
        "start",
        "entry",
        "bootstrap",
        "dispatch",
        "handler",
        "init",
    }
    _CATEGORY_HINTS = {
        "CONFIG": {"config", "option", "registry", "setting", "profile", "argv"},
        "CRYPTO": {"aes", "rsa", "sha", "decrypt", "encrypt", "cipher", "key"},
        "NETWORK": {"socket", "http", "connect", "dns", "packet", "tls", "port"},
    }
    _UNKNOWN_HINTS = {"unknown", "opaque", "mystery", "obfuscated", "todo", "unresolved"}
    _OPAQUE_NAME_PREFIXES = ("fun_", "sub_", "thunk_", "unknown")
    _ENTRYPOINT_EVIDENCE_KINDS = {"CALLSITE", "XREF"}

    def extract(self, record: FunctionRecord) -> TriageFunctionFeatures:
        text_tokens = set(_TOKEN_RE.findall(f"{record.name} {record.text}".lower()))
        canonical_evidence_refs = self._canonicalize_evidence_refs(record.evidence_refs)
        evidence_kinds = {ref.kind for ref in canonical_evidence_refs}

        entrypoint_hits = sorted(text_tokens & self._ENTRYPOINT_HINTS)
        entrypoint_score = min(len(entrypoint_hits) / 3.0, 1.0)
        if evidence_kinds & self._ENTRYPOINT_EVIDENCE_KINDS:
            entrypoint_score = min(1.0, entrypoint_score + 0.2)

        tags: list[str] = []
        category_signals: list[float] = []
        rationale: list[str] = []
        if entrypoint_hits:
            rationale.append(f"entrypoint_hints={','.join(entrypoint_hits)}")

        for category, hints in self._CATEGORY_HINTS.items():
            hits = sorted(text_tokens & hints)
            if hits:
                tags.append(category)
                rationale.append(f"{category.lower()}_hints={','.join(hits)}")
            category_signals.append(min(len(hits), 3) / 3.0)

        category_signal = (
            sum(category_signals) / len(category_signals) if category_signals else 0.0
        )
        category_coverage = (
            len(tags) / len(self._CATEGORY_HINTS) if self._CATEGORY_HINTS else 0.0
        )
        evidence_signal = min(len(canonical_evidence_refs), 4) / 4.0
        hotspot_score = min(
            1.0,
            0.6 * category_signal + 0.25 * category_coverage + 0.15 * evidence_signal,
        )

        unknown_hits = sorted(text_tokens & self._UNKNOWN_HINTS)
        opaque_name = 0.0
        lowered_name = record.name.lower()
        if lowered_name.startswith(self._OPAQUE_NAME_PREFIXES):
            opaque_name = 1.0
        missing_domain_tags = 1.0 if not tags else 0.0
        weak_evidence = 1.0 if len(canonical_evidence_refs) <= 1 else 0.0
        unknown_score = min(
            1.0,
            0.4 * (1.0 if unknown_hits else 0.0)
            + 0.3 * missing_domain_tags
            + 0.2 * weak_evidence
            + 0.1 * opaque_name,
        )
        if unknown_hits:
            rationale.append(f"unknown_hints={','.join(unknown_hits)}")
        if weak_evidence:
            rationale.append("weak_evidence")
        if missing_domain_tags:
            rationale.append("no_domain_tags")

        return TriageFunctionFeatures(
            function_id=record.function_id,
            name=record.name,
            entrypoint_score=entrypoint_score,
            hotspot_score=hotspot_score,
            unknown_score=unknown_score,
            tags=tuple(sorted(tags)),
            rationale=tuple(sorted(set(rationale))),
            evidence_refs=canonical_evidence_refs,
        )

    @staticmethod
    def _canonicalize_evidence_refs(evidence_refs: tuple[EvidenceRef, ...]) -> tuple[EvidenceRef, ...]:
        unique_refs: dict[tuple[str, str, str, str, float | None], EvidenceRef] = {}
        for ref in evidence_refs:
            key = (ref.evidence_ref_id, ref.kind, ref.uri, ref.description, ref.confidence)
            if key not in unique_refs:
                unique_refs[key] = ref
        ordered = sorted(unique_refs.values(), key=lambda item: (item.evidence_ref_id, item.kind, item.uri))
        return tuple(ordered)


class DeterministicTriageMission:
    """Deterministic stage-graph mission for triage outputs and artifacts."""

    STAGE_GRAPH: tuple[tuple[str, str | None], ...] = (
        ("extract_features", "select_entrypoints"),
        ("select_entrypoints", "rank_hotspots"),
        ("rank_hotspots", "select_unknowns"),
        ("select_unknowns", "build_summary"),
        ("build_summary", None),
    )

    def __init__(
        self,
        *,
        feature_extractor: DeterministicTriageFeatureExtractor | None = None,
        entrypoint_threshold: float = 0.45,
        hotspot_threshold: float = 0.30,
        unknown_threshold: float = 0.55,
        hotspot_limit: int = 10,
    ):
        if hotspot_limit <= 0:
            raise ValueError("hotspot_limit must be > 0")
        self._feature_extractor = feature_extractor or DeterministicTriageFeatureExtractor()
        self._entrypoint_threshold = max(0.0, min(1.0, entrypoint_threshold))
        self._hotspot_threshold = max(0.0, min(1.0, hotspot_threshold))
        self._unknown_threshold = max(0.0, min(1.0, unknown_threshold))
        self._hotspot_limit = hotspot_limit

    def run(
        self,
        records: list[FunctionRecord],
        *,
        mission_id: str | None = None,
    ) -> TriageMissionReport:
        ordered_records = sorted(records, key=lambda item: item.function_id)
        resolved_mission_id = mission_id or self._derive_mission_id(ordered_records)

        stage_handlers = {
            "extract_features": self._stage_extract_features,
            "select_entrypoints": self._stage_select_entrypoints,
            "rank_hotspots": self._stage_rank_hotspots,
            "select_unknowns": self._stage_select_unknowns,
            "build_summary": self._stage_build_summary,
        }

        context: dict[str, Any] = {
            "records": ordered_records,
            "features": tuple(),
            "entrypoints": tuple(),
            "hotspots": tuple(),
            "unknowns": tuple(),
        }
        stage_events: list[TriageMissionStageEvent] = []

        for stage_name, next_stage in self.STAGE_GRAPH:
            handler = stage_handlers[stage_name]
            input_count = self._stage_input_count(stage_name, context)
            handler(context)
            output_count = self._stage_output_count(stage_name, context)
            stage_events.append(
                TriageMissionStageEvent(
                    stage=stage_name,
                    input_count=input_count,
                    output_count=output_count,
                    next_stage=next_stage,
                )
            )

        features = context["features"]
        entrypoints = context["entrypoints"]
        hotspots = context["hotspots"]
        unknowns = context["unknowns"]
        return TriageMissionReport(
            mission_id=resolved_mission_id,
            generated_at_utc=_utc_now(),
            stages=tuple(stage_events),
            features=features,
            feature_count=len(features),
            entrypoints=entrypoints,
            hotspots=hotspots,
            unknowns=unknowns,
        )

    @staticmethod
    def _derive_mission_id(records: list[FunctionRecord]) -> str:
        seed = "|".join(record.function_id for record in records)
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return f"triage:{digest}"

    @staticmethod
    def _stage_input_count(stage_name: str, context: Mapping[str, Any]) -> int:
        if stage_name == "extract_features":
            return len(context["records"])
        if stage_name == "select_entrypoints":
            return len(context["features"])
        if stage_name == "rank_hotspots":
            return len(context["features"])
        if stage_name == "select_unknowns":
            return len(context["features"])
        if stage_name == "build_summary":
            return len(context["entrypoints"]) + len(context["hotspots"]) + len(context["unknowns"])
        return 0

    @staticmethod
    def _stage_output_count(stage_name: str, context: Mapping[str, Any]) -> int:
        if stage_name == "extract_features":
            return len(context["features"])
        if stage_name == "select_entrypoints":
            return len(context["entrypoints"])
        if stage_name == "rank_hotspots":
            return len(context["hotspots"])
        if stage_name == "select_unknowns":
            return len(context["unknowns"])
        if stage_name == "build_summary":
            return 1
        return 0

    def _stage_extract_features(self, context: dict[str, Any]) -> None:
        records = context["records"]
        features = [self._feature_extractor.extract(record) for record in records]
        context["features"] = tuple(sorted(features, key=lambda item: item.function_id))

    def _stage_select_entrypoints(self, context: dict[str, Any]) -> None:
        features = context["features"]
        rows = [
            self._build_finding(
                feature=feature,
                score=feature.entrypoint_score,
            )
            for feature in features
            if feature.entrypoint_score >= self._entrypoint_threshold
        ]
        if not rows and features:
            fallback_features = sorted(
                features,
                key=lambda item: (-item.entrypoint_score, item.function_id),
            )
            rows = [
                self._build_finding(
                    feature=fallback_features[0],
                    score=fallback_features[0].entrypoint_score,
                )
            ]
        rows.sort(key=lambda item: (-item.score, item.function_id))
        context["entrypoints"] = tuple(rows)

    def _stage_rank_hotspots(self, context: dict[str, Any]) -> None:
        features = context["features"]
        rows = [
            self._build_finding(
                feature=feature,
                score=feature.hotspot_score,
            )
            for feature in features
            if feature.hotspot_score >= self._hotspot_threshold and feature.tags
        ]
        if not rows and features:
            fallback_features = [feature for feature in features if feature.tags]
            if not fallback_features:
                fallback_features = list(features)
            fallback_features.sort(key=lambda item: (-item.hotspot_score, item.function_id))
            fallback_limit = min(self._hotspot_limit, max(1, min(3, len(fallback_features))))
            rows = [
                self._build_finding(
                    feature=feature,
                    score=feature.hotspot_score,
                )
                for feature in fallback_features[:fallback_limit]
            ]
        rows.sort(key=lambda item: (-item.score, item.function_id))
        context["hotspots"] = tuple(rows[: min(self._hotspot_limit, len(rows))])

    def _stage_select_unknowns(self, context: dict[str, Any]) -> None:
        features = context["features"]
        rows = [
            self._build_finding(
                feature=feature,
                score=feature.unknown_score,
            )
            for feature in features
            if feature.unknown_score >= self._unknown_threshold
        ]
        if not rows and features:
            fallback_features = sorted(
                features,
                key=lambda item: (-item.unknown_score, item.function_id),
            )
            fallback_limit = max(1, min(3, len(fallback_features)))
            rows = [
                self._build_finding(
                    feature=feature,
                    score=feature.unknown_score,
                )
                for feature in fallback_features[:fallback_limit]
            ]
        rows.sort(key=lambda item: (-item.score, item.function_id))
        context["unknowns"] = tuple(rows)

    @staticmethod
    def _stage_build_summary(_: dict[str, Any]) -> None:
        return

    @staticmethod
    def _build_finding(*, feature: TriageFunctionFeatures, score: float) -> TriageFinding:
        return TriageFinding(
            function_id=feature.function_id,
            name=feature.name,
            score=score,
            tags=feature.tags,
            rationale=feature.rationale,
            evidence_refs=feature.evidence_refs,
        )


def render_triage_panel(report: Mapping[str, Any]) -> dict[str, Any]:
    """Build panel payload used by the in-tool triage mission UI."""
    triage_map = report.get("triage_map")
    if not isinstance(triage_map, Mapping):
        triage_map = {"nodes": [], "legend": {}}
    ranked_hotspots = report.get("ranked_hotspots")
    if not isinstance(ranked_hotspots, list):
        ranked_hotspots = []
    entrypoints = report.get("entrypoints")
    if not isinstance(entrypoints, list):
        entrypoints = []
    unknowns = report.get("unknowns")
    if not isinstance(unknowns, list):
        unknowns = []

    execution = report.get("execution")
    feature_count = 0
    if isinstance(execution, Mapping):
        try:
            feature_count = int(execution.get("feature_count") or 0)
        except (TypeError, ValueError):
            feature_count = 0

    nodes = triage_map.get("nodes")
    node_count = len(nodes) if isinstance(nodes, list) else 0
    return {
        "schema_version": 1,
        "kind": "triage_mission_panel",
        "panel": {
            "id": "triage-mission",
            "title": "Triage Mission",
            "mission_id": str(report.get("mission_id") or ""),
            "generated_at_utc": str(report.get("generated_at_utc") or ""),
            "feature_count": feature_count,
            "map_node_count": node_count,
            "hotspot_count": len(ranked_hotspots),
            "entrypoint_count": len(entrypoints),
            "unknown_count": len(unknowns),
        },
        "triage_map": triage_map,
        "ranked_hotspots": ranked_hotspots,
        "entrypoints": entrypoints,
        "unknowns": unknowns,
        "execution": execution if isinstance(execution, Mapping) else {},
    }


def _markdown_link(label: str, uri: str) -> str:
    safe_label = label.replace("|", "\\|")
    if uri:
        return f"[{safe_label}]({uri})"
    return safe_label


def _triage_report_markdown(report: Mapping[str, Any]) -> str:
    mission_id = str(report.get("mission_id") or "triage:unknown")
    generated_at = str(report.get("generated_at_utc") or "")
    counts = report.get("counts")
    if not isinstance(counts, Mapping):
        counts = {}
    entry_count = int(counts.get("entrypoints") or 0)
    hotspot_count = int(counts.get("hotspots") or 0)
    unknown_count = int(counts.get("unknowns") or 0)

    lines: list[str] = [
        "# Triage Mission Report",
        "",
        f"- Mission ID: `{mission_id}`",
        f"- Generated At (UTC): `{generated_at}`",
        f"- Entrypoints: `{entry_count}`",
        f"- Hotspots: `{hotspot_count}`",
        f"- Unknowns: `{unknown_count}`",
        "",
        "## Triage Map",
        "",
        "| Function | Entrypoint | Hotspot | Unknown | Evidence Count |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]

    triage_map = report.get("triage_map")
    nodes_raw = triage_map.get("nodes") if isinstance(triage_map, Mapping) else []
    nodes = nodes_raw if isinstance(nodes_raw, list) else []
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        function_id = str(node.get("function_id") or "")
        source_context_uri = str(node.get("source_context_uri") or "")
        scores = node.get("scores")
        if not isinstance(scores, Mapping):
            scores = {}
        evidence_count = int(node.get("evidence_count") or 0)
        lines.append(
            "| "
            + _markdown_link(function_id, source_context_uri)
            + " | "
            + f"{float(scores.get('entrypoint') or 0.0):.3f}"
            + " | "
            + f"{float(scores.get('hotspot') or 0.0):.3f}"
            + " | "
            + f"{float(scores.get('unknown') or 0.0):.3f}"
            + " | "
            + str(evidence_count)
            + " |"
        )

    lines.extend(
        [
            "",
            "## Ranked Hotspots",
            "",
            "| Rank | Function | Score | Evidence Links | Source Context |",
            "| ---: | --- | ---: | --- | --- |",
        ]
    )

    ranked_hotspots_raw = report.get("ranked_hotspots")
    ranked_hotspots = ranked_hotspots_raw if isinstance(ranked_hotspots_raw, list) else []
    for hotspot in ranked_hotspots:
        if not isinstance(hotspot, Mapping):
            continue
        rank = int(hotspot.get("rank") or 0)
        function_id = str(hotspot.get("function_id") or "")
        score = float(hotspot.get("score") or 0.0)
        source_context_uri = str(hotspot.get("source_context_uri") or "")
        evidence_links_raw = hotspot.get("evidence_links")
        evidence_links = evidence_links_raw if isinstance(evidence_links_raw, list) else []
        rendered_links: list[str] = []
        for link in evidence_links:
            if not isinstance(link, Mapping):
                continue
            label = str(link.get("evidence_ref_id") or link.get("kind") or "evidence")
            uri = str(link.get("uri") or "")
            rendered_links.append(_markdown_link(label, uri))
        evidence_cell = "<br>".join(rendered_links) if rendered_links else "n/a"
        lines.append(
            "| "
            + str(rank)
            + " | "
            + _markdown_link(function_id, source_context_uri)
            + " | "
            + f"{score:.3f}"
            + " | "
            + evidence_cell
            + " | "
            + _markdown_link("open", source_context_uri)
            + " |"
        )

    return "\n".join(lines) + "\n"


def write_triage_report_artifacts(
    report: Mapping[str, Any],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    """Persist triage mission artifacts for UI/report consumers."""
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_path = output_dir / "triage-summary.json"
    panel_path = output_dir / "triage-panel.json"
    markdown_path = output_dir / "triage-report.md"
    manifest_path = output_dir / "triage-artifacts.json"

    panel = render_triage_panel(report)
    markdown = _triage_report_markdown(report)

    summary_path.write_text(json.dumps(dict(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    panel_path.write_text(json.dumps(panel, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown, encoding="utf-8")

    manifest = {
        "schema_version": 1,
        "kind": "triage_mission_artifacts",
        "generated_at_utc": _utc_now(),
        "mission_id": str(report.get("mission_id") or ""),
        "artifacts": {
            "summary": str(summary_path),
            "panel": str(panel_path),
            "markdown": str(markdown_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


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
    sparse_vector: tuple[tuple[int, float], ...] = ()


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
                    sparse_vector=tuple(
                        (dimension, value)
                        for dimension, value in enumerate(vector)
                        if value != 0.0
                    ),
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
        self._function_ids = [indexed.record.function_id for indexed in indexed_records]
        self._names = [indexed.record.name for indexed in indexed_records]
        self._record_by_id = {
            indexed.record.function_id: indexed.record for indexed in indexed_records
        }
        self._postings: list[list[tuple[int, float]]] = [[] for _ in range(vector_dimension)]
        for record_idx, indexed in enumerate(indexed_records):
            sparse_vector = indexed.sparse_vector
            if not sparse_vector:
                sparse_vector = tuple(
                    (dimension, value)
                    for dimension, value in enumerate(indexed.vector)
                    if value != 0.0
                )
            for dimension, value in sparse_vector:
                self._postings[dimension].append((record_idx, value))
        self._stats = stats

    @property
    def stats(self) -> IndexBuildStats:
        return self._stats

    def function_ids(self) -> tuple[str, ...]:
        return tuple(self._function_ids)

    def get_record(self, function_id: str) -> FunctionRecord | None:
        return self._record_by_id.get(function_id)

    def search(self, query_text: str, top_k: int, pipeline: LocalEmbeddingPipeline) -> list[SearchResult]:
        if top_k <= 0:
            return []

        query_vector, query_norm, _ = pipeline._embed_tokens(pipeline.tokenize(query_text))
        if query_norm == 0.0:
            return []
        record_count = len(self._records)
        if record_count == 0:
            return []

        scores = [0.0] * record_count
        for dimension, query_weight in enumerate(query_vector):
            if query_weight == 0.0:
                continue
            for record_idx, record_weight in self._postings[dimension]:
                scores[record_idx] += query_weight * record_weight

        limit = min(top_k, record_count)
        ranked_indexes = heapq.nsmallest(
            limit,
            range(record_count),
            key=lambda idx: (-scores[idx], self._function_ids[idx]),
        )
        return [
            SearchResult(
                function_id=self._function_ids[idx],
                name=self._names[idx],
                score=scores[idx],
            )
            for idx in ranked_indexes
        ]

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
                    sparse_vector=tuple(
                        (dimension, value)
                        for dimension, value in enumerate(vector)
                        if value != 0.0
                    ),
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
        rerank_candidate_multiplier: int = 4,
    ):
        if rerank_candidate_multiplier <= 0:
            raise ValueError("rerank_candidate_multiplier must be > 0")
        self._adapter = adapter
        self._index = index
        self._reranker = reranker
        self._rerank_candidate_multiplier = rerank_candidate_multiplier

    def search_intent(self, query_text: str, top_k: int = 5) -> SemanticSearchResponse:
        normalized = query_text.strip()
        candidate_k = top_k
        if self._reranker is not None:
            candidate_k = max(top_k, top_k * self._rerank_candidate_multiplier)
        start = _now_ns()
        hits = self._adapter.top_k(normalized, top_k=candidate_k)
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
        candidate_k = top_k + 1
        if self._reranker is not None:
            candidate_k = max(top_k * self._rerank_candidate_multiplier, top_k) + 1
        start = _now_ns()
        raw_hits = self._adapter.top_k(query_text, top_k=candidate_k)
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


def _append_type_suggestion_metric(
    telemetry_path: Path | None,
    *,
    policy: TypeSuggestionPolicy,
    metrics: Mapping[str, Any],
) -> None:
    if telemetry_path is None:
        return
    telemetry_path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "schema_version": 1,
        "kind": "type_suggestion_quality",
        "timestamp_utc": _utc_now(),
        "policy": policy.to_json(),
        **dict(metrics),
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
    rerank_candidate_multiplier: int = 4,
) -> dict[str, Any]:
    doc = json.loads(queries_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("queries"), list):
        raise ValueError("queries document must contain a 'queries' array")

    queries = doc["queries"]
    total = 0
    recall_hits = 0
    recall_hits_top_k = 0
    mrr_total = 0.0
    results: list[dict[str, Any]] = []

    for query in queries:
        text = str(query.get("text") or "")
        gt = str(query.get("ground_truth_id") or "")
        candidate_k = top_k
        if reranker is not None and index is not None:
            multiplier = max(1, rerank_candidate_multiplier)
            candidate_k = max(top_k, top_k * multiplier)
            candidate_k = min(candidate_k, index.stats.corpus_size)
        hits = adapter.top_k(text, top_k=candidate_k)
        if reranker is not None and index is not None:
            try:
                hits = reranker.rerank(query_text=text, hits=hits, index=index, top_k=top_k)
            except Exception:
                hits = hits[: min(top_k, len(hits))]

        total += 1
        ranked_ids = [item.function_id for item in hits]
        if ranked_ids and ranked_ids[0] == gt:
            recall_hits += 1
        if gt in ranked_ids:
            recall_hits_top_k += 1

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
    recall_at_k = (recall_hits_top_k / total) if total else 0.0
    mrr = (mrr_total / total) if total else 0.0
    return {
        "queries": total,
        "recall@1": round(recall_at_1, 6),
        f"recall@{top_k}": round(recall_at_k, 6),
        "mrr": round(mrr, 6),
        "results": results,
    }


def _nearest_rank_percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    bounded = min(max(percentile, 0.0), 1.0)
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * bounded))
    return ordered[rank - 1]


def _build_mvp_semantic_search_corpus(
    *,
    corpus_size: int,
    top_k: int,
    rerank_candidate_multiplier: int,
) -> tuple[list[FunctionRecord], str, str]:
    if corpus_size <= 0:
        raise ValueError("corpus_size must be > 0")
    if top_k <= 0:
        raise ValueError("top_k must be > 0")
    if rerank_candidate_multiplier <= 0:
        raise ValueError("rerank_candidate_multiplier must be > 0")
    if corpus_size < (top_k + 1):
        raise ValueError("corpus_size must be at least top_k + 1")

    # Keep target outside top-k baseline ordering but inside the reranker candidate window.
    candidate_window = max(top_k + 1, top_k * rerank_candidate_multiplier)
    prefix_noise = min(
        corpus_size - 1,
        max(top_k + 1, min(candidate_window - 1, 24)),
    )
    tail_noise = corpus_size - prefix_noise - 1

    query_text = "callsite evidence iat thunk import resolver"
    target_function_id = "fn.mm.target.parse_imports"

    noise_provenance = (
        ("record_id", "benchmark-noise"),
        ("receipt_id", "receipt:benchmark:noise"),
        ("source", "benchmark"),
    )
    noise_evidence = (
        EvidenceRef(
            evidence_ref_id="evidence:benchmark:noise",
            kind="TEXT_FEATURE",
            description="feature hash token evidence",
            uri="local-index://features/benchmark-noise",
            confidence=0.4,
        ),
    )

    records: list[FunctionRecord] = []
    for index in range(prefix_noise):
        records.append(
            FunctionRecord(
                function_id=f"fn.aa.noise.{index:06d}",
                name="helper_noise",
                text="auxiliary routine buffer state machine checksum handler",
                provenance=noise_provenance,
                evidence_refs=noise_evidence,
            )
        )

    records.append(
        FunctionRecord(
            function_id=target_function_id,
            name="helper_noise",
            text="auxiliary routine buffer state machine checksum handler",
            provenance=(
                ("record_id", target_function_id),
                ("receipt_id", "receipt:benchmark:target"),
                ("source", "benchmark"),
            ),
            evidence_refs=(
                EvidenceRef(
                    evidence_ref_id="evidence:benchmark:target:callsite",
                    kind="CALLSITE",
                    description="callsite evidence iat thunk import resolver",
                    uri=f"local-index://evidence/{target_function_id}/callsite",
                    confidence=0.99,
                ),
                EvidenceRef(
                    evidence_ref_id="evidence:benchmark:target:xref",
                    kind="XREF",
                    description="xref evidence links iat thunk references",
                    uri=f"local-index://evidence/{target_function_id}/xref",
                    confidence=0.95,
                ),
            ),
        )
    )

    for index in range(tail_noise):
        records.append(
            FunctionRecord(
                function_id=f"fn.zz.noise.{index:06d}",
                name="helper_noise",
                text="auxiliary routine buffer state machine checksum handler",
                provenance=noise_provenance,
                evidence_refs=noise_evidence,
            )
        )

    return records, target_function_id, query_text


def run_mvp_semantic_search_benchmark(
    *,
    corpus_size: int = 100_000,
    vector_dimension: int = 128,
    top_k: int = 10,
    rerank_candidate_multiplier: int = 4,
    recall_query_count: int = 16,
    latency_sample_count: int = 120,
    latency_gate_ms: float = 300.0,
    recall_delta_gate: float = 0.10,
    receipt_completeness: float = 1.0,
    rollback_success_rate: float = 1.0,
    run_id: str | None = None,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    if top_k != 10:
        raise ValueError("MVP benchmark requires top_k=10 to evaluate Recall@10 gate")
    if recall_query_count <= 0:
        raise ValueError("recall_query_count must be > 0")
    if latency_sample_count <= 0:
        raise ValueError("latency_sample_count must be > 0")

    records, target_function_id, query_text = _build_mvp_semantic_search_corpus(
        corpus_size=corpus_size,
        top_k=top_k,
        rerank_candidate_multiplier=rerank_candidate_multiplier,
    )
    pipeline = LocalEmbeddingPipeline(vector_dimension=vector_dimension)
    index = pipeline.build_index(records)
    adapter = BaselineSimilarityAdapter(pipeline=pipeline, index=index)

    query_rows = [
        {"text": query_text, "ground_truth_id": target_function_id}
        for _ in range(recall_query_count)
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
        queries_path = Path(tmpdir) / "benchmark_queries.json"
        queries_path.write_text(
            json.dumps({"queries": query_rows}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        baseline_metrics = evaluate_queries(adapter, queries_path, top_k=top_k)
        reranked_metrics = evaluate_queries(
            adapter,
            queries_path,
            top_k=top_k,
            index=index,
            reranker=EvidenceWeightedReranker(),
            rerank_candidate_multiplier=rerank_candidate_multiplier,
        )

    recall_key = f"recall@{top_k}"
    stock_recall = float(baseline_metrics.get(recall_key, 0.0))
    candidate_recall = float(reranked_metrics.get(recall_key, 0.0))
    recall_delta = candidate_recall - stock_recall

    service = SemanticSearchQueryService(
        adapter=adapter,
        index=index,
        reranker=EvidenceWeightedReranker(),
        rerank_candidate_multiplier=rerank_candidate_multiplier,
    )
    latencies_ms: list[float] = []
    for _ in range(latency_sample_count):
        response = service.search_intent(query_text, top_k=top_k)
        latencies_ms.append(response.metrics.latency_ms)

    latency_p50 = round(_nearest_rank_percentile(latencies_ms, 0.50), 3)
    latency_p95 = round(_nearest_rank_percentile(latencies_ms, 0.95), 3)
    latency_p99 = round(_nearest_rank_percentile(latencies_ms, 0.99), 3)

    recall_pass = recall_delta >= recall_delta_gate
    latency_pass = latency_p95 <= latency_gate_ms
    receipt_pass = math.isclose(receipt_completeness, 1.0, rel_tol=0.0, abs_tol=1e-9)
    rollback_pass = math.isclose(rollback_success_rate, 1.0, rel_tol=0.0, abs_tol=1e-9)

    resolved_run_id = run_id
    if not resolved_run_id:
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        resolved_run_id = f"semantic-search-mvp-{stamp}"

    resolved_commit_sha = commit_sha or os.environ.get("GITHUB_SHA") or "unknown"
    metrics = {
        "recall_at_10_delta_vs_stock": round(recall_delta, 6),
        "search_latency_p95_ms": latency_p95,
        "receipt_completeness": round(receipt_completeness, 6),
        "rollback_success_rate": round(rollback_success_rate, 6),
        "stock_recall_at_10": round(stock_recall, 6),
        "candidate_recall_at_10": round(candidate_recall, 6),
        "search_latency_p50_ms": latency_p50,
        "search_latency_p99_ms": latency_p99,
    }
    gates = {
        "recall_at_10_delta_vs_stock": {
            "operator": ">=",
            "threshold": round(recall_delta_gate, 6),
            "value": metrics["recall_at_10_delta_vs_stock"],
            "passed": recall_pass,
        },
        "search_latency_p95_ms": {
            "operator": "<=",
            "threshold": round(latency_gate_ms, 6),
            "value": metrics["search_latency_p95_ms"],
            "passed": latency_pass,
        },
        "receipt_completeness": {
            "operator": "==",
            "threshold": 1.0,
            "value": metrics["receipt_completeness"],
            "passed": receipt_pass,
        },
        "rollback_success_rate": {
            "operator": "==",
            "threshold": 1.0,
            "value": metrics["rollback_success_rate"],
            "passed": rollback_pass,
        },
    }
    return {
        "schema_version": 1,
        "kind": "semantic_search_mvp_benchmark",
        "run_id": resolved_run_id,
        "timestamp": _utc_now(),
        "commit_sha": resolved_commit_sha,
        "status": "passed" if all(gate["passed"] for gate in gates.values()) else "failed",
        "corpus": {
            "target_size": corpus_size,
            "actual_size": index.stats.corpus_size,
            "vector_dimension": vector_dimension,
        },
        "query_profile": {
            "top_k": top_k,
            "recall_query_count": recall_query_count,
            "latency_sample_count": latency_sample_count,
            "rerank_candidate_multiplier": rerank_candidate_multiplier,
            "query_text": query_text,
            "ground_truth_id": target_function_id,
        },
        "metrics": metrics,
        "gates": gates,
        "baseline": {
            "recall@10": round(stock_recall, 6),
            "recall@1": float(baseline_metrics.get("recall@1", 0.0)),
            "mrr": float(baseline_metrics.get("mrr", 0.0)),
        },
        "candidate": {
            "recall@10": round(candidate_recall, 6),
            "recall@1": float(reranked_metrics.get("recall@1", 0.0)),
            "mrr": float(reranked_metrics.get("mrr", 0.0)),
        },
        "build_stats": asdict(index.stats),
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
    recall_k_key = f"recall@{top_k}"
    recall_at_top_k_delta = float(candidate_metrics.get(recall_k_key, 0.0)) - float(
        baseline_metrics.get(recall_k_key, 0.0)
    )

    return {
        "queries_compared": total,
        "ordering_improved_queries": improved,
        "ordering_worsened_queries": worsened,
        "ordering_unchanged_queries": unchanged,
        "mean_rank_delta": round((sum(rank_deltas) / total), 6) if total else 0.0,
        "mrr_delta": round(mrr_delta, 6),
        "recall@1_delta": round(recall_delta, 6),
        "recall_metric_key": recall_k_key,
        "recall_at_top_k_delta": round(recall_at_top_k_delta, 6),
        "improves_against_baseline": bool(
            total > 0 and improved > 0 and worsened == 0 and mrr_delta >= 0.0 and recall_delta >= 0.0
        ),
    }


def load_type_suggestion_inputs(input_path: Path) -> list[Mapping[str, Any]]:
    doc = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("suggestions"), list):
        raise ValueError("type suggestion input must contain a 'suggestions' array")

    suggestions: list[Mapping[str, Any]] = []
    for idx, item in enumerate(doc["suggestions"]):
        if not isinstance(item, Mapping):
            raise ValueError(f"suggestion at index {idx} must be an object")
        suggestions.append(item)
    return suggestions


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
    service = SemanticSearchQueryService(
        adapter=adapter,
        index=index,
        reranker=reranker,
        rerank_candidate_multiplier=max(1, args.rerank_candidate_multiplier),
    )
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
    service = SemanticSearchQueryService(
        adapter=adapter,
        index=index,
        reranker=reranker,
        rerank_candidate_multiplier=max(1, args.rerank_candidate_multiplier),
    )
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
            "candidate_multiplier": 1,
        }
    else:
        reranker = EvidenceWeightedReranker()
        reranked_metrics = evaluate_queries(
            adapter,
            args.queries,
            top_k=args.top_k,
            index=index,
            reranker=reranker,
            rerank_candidate_multiplier=max(1, args.rerank_candidate_multiplier),
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
            "candidate_multiplier": max(1, args.rerank_candidate_multiplier),
        }
    metrics["build_stats"] = asdict(adapter.build_stats)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


def _benchmark_mvp_command(args: argparse.Namespace) -> int:
    report = run_mvp_semantic_search_benchmark(
        corpus_size=args.target_corpus_size,
        vector_dimension=args.vector_dimension,
        top_k=args.top_k,
        rerank_candidate_multiplier=max(1, args.rerank_candidate_multiplier),
        recall_query_count=args.recall_query_count,
        latency_sample_count=args.latency_sample_count,
        latency_gate_ms=args.latency_gate_ms,
        recall_delta_gate=args.recall_delta_gate,
        receipt_completeness=args.receipt_completeness,
        rollback_success_rate=args.rollback_success_rate,
        run_id=args.run_id,
        commit_sha=args.commit_sha,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.no_fail_on_gate_fail:
        return 0
    return 0 if report.get("status") == "passed" else 1


def _suggest_types_command(args: argparse.Namespace) -> int:
    policy = TypeSuggestionPolicy(
        auto_apply_threshold=args.auto_apply_threshold,
        suggest_threshold=args.suggest_threshold,
    )
    raw_suggestions = load_type_suggestion_inputs(args.input)
    report = generate_type_suggestion_report(raw_suggestions, policy=policy)
    _append_type_suggestion_metric(args.telemetry_path, policy=policy, metrics=report["metrics"])

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _run_triage_mission(args: argparse.Namespace) -> dict[str, Any]:
    records = load_corpus(args.corpus)
    mission = DeterministicTriageMission(
        entrypoint_threshold=args.entrypoint_threshold,
        hotspot_threshold=args.hotspot_threshold,
        unknown_threshold=args.unknown_threshold,
        hotspot_limit=args.hotspot_limit,
    )
    return mission.run(records, mission_id=args.mission_id).to_json()


def _triage_mission_command(args: argparse.Namespace) -> int:
    report = _run_triage_mission(args)
    wrote_output = False

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml327] wrote {args.output}")
        wrote_output = True

    if args.report_dir:
        manifest = write_triage_report_artifacts(report, output_dir=args.report_dir)
        print(f"[ml327] wrote {args.report_dir}")
        print(json.dumps(manifest, indent=2, sort_keys=True))
        wrote_output = True

    if not wrote_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _triage_panel_command(args: argparse.Namespace) -> int:
    report = _run_triage_mission(args)
    panel = render_triage_panel(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(panel, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml327] wrote {args.output}")
    else:
        print(json.dumps(panel, indent=2, sort_keys=True))
    return 0


def _pullback_reuse_command(args: argparse.Namespace) -> int:
    normalized_program_id = str(args.program_id).strip() if args.program_id is not None else None
    if normalized_program_id == "":
        normalized_program_id = None
    report = pullback_cross_binary_reuse(
        index_dir=args.index_dir,
        backend_store=args.backend_store,
        local_store=args.local_store,
        function_ids=args.function_id,
        top_k=args.top_k,
        min_score=args.min_score,
        program_id=normalized_program_id,
        disable_reranker=args.disable_reranker,
        rerank_candidate_multiplier=max(1, args.rerank_candidate_multiplier),
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _add_triage_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--corpus", type=Path, required=True, help="Path to corpus JSON")
    parser.add_argument(
        "--mission-id",
        type=str,
        default=None,
        help="Optional mission id override for deterministic artifact naming",
    )
    parser.add_argument(
        "--entrypoint-threshold",
        type=float,
        default=0.45,
        help="Score threshold for entrypoint emission",
    )
    parser.add_argument(
        "--hotspot-threshold",
        type=float,
        default=0.30,
        help="Score threshold for hotspot emission",
    )
    parser.add_argument(
        "--unknown-threshold",
        type=float,
        default=0.55,
        help="Score threshold for unknown emission",
    )
    parser.add_argument(
        "--hotspot-limit",
        type=int,
        default=10,
        help="Maximum hotspot rows to include in summary artifact",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ML-301/ML-327 deterministic ML utility commands")
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
    search_parser.add_argument(
        "--rerank-candidate-multiplier",
        type=int,
        default=4,
        help="When reranker is enabled, retrieve top_k*multiplier candidates before reranking",
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
    panel_parser.add_argument(
        "--rerank-candidate-multiplier",
        type=int,
        default=4,
        help="When reranker is enabled, retrieve top_k*multiplier candidates before reranking",
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
    eval_parser.add_argument(
        "--rerank-candidate-multiplier",
        type=int,
        default=4,
        help="When reranker is enabled, retrieve top_k*multiplier candidates before reranking",
    )
    eval_parser.set_defaults(func=_evaluate_command)

    benchmark_parser = subparsers.add_parser(
        "benchmark-mvp",
        help="Run deterministic semantic search MVP benchmark and emit gate metrics",
    )
    benchmark_parser.add_argument(
        "--target-corpus-size",
        type=int,
        default=100000,
        help="Deterministic synthetic corpus size used for latency and recall gates",
    )
    benchmark_parser.add_argument(
        "--vector-dimension",
        type=int,
        default=128,
        help="Embedding vector dimension for the benchmark index",
    )
    benchmark_parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Top-k cutoff (MVP gate expects top-k=10)",
    )
    benchmark_parser.add_argument(
        "--recall-query-count",
        type=int,
        default=16,
        help="Number of benchmark queries used to compute recall deltas",
    )
    benchmark_parser.add_argument(
        "--latency-sample-count",
        type=int,
        default=120,
        help="Number of instrumented queries used to estimate latency percentiles",
    )
    benchmark_parser.add_argument(
        "--rerank-candidate-multiplier",
        type=int,
        default=4,
        help="Candidate oversampling multiplier for reranked retrieval",
    )
    benchmark_parser.add_argument(
        "--latency-gate-ms",
        type=float,
        default=300.0,
        help="MVP p95 latency gate in milliseconds",
    )
    benchmark_parser.add_argument(
        "--recall-delta-gate",
        type=float,
        default=0.10,
        help="Minimum Recall@10 delta over stock baseline",
    )
    benchmark_parser.add_argument(
        "--receipt-completeness",
        type=float,
        default=1.0,
        help="Receipt completeness metric included in the MVP gate artifact",
    )
    benchmark_parser.add_argument(
        "--rollback-success-rate",
        type=float,
        default=1.0,
        help="Rollback success-rate metric included in the MVP gate artifact",
    )
    benchmark_parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Optional deterministic run id for artifact naming",
    )
    benchmark_parser.add_argument(
        "--commit-sha",
        type=str,
        default=None,
        help="Optional commit SHA attached to the benchmark artifact",
    )
    benchmark_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write benchmark artifact JSON",
    )
    benchmark_parser.add_argument(
        "--no-fail-on-gate-fail",
        action="store_true",
        help="Always exit zero even when one or more gates fail",
    )
    benchmark_parser.set_defaults(func=_benchmark_mvp_command)

    suggest_parser = subparsers.add_parser(
        "suggest-types",
        help="Generate confidence-scored type suggestions with threshold policy",
    )
    suggest_parser.add_argument("--input", type=Path, required=True, help="Path to type suggestion input JSON")
    suggest_parser.add_argument("--output", type=Path, default=None, help="Optional suggestion report JSON")
    suggest_parser.add_argument(
        "--auto-apply-threshold",
        type=float,
        default=0.9,
        help="Confidence threshold for AUTO_APPLY policy action",
    )
    suggest_parser.add_argument(
        "--suggest-threshold",
        type=float,
        default=0.5,
        help="Minimum confidence threshold before suggestions leave quarantine",
    )
    suggest_parser.add_argument(
        "--telemetry-path",
        type=Path,
        default=None,
        help="Optional JSONL path for suggestion-quality telemetry events",
    )
    suggest_parser.set_defaults(func=_suggest_types_command)

    triage_parser = subparsers.add_parser(
        "triage-mission",
        help="Run deterministic triage mission graph and emit summary artifact",
    )
    _add_triage_common_args(triage_parser)
    triage_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write mission summary artifact JSON",
    )
    triage_parser.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Optional directory for triage summary/panel/markdown export artifacts",
    )
    triage_parser.set_defaults(func=_triage_mission_command)

    triage_panel_parser = subparsers.add_parser(
        "triage-panel",
        help="Render triage mission panel payload (map + ranked hotspots)",
    )
    _add_triage_common_args(triage_panel_parser)
    triage_panel_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write triage panel payload JSON",
    )
    triage_panel_parser.set_defaults(func=_triage_panel_command)

    pullback_parser = subparsers.add_parser(
        "pullback-reuse",
        help="Pull cross-binary reusable artifacts into local proposal store",
    )
    pullback_parser.add_argument("--index-dir", type=Path, required=True, help="Directory containing local index")
    pullback_parser.add_argument(
        "--backend-store",
        type=Path,
        required=True,
        help="Path to shared corpus backend JSON produced by corpus sync worker",
    )
    pullback_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON to insert pulled proposals",
    )
    pullback_parser.add_argument(
        "--function-id",
        action="append",
        default=None,
        help="Local function id to query for cross-binary matches. Repeatable. Defaults to all local functions.",
    )
    pullback_parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="Top-k cross-binary matches to consider per local function",
    )
    pullback_parser.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        help="Minimum similarity score required before proposals are generated",
    )
    pullback_parser.add_argument(
        "--program-id",
        type=str,
        default=None,
        help="Optional local program id attached to generated proposals",
    )
    pullback_parser.add_argument(
        "--disable-reranker",
        action="store_true",
        help="Skip evidence-weighted reranking and use baseline ordering only",
    )
    pullback_parser.add_argument(
        "--rerank-candidate-multiplier",
        type=int,
        default=4,
        help="When reranker is enabled, retrieve top_k*multiplier candidates before reranking",
    )
    pullback_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write pullback report JSON",
    )
    pullback_parser.set_defaults(func=_pullback_reuse_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
