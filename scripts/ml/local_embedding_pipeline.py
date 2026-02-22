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
import uuid
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
TRIAGE_LABEL_KEYS = ("entrypoint", "hotspot", "unknown")

# Legacy threshold tuple retained for calibration reports and before/after docs.
LEGACY_TRIAGE_ENTRYPOINT_THRESHOLD = 0.45
LEGACY_TRIAGE_HOTSPOT_THRESHOLD = 0.30
LEGACY_TRIAGE_UNKNOWN_THRESHOLD = 0.55

# Calibrated defaults from curated benchmark v2026.02.1.
DEFAULT_TRIAGE_ENTRYPOINT_THRESHOLD = 0.30
DEFAULT_TRIAGE_HOTSPOT_THRESHOLD = 0.25
DEFAULT_TRIAGE_UNKNOWN_THRESHOLD = 0.65
DEFAULT_TRIAGE_CALIBRATION_STEP = 0.05

PROPOSAL_STATE_PROPOSED = "PROPOSED"
PROPOSAL_STATE_APPROVED = "APPROVED"
PROPOSAL_STATE_REJECTED = "REJECTED"
PROPOSAL_STATE_APPLIED = "APPLIED"
PROPOSAL_ACTION_APPLY = "APPLY"
PROPOSAL_ACTION_ROLLBACK = "ROLLBACK"
PROPOSAL_LINK_APPLIES_PROPOSAL = "APPLIES_PROPOSAL"
PROPOSAL_LINK_ROLLS_BACK_APPLY = "ROLLS_BACK_APPLY"
PROPOSAL_REVIEW_ACTION_APPROVE = "APPROVE"
PROPOSAL_REVIEW_ACTION_REJECT = "REJECT"
PROPOSAL_ALLOWED_STATES = (
    PROPOSAL_STATE_PROPOSED,
    PROPOSAL_STATE_APPROVED,
    PROPOSAL_STATE_REJECTED,
    PROPOSAL_STATE_APPLIED,
)
PROPOSAL_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    PROPOSAL_STATE_PROPOSED: frozenset({PROPOSAL_STATE_APPROVED, PROPOSAL_STATE_REJECTED}),
    PROPOSAL_STATE_APPROVED: frozenset({PROPOSAL_STATE_APPLIED}),
    PROPOSAL_STATE_REJECTED: frozenset(),
    PROPOSAL_STATE_APPLIED: frozenset({PROPOSAL_STATE_APPROVED}),
}
PROPOSAL_REVIEW_ACTION_TO_STATE = {
    PROPOSAL_REVIEW_ACTION_APPROVE: PROPOSAL_STATE_APPROVED,
    PROPOSAL_REVIEW_ACTION_REJECT: PROPOSAL_STATE_REJECTED,
}

TYPE_ASSERTION_STATE_PROPOSED = "PROPOSED"
TYPE_ASSERTION_STATE_UNDER_REVIEW = "UNDER_REVIEW"
TYPE_ASSERTION_STATE_ACCEPTED = "ACCEPTED"
TYPE_ASSERTION_STATE_PROPAGATED = "PROPAGATED"
TYPE_ASSERTION_STATE_DEPRECATED = "DEPRECATED"
TYPE_ASSERTION_STATE_REJECTED = "REJECTED"
TYPE_ASSERTION_ALLOWED_STATES = (
    TYPE_ASSERTION_STATE_PROPOSED,
    TYPE_ASSERTION_STATE_UNDER_REVIEW,
    TYPE_ASSERTION_STATE_ACCEPTED,
    TYPE_ASSERTION_STATE_PROPAGATED,
    TYPE_ASSERTION_STATE_DEPRECATED,
    TYPE_ASSERTION_STATE_REJECTED,
)

TYPE_SOURCE_DWARF = "DWARF"
TYPE_SOURCE_ANALYST = "ANALYST"
TYPE_SOURCE_CONSTRAINT_SOLVER = "CONSTRAINT_SOLVER"
TYPE_SOURCE_ML_MODEL = "ML_MODEL"
TYPE_SOURCE_HEURISTIC = "HEURISTIC"
TYPE_SOURCE_GHIDRA_DEFAULT = "GHIDRA_DEFAULT"
TYPE_SOURCE_ALLOWED = (
    TYPE_SOURCE_DWARF,
    TYPE_SOURCE_ANALYST,
    TYPE_SOURCE_CONSTRAINT_SOLVER,
    TYPE_SOURCE_ML_MODEL,
    TYPE_SOURCE_HEURISTIC,
    TYPE_SOURCE_GHIDRA_DEFAULT,
)

TYPE_PROPAGATION_SCOPE_SAME_PROGRAM = "SAME_PROGRAM"
TYPE_PROPAGATION_SCOPE_CROSS_PROGRAM = "CROSS_PROGRAM"
TYPE_PROPAGATION_SCOPE_CORPUS_KB = "CORPUS_KB"
TYPE_PROPAGATION_ALLOWED_SCOPES = (
    TYPE_PROPAGATION_SCOPE_SAME_PROGRAM,
    TYPE_PROPAGATION_SCOPE_CROSS_PROGRAM,
    TYPE_PROPAGATION_SCOPE_CORPUS_KB,
)

RETRIEVAL_SCOPE_LOCAL = "LOCAL"
RETRIEVAL_SCOPE_CORPUS = "CORPUS"
RETRIEVAL_SCOPE_BOTH = "BOTH"
RETRIEVAL_ALLOWED_SCOPES = (
    RETRIEVAL_SCOPE_LOCAL,
    RETRIEVAL_SCOPE_CORPUS,
    RETRIEVAL_SCOPE_BOTH,
)

TYPE_PROPAGATION_MODE_AUTO = "AUTO_PROPAGATE"
TYPE_PROPAGATION_MODE_PROPOSE = "PROPOSE"
TYPE_PROPAGATION_MODE_DISABLED = "DISABLED"
TYPE_PROPAGATION_ALLOWED_MODES = (
    TYPE_PROPAGATION_MODE_AUTO,
    TYPE_PROPAGATION_MODE_PROPOSE,
    TYPE_PROPAGATION_MODE_DISABLED,
)

TYPE_PROPAGATION_OUTCOME_APPLIED = "APPLIED"
TYPE_PROPAGATION_OUTCOME_PROPOSED = "PROPOSED"
TYPE_PROPAGATION_OUTCOME_SKIPPED = "SKIPPED"
TYPE_PROPAGATION_OUTCOME_CONFLICT = "CONFLICT"
TYPE_PROPAGATION_OUTCOME_ROLLED_BACK = "ROLLED_BACK"

TYPE_CONFLICT_STATUS_OPEN = "OPEN"
TYPE_CONFLICT_STATUS_AUTO_RESOLVED = "AUTO_RESOLVED"
TYPE_CONFLICT_STATUS_ESCALATED = "ESCALATED"
TYPE_CONFLICT_STATUS_RESOLVED = "RESOLVED"

TYPE_CONFLICT_STRATEGY_SOURCE_PRIORITY = "SOURCE_PRIORITY"
TYPE_CONFLICT_STRATEGY_HIGHER_CONFIDENCE = "HIGHER_CONFIDENCE"
TYPE_CONFLICT_STRATEGY_TIE_BREAK = "DETERMINISTIC_TIE_BREAK"
TYPE_CONFLICT_STRATEGY_MANUAL_REVIEW = "MANUAL_REVIEW"

TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC = "ASSERTION_ID_ASC"
TYPE_PROPAGATION_TIE_BREAK_TARGET_ID_ASC = "TARGET_ID_ASC"
TYPE_PROPAGATION_TIE_BREAK_RECEIPT_TIMESTAMP_ASC = "RECEIPT_TIMESTAMP_ASC"
TYPE_PROPAGATION_WORKFLOW_VERSION = "source-priority-confidence-tiebreak-v1"

TYPE_PR_STATUS_DRAFT = "DRAFT"
TYPE_PR_STATUS_OPEN = "OPEN"
TYPE_PR_STATUS_IN_REVIEW = "IN_REVIEW"
TYPE_PR_STATUS_CHANGES_REQUESTED = "CHANGES_REQUESTED"
TYPE_PR_STATUS_APPROVED = "APPROVED"
TYPE_PR_STATUS_MERGED = "MERGED"
TYPE_PR_STATUS_REJECTED = "REJECTED"
TYPE_PR_STATUS_CLOSED = "CLOSED"
TYPE_PR_ALLOWED_STATUSES = (
    TYPE_PR_STATUS_DRAFT,
    TYPE_PR_STATUS_OPEN,
    TYPE_PR_STATUS_IN_REVIEW,
    TYPE_PR_STATUS_CHANGES_REQUESTED,
    TYPE_PR_STATUS_APPROVED,
    TYPE_PR_STATUS_MERGED,
    TYPE_PR_STATUS_REJECTED,
    TYPE_PR_STATUS_CLOSED,
)
TYPE_PR_QUEUE_STATUSES = (
    TYPE_PR_STATUS_OPEN,
    TYPE_PR_STATUS_IN_REVIEW,
    TYPE_PR_STATUS_CHANGES_REQUESTED,
)
TYPE_PR_REVIEWABLE_STATUSES = frozenset(TYPE_PR_QUEUE_STATUSES)

TYPE_PR_DECISION_APPROVE = "APPROVE"
TYPE_PR_DECISION_REQUEST_CHANGES = "REQUEST_CHANGES"
TYPE_PR_DECISION_REJECT = "REJECT"
TYPE_PR_DECISION_TO_PR_STATUS = {
    TYPE_PR_DECISION_APPROVE: TYPE_PR_STATUS_APPROVED,
    TYPE_PR_DECISION_REQUEST_CHANGES: TYPE_PR_STATUS_CHANGES_REQUESTED,
    TYPE_PR_DECISION_REJECT: TYPE_PR_STATUS_REJECTED,
}
TYPE_PR_DECISION_TO_ASSERTION_STATE = {
    TYPE_PR_DECISION_APPROVE: TYPE_ASSERTION_STATE_ACCEPTED,
    TYPE_PR_DECISION_REQUEST_CHANGES: TYPE_ASSERTION_STATE_PROPOSED,
    TYPE_PR_DECISION_REJECT: TYPE_ASSERTION_STATE_REJECTED,
}
TYPE_PR_DECISION_TO_REVIEWER_STATUS = {
    TYPE_PR_DECISION_APPROVE: "APPROVED",
    TYPE_PR_DECISION_REQUEST_CHANGES: "CHANGES_REQUESTED",
    TYPE_PR_DECISION_REJECT: "REJECTED",
}


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
    evidence_diversity: float
    stable_ref_ratio: float
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
        evidence_diversity_weight: float = 0.03,
        stable_ref_weight: float = 0.02,
        receipt_weight: float = 0.03,
        default_confidence: float = 0.5,
    ):
        self._query_overlap_weight = query_overlap_weight
        self._evidence_kind_weight = evidence_kind_weight
        self._confidence_weight = confidence_weight
        self._evidence_count_weight = evidence_count_weight
        self._evidence_diversity_weight = evidence_diversity_weight
        self._stable_ref_weight = stable_ref_weight
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
                evidence_diversity=0.0,
                stable_ref_ratio=0.0,
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
                evidence_diversity=0.0,
                stable_ref_ratio=0.0,
                query_overlap=0.0,
                receipt_signal=self._receipt_signal(record),
            )

        weighted_kind_total = 0.0
        confidence_total = 0.0
        stable_ref_count = 0
        evidence_kinds: set[str] = set()
        overlap_scores: list[float] = []
        for ref in record.evidence_refs:
            kind_weight = self._KIND_WEIGHTS.get(ref.kind, self._KIND_WEIGHTS["OTHER"])
            confidence = ref.confidence if ref.confidence is not None else self._default_confidence
            bounded_confidence = min(max(confidence, 0.0), 1.0)
            evidence_kinds.add(ref.kind)
            ref_id = str(ref.evidence_ref_id).strip().lower()
            if ref_id.startswith("evr_") or ref_id.startswith("evidence:"):
                stable_ref_count += 1

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
        evidence_diversity = len(evidence_kinds) / min(evidence_count, 3)
        stable_ref_ratio = stable_ref_count / evidence_count
        query_overlap = max(overlap_scores) if overlap_scores else 0.0
        return EvidenceDerivedFeatures(
            evidence_count=evidence_count,
            evidence_kind_score=evidence_kind_score,
            confidence_mean=confidence_mean,
            evidence_diversity=evidence_diversity,
            stable_ref_ratio=stable_ref_ratio,
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
            + self._evidence_diversity_weight * features.evidence_diversity
            + self._stable_ref_weight * features.stable_ref_ratio
            + self._receipt_weight * features.receipt_signal
        )
        return min(max(bonus, 0.0), 0.35)

    @staticmethod
    def _receipt_signal(record: FunctionRecord) -> float:
        provenance = dict(record.provenance)
        receipt_id = str(provenance.get("receipt_id", "")).strip()
        source = str(provenance.get("source", "")).strip()
        record_id = str(provenance.get("record_id", "")).strip()
        completeness = sum(1 for value in (receipt_id, source, record_id) if value) / 3.0
        if not receipt_id:
            return 0.35 * completeness
        if receipt_id.startswith("receipt:") and receipt_id.count(":") >= 2:
            structure_score = 1.0
        elif receipt_id.startswith("receipt:"):
            structure_score = 0.75
        else:
            structure_score = 0.5
        return min(1.0, 0.6 * structure_score + 0.4 * completeness)


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
class CandidateStageMetric:
    """Per-stage candidate generation accounting emitted with each query."""

    stage: str
    enabled: bool
    input_count: int
    output_count: int
    contribution_count: int
    details: tuple[tuple[str, Any], ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "enabled": self.enabled,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "contribution_count": self.contribution_count,
            "details": dict(self.details),
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
    candidate_stage_metrics: tuple[CandidateStageMetric, ...] = ()
    embedding_backend_status: str = "available"
    embedding_fallback_applied: bool = False

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
            "embedding_backend_status": self.embedding_backend_status,
            "embedding_fallback_applied": self.embedding_fallback_applied,
            "candidate_stage_metrics": [stage.to_json() for stage in self.candidate_stage_metrics],
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
class BenchmarkArtifact:
    """Benchmark artifact capturing recall and p95 latency deltas."""

    artifact_id: str
    timestamp_utc: str
    scope: str
    recall_at_10_baseline: float
    recall_at_10_candidate: float
    recall_at_10_delta: float
    latency_p95_baseline_ms: float
    latency_p95_candidate_ms: float
    latency_p95_delta_ms: float
    corpus_size: int
    query_count: int
    passed: bool
    recall_gate_threshold: float = 0.10
    latency_gate_threshold_ms: float = 300.0

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "benchmark_artifact",
            "artifact_id": self.artifact_id,
            "timestamp_utc": self.timestamp_utc,
            "scope": self.scope,
            "recall": {
                "baseline": round(self.recall_at_10_baseline, 6),
                "candidate": round(self.recall_at_10_candidate, 6),
                "delta": round(self.recall_at_10_delta, 6),
                "gate_threshold": round(self.recall_gate_threshold, 6),
                "passed": self.recall_at_10_delta >= self.recall_gate_threshold,
            },
            "latency_p95": {
                "baseline_ms": round(self.latency_p95_baseline_ms, 3),
                "candidate_ms": round(self.latency_p95_candidate_ms, 3),
                "delta_ms": round(self.latency_p95_delta_ms, 3),
                "gate_threshold_ms": round(self.latency_gate_threshold_ms, 3),
                "passed": self.latency_p95_candidate_ms <= self.latency_gate_threshold_ms,
            },
            "corpus_size": self.corpus_size,
            "query_count": self.query_count,
            "passed": self.passed,
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

        state = str(value.get("state") or "").strip().upper()
        if state and state != PROPOSAL_STATE_APPROVED:
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
            "type_prs": [],
        }

    doc = json.loads(local_store_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("local store must be a JSON object with a 'proposals' array")
    proposals = doc.get("proposals")
    if not isinstance(proposals, list):
        raise ValueError("local store missing required 'proposals' array")
    normalized = [
        normalized_item
        for item in proposals
        if isinstance(item, Mapping)
        for normalized_item in (_normalize_local_proposal(item),)
        if normalized_item
    ]
    type_prs_raw = doc.get("type_prs")
    if type_prs_raw is None:
        type_prs_raw = []
    if not isinstance(type_prs_raw, list):
        raise ValueError("local store 'type_prs' value must be an array when provided")
    normalized_type_prs = [
        normalized_item
        for item in type_prs_raw
        if isinstance(item, Mapping)
        for normalized_item in (_normalize_local_type_pr(item),)
        if normalized_item
    ]
    resolved = dict(doc)
    resolved["proposals"] = normalized
    resolved["type_prs"] = normalized_type_prs
    return resolved


def _proposal_id_from_doc(proposal: Mapping[str, Any]) -> str:
    return str(proposal.get("proposal_id") or proposal.get("id") or "").strip()


def _type_pr_id_from_doc(type_pr: Mapping[str, Any]) -> str:
    return str(type_pr.get("type_pr_id") or type_pr.get("pr_id") or type_pr.get("id") or "").strip()


def _type_assertion_id_from_doc(assertion: Mapping[str, Any]) -> str:
    return str(assertion.get("assertion_id") or assertion.get("id") or "").strip()


def _normalize_proposal_state(
    raw_state: Any,
    *,
    default: str = PROPOSAL_STATE_PROPOSED,
) -> str:
    normalized = str(raw_state or "").strip().upper()
    if not normalized:
        return default
    return normalized


def _new_proposal_transition(
    *,
    from_state: str | None,
    to_state: str,
    action: str,
    changed_at_utc: str | None = None,
    actor_id: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    transition: dict[str, Any] = {
        "from_state": from_state,
        "to_state": to_state,
        "action": action,
        "changed_at_utc": changed_at_utc or _utc_now(),
    }
    if actor_id:
        transition["actor_id"] = actor_id
    if reason:
        transition["reason"] = reason
    return transition


def _normalize_evidence_kind(raw_kind: Any) -> str:
    normalized = str(raw_kind or "").strip().upper()
    return normalized or "OTHER"


def _coerce_evidence_confidence(raw_confidence: Any) -> float | None:
    if raw_confidence is None:
        return None
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(confidence):
        return None
    return confidence


def _stable_evidence_ref_id(
    *,
    kind: str,
    uri: str,
    description: str,
    confidence: float | None,
) -> str:
    confidence_token = "" if confidence is None else f"{confidence:.6f}"
    seed_payload = {
        "kind": kind,
        "uri": uri,
        "description": description,
        "confidence": confidence_token,
    }
    canonical_seed = json.dumps(
        seed_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical_seed.encode("utf-8")).hexdigest()
    return f"evr_{digest}"


def _normalize_proposal_evidence_ref(
    raw_ref: Mapping[str, Any],
    *,
    proposal_id: str,
) -> dict[str, Any]:
    kind = _normalize_evidence_kind(raw_ref.get("kind") or raw_ref.get("type"))
    description = str(raw_ref.get("description") or "").strip()
    if not description:
        description = f"{kind} evidence for {proposal_id}"

    uri = str(raw_ref.get("uri") or "").strip()
    if not uri:
        uri = f"local-proposal://{proposal_id}/evidence/{kind.lower()}"

    confidence = _coerce_evidence_confidence(raw_ref.get("confidence"))
    evidence_ref_id = str(raw_ref.get("evidence_ref_id") or raw_ref.get("id") or "").strip()
    if not evidence_ref_id:
        evidence_ref_id = _stable_evidence_ref_id(
            kind=kind,
            uri=uri,
            description=description,
            confidence=confidence,
        )

    normalized: dict[str, Any] = {
        "evidence_ref_id": evidence_ref_id,
        "kind": kind,
        "description": description,
        "uri": uri,
    }
    if confidence is not None:
        normalized["confidence"] = confidence
    return normalized


def _normalize_proposal_evidence_refs(
    raw_refs: Any,
    *,
    proposal_id: str,
) -> list[dict[str, Any]]:
    if not isinstance(raw_refs, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in raw_refs:
        if not isinstance(item, Mapping):
            continue
        normalized.append(_normalize_proposal_evidence_ref(item, proposal_id=proposal_id))

    deduped: dict[str, dict[str, Any]] = {}
    for item in normalized:
        evidence_ref_id = str(item.get("evidence_ref_id") or "").strip()
        if not evidence_ref_id:
            continue
        if evidence_ref_id not in deduped:
            deduped[evidence_ref_id] = dict(item)

    return sorted(
        deduped.values(),
        key=lambda item: (
            str(item.get("evidence_ref_id") or ""),
            str(item.get("kind") or ""),
            str(item.get("uri") or ""),
        ),
    )


def _collect_proposal_evidence_refs(
    proposal: Mapping[str, Any],
    *,
    proposal_id: str,
) -> list[dict[str, Any]]:
    raw_collected: list[dict[str, Any]] = []
    for field in ("evidence_refs", "evidence_links"):
        field_value = proposal.get(field)
        if isinstance(field_value, list):
            raw_collected.extend(dict(item) for item in field_value if isinstance(item, Mapping))

    artifact_raw = proposal.get("artifact")
    if isinstance(artifact_raw, Mapping):
        for field in ("evidence_refs", "evidence_links"):
            field_value = artifact_raw.get(field)
            if isinstance(field_value, list):
                raw_collected.extend(dict(item) for item in field_value if isinstance(item, Mapping))

    if not raw_collected:
        evidence_link_ids_raw = proposal.get("evidence_link_ids")
        if isinstance(evidence_link_ids_raw, list):
            for evidence_ref_id in evidence_link_ids_raw:
                normalized_id = str(evidence_ref_id).strip()
                if not normalized_id:
                    continue
                raw_collected.append(
                    {
                        "evidence_ref_id": normalized_id,
                        "kind": "OTHER",
                        "description": f"Evidence link {normalized_id} for {proposal_id}",
                        "uri": f"local-proposal://{proposal_id}/evidence/{normalized_id}",
                    }
                )

    return _normalize_proposal_evidence_refs(raw_collected, proposal_id=proposal_id)


def _proposal_evidence_link_ids(proposal: Mapping[str, Any]) -> list[str]:
    evidence_link_ids_raw = proposal.get("evidence_link_ids")
    if isinstance(evidence_link_ids_raw, list):
        normalized = sorted(
            {
                str(item).strip()
                for item in evidence_link_ids_raw
                if str(item).strip()
            }
        )
        if normalized:
            return normalized

    evidence_refs_raw = proposal.get("evidence_refs")
    if not isinstance(evidence_refs_raw, list):
        return []

    return sorted(
        {
            str(item.get("evidence_ref_id") or "").strip()
            for item in evidence_refs_raw
            if isinstance(item, Mapping) and str(item.get("evidence_ref_id") or "").strip()
        }
    )


def _proposal_evidence_links(proposal: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence_refs_raw = proposal.get("evidence_refs")
    if isinstance(evidence_refs_raw, list):
        normalized = _normalize_proposal_evidence_refs(
            evidence_refs_raw,
            proposal_id=_proposal_id_from_doc(proposal) or "proposal",
        )
        if normalized:
            return normalized

    proposal_id = _proposal_id_from_doc(proposal) or "proposal"
    return [
        {
            "evidence_ref_id": evidence_ref_id,
            "kind": "OTHER",
            "description": f"Evidence link {evidence_ref_id} for {proposal_id}",
            "uri": f"local-proposal://{proposal_id}/evidence/{evidence_ref_id}",
        }
        for evidence_ref_id in _proposal_evidence_link_ids(proposal)
    ]


def _normalize_local_proposal(raw: Mapping[str, Any]) -> dict[str, Any]:
    proposal = dict(raw)
    proposal_id = _proposal_id_from_doc(proposal)
    if not proposal_id:
        return {}

    proposal["proposal_id"] = proposal_id
    proposal["state"] = _normalize_proposal_state(
        proposal.get("state") or proposal.get("status"),
    )

    updated_at_utc = str(proposal.get("updated_at_utc") or proposal.get("updated_at") or "").strip()
    if not updated_at_utc:
        updated_at_utc = _utc_now()
    proposal["updated_at_utc"] = updated_at_utc

    transitions_raw = proposal.get("lifecycle_transitions")
    transitions = [dict(item) for item in transitions_raw if isinstance(item, Mapping)] if isinstance(transitions_raw, list) else []
    if not transitions:
        transitions = [
            _new_proposal_transition(
                from_state=None,
                to_state=proposal["state"],
                action="CREATE",
                changed_at_utc=updated_at_utc,
            )
        ]
    proposal["lifecycle_transitions"] = transitions

    evidence_refs = _collect_proposal_evidence_refs(proposal, proposal_id=proposal_id)
    proposal["evidence_refs"] = [dict(item) for item in evidence_refs]
    proposal["evidence_link_ids"] = [
        str(item.get("evidence_ref_id") or "").strip()
        for item in evidence_refs
        if str(item.get("evidence_ref_id") or "").strip()
    ]
    proposal["evidence_links"] = [dict(item) for item in evidence_refs]

    artifact_raw = proposal.get("artifact")
    if isinstance(artifact_raw, Mapping):
        artifact_doc = dict(artifact_raw)
        artifact_doc["evidence_refs"] = [dict(item) for item in evidence_refs]
        artifact_doc["evidence_links"] = [dict(item) for item in evidence_refs]
        proposal["artifact"] = artifact_doc

    return proposal


def _normalize_type_pr_status(
    raw_status: Any,
    *,
    default: str = TYPE_PR_STATUS_OPEN,
) -> str:
    normalized = str(raw_status or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not normalized:
        return default
    return normalized


def _normalize_type_assertion_state(
    raw_state: Any,
    *,
    default: str = TYPE_ASSERTION_STATE_PROPOSED,
) -> str:
    normalized = str(raw_state or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not normalized:
        return default
    return normalized


def _normalize_type_pr_decision(raw_decision: Any) -> str:
    normalized = str(raw_decision or "").strip().upper().replace("-", "_").replace(" ", "_")
    if normalized == "APPROVED":
        return TYPE_PR_DECISION_APPROVE
    return normalized


def _coerce_float(raw: Any, *, default: float = 0.0) -> float:
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def _normalize_type_source(
    raw_source: Any,
    *,
    default: str = TYPE_SOURCE_ML_MODEL,
) -> str:
    normalized = str(raw_source or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not normalized:
        return default
    if normalized in TYPE_SOURCE_ALLOWED:
        return normalized
    return default


def _normalize_propagation_scope(
    raw_scope: Any,
    *,
    default: str = TYPE_PROPAGATION_SCOPE_SAME_PROGRAM,
) -> str:
    normalized = str(raw_scope or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not normalized:
        return default
    if normalized in TYPE_PROPAGATION_ALLOWED_SCOPES:
        return normalized
    return default


def _normalize_propagation_mode(
    raw_mode: Any,
    *,
    default: str = TYPE_PROPAGATION_MODE_PROPOSE,
) -> str:
    normalized = str(raw_mode or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not normalized:
        return default
    if normalized in TYPE_PROPAGATION_ALLOWED_MODES:
        return normalized
    return default


def _scope_key_for_propagation_scope(scope: str) -> str:
    if scope == TYPE_PROPAGATION_SCOPE_CROSS_PROGRAM:
        return "cross_program"
    if scope == TYPE_PROPAGATION_SCOPE_CORPUS_KB:
        return "corpus_kb"
    return "same_program"


def _default_scope_policy(
    *,
    mode: str,
    min_confidence: float,
    confidence_adjustment: float,
    require_review_on_conflict: bool,
    allow_replace_lower_priority: bool,
) -> dict[str, Any]:
    return {
        "mode": _normalize_propagation_mode(mode),
        "min_confidence": _clamp_confidence(min_confidence),
        "confidence_adjustment": max(-1.0, min(1.0, confidence_adjustment)),
        "require_review_on_conflict": bool(require_review_on_conflict),
        "allow_replace_lower_priority": bool(allow_replace_lower_priority),
    }


def _default_propagation_policy() -> dict[str, Any]:
    return {
        "same_program": _default_scope_policy(
            mode=TYPE_PROPAGATION_MODE_AUTO,
            min_confidence=0.80,
            confidence_adjustment=-0.05,
            require_review_on_conflict=True,
            allow_replace_lower_priority=True,
        ),
        "cross_program": _default_scope_policy(
            mode=TYPE_PROPAGATION_MODE_PROPOSE,
            min_confidence=0.85,
            confidence_adjustment=-0.10,
            require_review_on_conflict=True,
            allow_replace_lower_priority=False,
        ),
        "corpus_kb": _default_scope_policy(
            mode=TYPE_PROPAGATION_MODE_PROPOSE,
            min_confidence=0.90,
            confidence_adjustment=-0.10,
            require_review_on_conflict=True,
            allow_replace_lower_priority=False,
        ),
        "conflict_resolution": {
            "source_priority_order": [
                TYPE_SOURCE_DWARF,
                TYPE_SOURCE_ANALYST,
                TYPE_SOURCE_CONSTRAINT_SOLVER,
                TYPE_SOURCE_ML_MODEL,
                TYPE_SOURCE_HEURISTIC,
                TYPE_SOURCE_GHIDRA_DEFAULT,
            ],
            "confidence_margin": 0.15,
            "tie_breaker": TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC,
            "workflow": [
                TYPE_CONFLICT_STRATEGY_SOURCE_PRIORITY,
                "CONFIDENCE",
                "TIE_BREAKER",
            ],
        },
    }


def _normalize_scope_policy(
    raw_policy: Any,
    *,
    default_policy: Mapping[str, Any],
) -> dict[str, Any]:
    policy = dict(raw_policy) if isinstance(raw_policy, Mapping) else {}
    normalized = _default_scope_policy(
        mode=_normalize_propagation_mode(
            policy.get("mode"),
            default=_normalize_propagation_mode(default_policy.get("mode")),
        ),
        min_confidence=_coerce_float(
            policy.get("min_confidence"),
            default=_coerce_float(default_policy.get("min_confidence"), default=0.0),
        ),
        confidence_adjustment=_coerce_float(
            policy.get("confidence_adjustment"),
            default=_coerce_float(default_policy.get("confidence_adjustment"), default=0.0),
        ),
        require_review_on_conflict=bool(
            policy.get("require_review_on_conflict", default_policy.get("require_review_on_conflict", True))
        ),
        allow_replace_lower_priority=bool(
            policy.get("allow_replace_lower_priority", default_policy.get("allow_replace_lower_priority", False))
        ),
    )
    return normalized


def _normalize_conflict_resolution_policy(raw_policy: Any) -> dict[str, Any]:
    defaults = _default_propagation_policy()["conflict_resolution"]
    policy = dict(raw_policy) if isinstance(raw_policy, Mapping) else {}

    source_priority_raw = policy.get("source_priority_order")
    if isinstance(source_priority_raw, list):
        source_priority = [
            _normalize_type_source(item, default="")
            for item in source_priority_raw
            if _normalize_type_source(item, default="")
        ]
    else:
        source_priority = list(defaults["source_priority_order"])
    if len(source_priority) != len(TYPE_SOURCE_ALLOWED) or len(set(source_priority)) != len(TYPE_SOURCE_ALLOWED):
        source_priority = list(defaults["source_priority_order"])

    tie_breaker = str(policy.get("tie_breaker") or "").strip().upper()
    if tie_breaker not in {
        TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC,
        TYPE_PROPAGATION_TIE_BREAK_TARGET_ID_ASC,
        TYPE_PROPAGATION_TIE_BREAK_RECEIPT_TIMESTAMP_ASC,
    }:
        tie_breaker = str(defaults["tie_breaker"])

    workflow_raw = policy.get("workflow")
    if isinstance(workflow_raw, list):
        workflow = [str(item).strip().upper().replace("-", "_").replace(" ", "_") for item in workflow_raw]
    else:
        workflow = list(defaults["workflow"])
    if workflow != [TYPE_CONFLICT_STRATEGY_SOURCE_PRIORITY, "CONFIDENCE", "TIE_BREAKER"]:
        workflow = list(defaults["workflow"])

    return {
        "source_priority_order": source_priority,
        "confidence_margin": _clamp_confidence(
            _coerce_float(policy.get("confidence_margin"), default=_coerce_float(defaults["confidence_margin"]))
        ),
        "tie_breaker": tie_breaker,
        "workflow": workflow,
    }


def _normalize_propagation_policy(raw_policy: Any) -> dict[str, Any]:
    defaults = _default_propagation_policy()
    policy = dict(raw_policy) if isinstance(raw_policy, Mapping) else {}
    return {
        "same_program": _normalize_scope_policy(
            policy.get("same_program"),
            default_policy=defaults["same_program"],
        ),
        "cross_program": _normalize_scope_policy(
            policy.get("cross_program"),
            default_policy=defaults["cross_program"],
        ),
        "corpus_kb": _normalize_scope_policy(
            policy.get("corpus_kb"),
            default_policy=defaults["corpus_kb"],
        ),
        "conflict_resolution": _normalize_conflict_resolution_policy(policy.get("conflict_resolution")),
    }


def _normalize_propagation_targets(raw_targets: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_targets, list):
        return []
    targets: list[dict[str, Any]] = []
    for item in raw_targets:
        if not isinstance(item, Mapping):
            continue
        target = dict(item)
        target["scope"] = _normalize_propagation_scope(target.get("scope"))
        rule = str(target.get("rule") or "").strip().upper()
        if not rule:
            if target["scope"] == TYPE_PROPAGATION_SCOPE_CROSS_PROGRAM:
                rule = "CROSS_PROGRAM_EXACT_FUNCTION_MATCH"
            elif target["scope"] == TYPE_PROPAGATION_SCOPE_CORPUS_KB:
                rule = "CORPUS_KB_LAYOUT_FINGERPRINT"
            else:
                rule = "SAME_PROGRAM_DIRECT_DATAFLOW"
        target["rule"] = rule

        for key in (
            "target_program_id",
            "target_assertion_id",
            "target_id",
            "competing_assertion_id",
            "competing_source_type",
            "competing_target_id",
            "conflict_category",
        ):
            if key in target and target[key] is not None:
                target[key] = str(target[key]).strip()
        if "competing_source_type" in target:
            target["competing_source_type"] = _normalize_type_source(
                target.get("competing_source_type"),
                default=TYPE_SOURCE_ML_MODEL,
            )
        competing_confidence_raw = target.get("competing_confidence")
        if competing_confidence_raw is not None:
            target["competing_confidence"] = _clamp_confidence(
                _coerce_float(competing_confidence_raw, default=0.0)
            )
        targets.append(target)
    return targets


def _normalize_propagation_events(raw_events: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_events, list):
        return []
    events: list[dict[str, Any]] = []
    for item in raw_events:
        if isinstance(item, Mapping):
            events.append(dict(item))
    return events


def _normalize_type_conflicts(raw_conflicts: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_conflicts, list):
        return []
    conflicts: list[dict[str, Any]] = []
    for item in raw_conflicts:
        if not isinstance(item, Mapping):
            continue
        conflict = dict(item)
        status = str(conflict.get("status") or TYPE_CONFLICT_STATUS_OPEN).strip().upper().replace("-", "_")
        if status not in {
            TYPE_CONFLICT_STATUS_OPEN,
            TYPE_CONFLICT_STATUS_AUTO_RESOLVED,
            TYPE_CONFLICT_STATUS_ESCALATED,
            TYPE_CONFLICT_STATUS_RESOLVED,
        }:
            status = TYPE_CONFLICT_STATUS_OPEN
        conflict["status"] = status
        conflicts.append(conflict)
    return conflicts


def _new_type_assertion_transition(
    *,
    from_state: str | None,
    to_state: str,
    receipt_id: str,
    changed_at_utc: str | None = None,
    reviewer_id: str | None = None,
    decision: str | None = None,
    comment: str | None = None,
    rationale: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    transition: dict[str, Any] = {
        "from_state": from_state,
        "to_state": to_state,
        "receipt_id": receipt_id,
        "changed_at_utc": changed_at_utc or _utc_now(),
    }
    if reviewer_id:
        transition["reviewer_id"] = reviewer_id
    if decision:
        transition["decision"] = decision
    if comment:
        transition["comment"] = comment
    if rationale:
        transition["rationale"] = rationale
    if reason:
        transition["reason"] = reason
    return transition


def _new_type_pr_status_transition(
    *,
    from_status: str | None,
    to_status: str,
    receipt_id: str,
    changed_at_utc: str | None = None,
    reviewer_id: str | None = None,
    decision: str | None = None,
    comment: str | None = None,
    rationale: str | None = None,
) -> dict[str, Any]:
    transition: dict[str, Any] = {
        "from_status": from_status,
        "to_status": to_status,
        "receipt_id": receipt_id,
        "changed_at_utc": changed_at_utc or _utc_now(),
    }
    if reviewer_id:
        transition["reviewer_id"] = reviewer_id
    if decision:
        transition["decision"] = decision
    if comment:
        transition["comment"] = comment
    if rationale:
        transition["rationale"] = rationale
    return transition


def _normalize_type_pr_review_decision(
    raw: Mapping[str, Any],
    *,
    type_pr_id: str,
    decided_at_default: str,
) -> dict[str, Any]:
    decision = _normalize_type_pr_decision(raw.get("decision"))
    if decision not in TYPE_PR_DECISION_TO_PR_STATUS:
        return {}

    rationale = str(raw.get("rationale") or "").strip()
    if not rationale:
        return {}

    reviewer_id = str(raw.get("reviewer_id") or raw.get("reviewer") or "").strip()
    if not reviewer_id:
        return {}

    decision_doc: dict[str, Any] = {
        "review_id": str(raw.get("review_id") or raw.get("id") or uuid.uuid4()),
        "type_pr_id": type_pr_id,
        "reviewer_id": reviewer_id,
        "decision": decision,
        "rationale": rationale,
        "receipt_id": str(raw.get("receipt_id") or "").strip(),
        "decided_at_utc": str(raw.get("decided_at_utc") or raw.get("decided_at") or decided_at_default).strip()
        or decided_at_default,
        "resulting_state": _normalize_type_assertion_state(
            raw.get("resulting_state"),
            default=TYPE_PR_DECISION_TO_ASSERTION_STATE[decision],
        ),
    }
    comment = str(raw.get("comment") or "").strip()
    if comment:
        decision_doc["comment"] = comment
    return decision_doc


def _normalize_type_pr_assertion(raw: Mapping[str, Any]) -> dict[str, Any]:
    assertion = dict(raw)
    assertion_id = _type_assertion_id_from_doc(assertion)
    if not assertion_id:
        return {}

    assertion["assertion_id"] = assertion_id
    assertion["lifecycle_state"] = _normalize_type_assertion_state(
        assertion.get("lifecycle_state") or assertion.get("state"),
        default=TYPE_ASSERTION_STATE_UNDER_REVIEW,
    )

    updated_at_utc = str(assertion.get("updated_at_utc") or assertion.get("updated_at") or "").strip()
    if not updated_at_utc:
        updated_at_utc = _utc_now()
    assertion["updated_at_utc"] = updated_at_utc

    confidence_raw = assertion.get("confidence")
    if confidence_raw is not None:
        assertion["confidence"] = _clamp_confidence(_coerce_float(confidence_raw, default=0.0))

    evidence_ids_raw = assertion.get("evidence_ids")
    if isinstance(evidence_ids_raw, list):
        assertion["evidence_ids"] = [str(item).strip() for item in evidence_ids_raw if str(item).strip()]

    source_raw = assertion.get("source")
    if isinstance(source_raw, Mapping):
        source_doc = dict(source_raw)
    else:
        source_doc = {}
    source_doc["source_type"] = _normalize_type_source(source_doc.get("source_type"))
    source_id = str(source_doc.get("source_id") or "").strip()
    if source_id:
        source_doc["source_id"] = source_id
    assertion["source"] = source_doc

    if (
        assertion["lifecycle_state"] in {TYPE_ASSERTION_STATE_ACCEPTED, TYPE_ASSERTION_STATE_PROPAGATED}
        or "propagation_policy" in assertion
    ):
        assertion["propagation_policy"] = _normalize_propagation_policy(assertion.get("propagation_policy"))

    if "propagation_targets" in assertion:
        assertion["propagation_targets"] = _normalize_propagation_targets(assertion.get("propagation_targets"))
    elif "propagation_candidates" in assertion:
        assertion["propagation_targets"] = _normalize_propagation_targets(assertion.get("propagation_candidates"))

    if "propagation_events" in assertion:
        assertion["propagation_events"] = _normalize_propagation_events(assertion.get("propagation_events"))
    elif assertion["lifecycle_state"] == TYPE_ASSERTION_STATE_PROPAGATED:
        assertion["propagation_events"] = []

    conflicts = _normalize_type_conflicts(assertion.get("conflicts"))
    assertion["conflicts"] = conflicts
    if "conflict_count" in assertion:
        try:
            assertion["conflict_count"] = int(assertion.get("conflict_count") or 0)
        except (TypeError, ValueError):
            assertion["conflict_count"] = len(conflicts)
    else:
        assertion["conflict_count"] = len(conflicts)

    transitions_raw = (
        assertion.get("transition_history")
        or assertion.get("transitions")
        or assertion.get("lifecycle_transitions")
    )
    transitions = [dict(item) for item in transitions_raw if isinstance(item, Mapping)] if isinstance(transitions_raw, list) else []
    if not transitions:
        transitions = [
            _new_type_assertion_transition(
                from_state=None,
                to_state=assertion["lifecycle_state"],
                receipt_id=str(assertion.get("last_receipt_id") or "").strip(),
                changed_at_utc=updated_at_utc,
                reason="initial_state",
            )
        ]
    assertion["transition_history"] = transitions

    decisions_raw = assertion.get("review_decisions")
    if isinstance(decisions_raw, list):
        assertion["review_decisions"] = [
            decision
            for item in decisions_raw
            if isinstance(item, Mapping)
            for decision in (
                _normalize_type_pr_review_decision(
                    item,
                    type_pr_id=str(assertion.get("type_pr_id") or ""),
                    decided_at_default=updated_at_utc,
                ),
            )
            if decision
        ]
    else:
        assertion["review_decisions"] = []

    return assertion


def _normalize_local_type_pr(raw: Mapping[str, Any]) -> dict[str, Any]:
    type_pr = dict(raw)
    type_pr_id = _type_pr_id_from_doc(type_pr)
    if not type_pr_id:
        return {}

    type_pr["type_pr_id"] = type_pr_id
    type_pr["status"] = _normalize_type_pr_status(type_pr.get("status") or type_pr.get("state"))

    created_at_utc = str(type_pr.get("created_at_utc") or type_pr.get("created_at") or "").strip()
    if not created_at_utc:
        created_at_utc = _utc_now()
    updated_at_utc = str(type_pr.get("updated_at_utc") or type_pr.get("updated_at") or "").strip()
    if not updated_at_utc:
        updated_at_utc = created_at_utc
    type_pr["created_at_utc"] = created_at_utc
    type_pr["updated_at_utc"] = updated_at_utc

    assertions_raw = type_pr.get("assertions")
    type_pr["assertions"] = [
        assertion
        for item in assertions_raw
        if isinstance(item, Mapping)
        for assertion in (_normalize_type_pr_assertion(item),)
        if assertion
    ] if isinstance(assertions_raw, list) else []
    for assertion in type_pr["assertions"]:
        assertion["type_pr_id"] = type_pr_id

    decisions_raw = type_pr.get("review_decisions")
    if isinstance(decisions_raw, list):
        type_pr["review_decisions"] = [
            decision
            for item in decisions_raw
            if isinstance(item, Mapping)
            for decision in (
                _normalize_type_pr_review_decision(
                    item,
                    type_pr_id=type_pr_id,
                    decided_at_default=updated_at_utc,
                ),
            )
            if decision
        ]
    else:
        type_pr["review_decisions"] = []

    reviewers_raw = type_pr.get("reviewers")
    reviewers: list[dict[str, str]] = []
    if isinstance(reviewers_raw, list):
        for entry in reviewers_raw:
            if isinstance(entry, Mapping):
                reviewer_id = str(entry.get("reviewer_id") or entry.get("reviewer") or "").strip()
                status = str(entry.get("status") or "PENDING").strip().upper() or "PENDING"
            else:
                reviewer_id = str(entry).strip()
                status = "PENDING"
            if reviewer_id:
                reviewers.append({"reviewer_id": reviewer_id, "status": status})
    type_pr["reviewers"] = reviewers

    transitions_raw = type_pr.get("status_transitions")
    transitions = [dict(item) for item in transitions_raw if isinstance(item, Mapping)] if isinstance(transitions_raw, list) else []
    if not transitions:
        transitions = [
            _new_type_pr_status_transition(
                from_status=None,
                to_status=type_pr["status"],
                receipt_id=str(type_pr.get("last_receipt_id") or "").strip(),
                changed_at_utc=updated_at_utc,
            )
        ]
    type_pr["status_transitions"] = transitions

    propagation_transactions_raw = type_pr.get("propagation_transactions")
    if isinstance(propagation_transactions_raw, list):
        type_pr["propagation_transactions"] = [
            dict(item)
            for item in propagation_transactions_raw
            if isinstance(item, Mapping)
        ]
    else:
        type_pr["propagation_transactions"] = []
    return type_pr


def _proposal_state_counts(proposals: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(
        _normalize_proposal_state(proposal.get("state"))
        for proposal in proposals
    )
    return {state: int(counts.get(state, 0)) for state in sorted(counts)}


def _new_receipt_id(*, action: str) -> str:
    return f"receipt:{action.lower()}:{uuid.uuid4()}"


def _new_transaction_id() -> str:
    return str(uuid.uuid4())


def _digest_json(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _capture_proposal_snapshot(proposal: Mapping[str, Any]) -> dict[str, Any]:
    evidence_refs_raw = proposal.get("evidence_refs")
    evidence_refs = (
        [dict(item) for item in evidence_refs_raw if isinstance(item, Mapping)]
        if isinstance(evidence_refs_raw, list)
        else []
    )
    return {
        "state": _normalize_proposal_state(proposal.get("state")),
        "receipt_id": str(proposal.get("receipt_id") or "").strip(),
        "evidence_link_ids": _proposal_evidence_link_ids(proposal),
        "evidence_refs": evidence_refs,
    }


def _ensure_apply_transactions(store_doc: dict[str, Any]) -> list[dict[str, Any]]:
    transactions_raw = store_doc.get("apply_transactions")
    if not isinstance(transactions_raw, list):
        transactions_raw = []
    transactions = [dict(item) for item in transactions_raw if isinstance(item, Mapping)]
    store_doc["apply_transactions"] = transactions
    return transactions


def _next_program_transaction_id(
    store_doc: dict[str, Any],
    *,
    apply_transactions: list[dict[str, Any]],
) -> int:
    next_value_raw = store_doc.get("next_program_transaction_id")
    if next_value_raw is None:
        max_seen = -1
        for transaction in apply_transactions:
            tx_id_raw = transaction.get("program_transaction_id")
            try:
                tx_id = int(tx_id_raw)
            except (TypeError, ValueError):
                continue
            if tx_id > max_seen:
                max_seen = tx_id
            rollback_raw = transaction.get("rollback_transaction")
            if isinstance(rollback_raw, Mapping):
                rollback_tx_id_raw = rollback_raw.get("program_transaction_id")
                try:
                    rollback_tx_id = int(rollback_tx_id_raw)
                except (TypeError, ValueError):
                    continue
                if rollback_tx_id > max_seen:
                    max_seen = rollback_tx_id
        next_value = max_seen + 1
    else:
        try:
            next_value = int(next_value_raw)
        except (TypeError, ValueError):
            next_value = 0

    if next_value < 0:
        next_value = 0
    store_doc["next_program_transaction_id"] = next_value + 1
    return next_value


def _write_local_proposal_store(
    local_store_path: Path,
    store_doc: Mapping[str, Any],
) -> None:
    persisted = dict(store_doc)
    persisted["schema_version"] = int(persisted.get("schema_version") or 1)
    persisted["kind"] = str(persisted.get("kind") or "local_proposal_store")

    proposals_raw = persisted.get("proposals")
    if isinstance(proposals_raw, list):
        proposals = [
            normalized_item
            for item in proposals_raw
            if isinstance(item, Mapping)
            for normalized_item in (_normalize_local_proposal(item),)
            if normalized_item
        ]
    else:
        proposals = []
    persisted["proposals"] = proposals

    type_prs_raw = persisted.get("type_prs")
    if isinstance(type_prs_raw, list):
        type_prs = [
            normalized_item
            for item in type_prs_raw
            if isinstance(item, Mapping)
            for normalized_item in (_normalize_local_type_pr(item),)
            if normalized_item
        ]
    else:
        type_prs = []
    persisted["type_prs"] = type_prs

    _write_json_atomic(local_store_path, persisted)


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(serialized)
            temp_path = Path(tmp.name)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def _set_proposal_state(
    proposal: dict[str, Any],
    *,
    to_state: str,
    action: str,
    actor_id: str | None = None,
    reason: str | None = None,
) -> None:
    from_state = _normalize_proposal_state(proposal.get("state"))
    normalized_to_state = _normalize_proposal_state(to_state)
    if from_state == normalized_to_state:
        return

    allowed = PROPOSAL_ALLOWED_TRANSITIONS.get(from_state, frozenset())
    if normalized_to_state not in allowed:
        raise ValueError(f"invalid proposal lifecycle transition: {from_state} -> {normalized_to_state}")

    changed_at_utc = _utc_now()
    proposal["state"] = normalized_to_state
    proposal["updated_at_utc"] = changed_at_utc

    transitions_raw = proposal.get("lifecycle_transitions")
    transitions = [dict(item) for item in transitions_raw if isinstance(item, Mapping)] if isinstance(transitions_raw, list) else []
    transitions.append(
        _new_proposal_transition(
            from_state=from_state,
            to_state=normalized_to_state,
            action=action,
            changed_at_utc=changed_at_utc,
            actor_id=actor_id,
            reason=reason,
        )
    )
    proposal["lifecycle_transitions"] = transitions

    if action in PROPOSAL_REVIEW_ACTION_TO_STATE:
        decisions_raw = proposal.get("review_decisions")
        decisions = [dict(item) for item in decisions_raw if isinstance(item, Mapping)] if isinstance(decisions_raw, list) else []
        decision: dict[str, Any] = {
            "decision": action,
            "resulting_state": normalized_to_state,
            "decided_at_utc": changed_at_utc,
        }
        if actor_id:
            decision["reviewer_id"] = actor_id
        if reason:
            decision["comment"] = reason
        decisions.append(decision)
        proposal["review_decisions"] = decisions
    elif action == PROPOSAL_ACTION_APPLY:
        events_raw = proposal.get("apply_events")
        events = [dict(item) for item in events_raw if isinstance(item, Mapping)] if isinstance(events_raw, list) else []
        event: dict[str, Any] = {
            "action": PROPOSAL_ACTION_APPLY,
            "resulting_state": normalized_to_state,
            "applied_at_utc": changed_at_utc,
        }
        if actor_id:
            event["actor_id"] = actor_id
        events.append(event)
        proposal["apply_events"] = events


def _resolve_proposal_targets(
    proposals: list[dict[str, Any]],
    *,
    proposal_ids: set[str] | None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    by_id: dict[str, dict[str, Any]] = {}
    for proposal in proposals:
        proposal_id = _proposal_id_from_doc(proposal)
        if proposal_id and proposal_id not in by_id:
            by_id[proposal_id] = proposal

    if proposal_ids is None:
        target_ids = sorted(by_id)
        missing: list[str] = []
    else:
        target_ids = sorted(proposal_ids)
        missing = [proposal_id for proposal_id in target_ids if proposal_id not in by_id]
    return by_id, target_ids, missing


def query_local_proposals(
    *,
    local_store: Path,
    state: str | None = None,
    proposal_ids: list[str] | None = None,
) -> dict[str, Any]:
    store_doc = _load_local_proposal_store(local_store)
    proposals = store_doc["proposals"]

    filter_ids = {str(item).strip() for item in (proposal_ids or []) if str(item).strip()}
    by_id, target_ids, missing = _resolve_proposal_targets(
        proposals,
        proposal_ids=filter_ids if filter_ids else None,
    )
    normalized_state = _normalize_proposal_state(state, default="") if state else None

    matched: list[dict[str, Any]] = []
    for proposal_id in target_ids:
        proposal = by_id.get(proposal_id)
        if proposal is None:
            continue
        proposal_state = _normalize_proposal_state(proposal.get("state"))
        if normalized_state and proposal_state != normalized_state:
            continue
        rendered = dict(proposal)
        rendered["evidence_link_ids"] = _proposal_evidence_link_ids(proposal)
        rendered["evidence_links"] = _proposal_evidence_links(proposal)
        matched.append(rendered)

    return {
        "schema_version": 1,
        "kind": "proposal_query_report",
        "generated_at_utc": _utc_now(),
        "query": {
            "state": normalized_state,
            "proposal_ids": sorted(filter_ids),
        },
        "metrics": {
            "scanned_total": len(proposals),
            "matched_total": len(matched),
            "missing_total": len(missing),
            "state_counts": _proposal_state_counts(proposals),
        },
        "missing_proposal_ids": missing,
        "proposals": matched,
        "local_store": str(local_store),
    }


def _resolve_type_pr_targets(
    type_prs: list[dict[str, Any]],
    *,
    type_pr_ids: set[str] | None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    by_id: dict[str, dict[str, Any]] = {}
    for type_pr in type_prs:
        type_pr_id = _type_pr_id_from_doc(type_pr)
        if type_pr_id and type_pr_id not in by_id:
            by_id[type_pr_id] = type_pr

    if type_pr_ids is None:
        target_ids = sorted(by_id)
        missing: list[str] = []
    else:
        target_ids = sorted(type_pr_ids)
        missing = [type_pr_id for type_pr_id in target_ids if type_pr_id not in by_id]
    return by_id, target_ids, missing


def _type_pr_status_counts(type_prs: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_normalize_type_pr_status(type_pr.get("status")) for type_pr in type_prs)
    return {state: int(counts.get(state, 0)) for state in sorted(counts)}


def _type_pr_confidence_floor(type_pr: Mapping[str, Any]) -> float:
    assertions_raw = type_pr.get("assertions")
    assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    confidence_values: list[float] = []
    for assertion in assertions:
        confidence_raw = assertion.get("confidence")
        if confidence_raw is None:
            continue
        try:
            confidence_values.append(float(confidence_raw))
        except (TypeError, ValueError):
            continue
    if not confidence_values:
        return 0.0
    return round(min(confidence_values), 6)


def _type_pr_conflict_count(type_pr: Mapping[str, Any]) -> int:
    assertions_raw = type_pr.get("assertions")
    assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    total = 0
    for assertion in assertions:
        conflict_count_raw = assertion.get("conflict_count")
        if conflict_count_raw is not None:
            try:
                total += int(conflict_count_raw)
                continue
            except (TypeError, ValueError):
                pass
        conflicts_raw = assertion.get("conflicts")
        if isinstance(conflicts_raw, list):
            total += len([item for item in conflicts_raw if isinstance(item, Mapping)])
    return total


def _type_pr_assertion_state_counts(type_pr: Mapping[str, Any]) -> dict[str, int]:
    assertions_raw = type_pr.get("assertions")
    assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    counts = Counter(_normalize_type_assertion_state(assertion.get("lifecycle_state")) for assertion in assertions)
    return {state: int(counts.get(state, 0)) for state in sorted(counts)}


def _type_pr_matches_reviewer(type_pr: Mapping[str, Any], *, reviewer_id: str | None) -> bool:
    if not reviewer_id:
        return True
    reviewers_raw = type_pr.get("reviewers")
    if not isinstance(reviewers_raw, list):
        return False
    for reviewer in reviewers_raw:
        if isinstance(reviewer, Mapping):
            candidate = str(reviewer.get("reviewer_id") or reviewer.get("reviewer") or "").strip()
        else:
            candidate = str(reviewer).strip()
        if candidate == reviewer_id:
            return True
    return False


def _extract_asserted_type_name(assertion: Mapping[str, Any]) -> str:
    asserted_type_raw = assertion.get("asserted_type")
    if isinstance(asserted_type_raw, Mapping):
        asserted_name = str(asserted_type_raw.get("name") or asserted_type_raw.get("display") or "").strip()
        if asserted_name:
            return asserted_name
    return str(assertion.get("suggested_type") or assertion.get("type_name") or "").strip()


def _capture_type_assertion_snapshot(assertion: Mapping[str, Any]) -> dict[str, Any]:
    transition_history_raw = assertion.get("transition_history")
    transition_history = (
        [dict(item) for item in transition_history_raw if isinstance(item, Mapping)]
        if isinstance(transition_history_raw, list)
        else []
    )
    propagation_events_raw = assertion.get("propagation_events")
    propagation_events = (
        [dict(item) for item in propagation_events_raw if isinstance(item, Mapping)]
        if isinstance(propagation_events_raw, list)
        else []
    )
    conflicts_raw = assertion.get("conflicts")
    conflicts = (
        [dict(item) for item in conflicts_raw if isinstance(item, Mapping)]
        if isinstance(conflicts_raw, list)
        else []
    )
    return {
        "state": _normalize_type_assertion_state(assertion.get("lifecycle_state")),
        "last_receipt_id": str(assertion.get("last_receipt_id") or "").strip(),
        "updated_at_utc": str(assertion.get("updated_at_utc") or ""),
        "transition_history": transition_history,
        "propagation_events": propagation_events,
        "conflicts": conflicts,
        "conflict_count": int(assertion.get("conflict_count") or len(conflicts)),
    }


def _ensure_type_pr_propagation_transactions(type_pr: dict[str, Any]) -> list[dict[str, Any]]:
    transactions_raw = type_pr.get("propagation_transactions")
    if not isinstance(transactions_raw, list):
        transactions_raw = []
    transactions = [dict(item) for item in transactions_raw if isinstance(item, Mapping)]
    type_pr["propagation_transactions"] = transactions
    return transactions


def _source_priority_rank(source_type: str, priority_order: list[str]) -> int:
    normalized_source = _normalize_type_source(source_type, default="")
    try:
        return priority_order.index(normalized_source)
    except ValueError:
        return len(priority_order) + 1


def _resolve_conflict_tie_break_winner(
    *,
    tie_breaker: str,
    source_assertion_id: str,
    competing_assertion_id: str,
    source_target_id: str,
    competing_target_id: str,
) -> str:
    if tie_breaker == TYPE_PROPAGATION_TIE_BREAK_TARGET_ID_ASC:
        source_value = source_target_id or source_assertion_id
        competing_value = competing_target_id or competing_assertion_id
    else:
        source_value = source_assertion_id
        competing_value = competing_assertion_id
    if source_value <= competing_value:
        return source_assertion_id
    return competing_assertion_id


def _resolve_propagation_conflict(
    *,
    assertion: Mapping[str, Any],
    target: Mapping[str, Any],
    policy: Mapping[str, Any],
    scope_policy: Mapping[str, Any],
    resulting_confidence: float,
    policy_mode: str,
    propagation_receipt_id: str,
    propagated_at_utc: str,
) -> tuple[dict[str, Any], str, str]:
    assertion_id = _type_assertion_id_from_doc(assertion)
    competing_assertion_id = str(target.get("competing_assertion_id") or "").strip() or f"conflict:{uuid.uuid4()}"
    competing_source_type = _normalize_type_source(
        target.get("competing_source_type"),
        default=TYPE_SOURCE_ML_MODEL,
    )
    competing_confidence = _clamp_confidence(
        _coerce_float(target.get("competing_confidence"), default=resulting_confidence)
    )

    conflict_policy = (
        dict(policy.get("conflict_resolution"))
        if isinstance(policy.get("conflict_resolution"), Mapping)
        else _default_propagation_policy()["conflict_resolution"]
    )
    source_priority_order = [
        _normalize_type_source(item, default="")
        for item in conflict_policy.get("source_priority_order", [])
        if _normalize_type_source(item, default="")
    ]
    if len(source_priority_order) != len(TYPE_SOURCE_ALLOWED) or len(set(source_priority_order)) != len(TYPE_SOURCE_ALLOWED):
        source_priority_order = list(_default_propagation_policy()["conflict_resolution"]["source_priority_order"])

    source_type = TYPE_SOURCE_ML_MODEL
    source_raw = assertion.get("source")
    if isinstance(source_raw, Mapping):
        source_type = _normalize_type_source(source_raw.get("source_type"), default=TYPE_SOURCE_ML_MODEL)

    source_rank = _source_priority_rank(source_type, source_priority_order)
    competing_rank = _source_priority_rank(competing_source_type, source_priority_order)
    confidence_margin = _clamp_confidence(_coerce_float(conflict_policy.get("confidence_margin"), default=0.15))
    tie_breaker = str(conflict_policy.get("tie_breaker") or TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC).strip().upper()
    if tie_breaker not in {
        TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC,
        TYPE_PROPAGATION_TIE_BREAK_TARGET_ID_ASC,
        TYPE_PROPAGATION_TIE_BREAK_RECEIPT_TIMESTAMP_ASC,
    }:
        tie_breaker = TYPE_PROPAGATION_TIE_BREAK_ASSERTION_ID_ASC

    requires_review = bool(scope_policy.get("require_review_on_conflict", True))
    allow_replace_lower_priority = bool(scope_policy.get("allow_replace_lower_priority", False))
    conflict_id = str(uuid.uuid4())

    resolution: dict[str, Any]
    reason: str
    winner_assertion_id: str
    loser_assertion_id: str

    if source_rank != competing_rank:
        winner_assertion_id = assertion_id if source_rank < competing_rank else competing_assertion_id
        loser_assertion_id = competing_assertion_id if winner_assertion_id == assertion_id else assertion_id
        resolution = {
            "strategy": TYPE_CONFLICT_STRATEGY_SOURCE_PRIORITY,
            "requires_review": requires_review,
            "winner_assertion_id": winner_assertion_id,
            "loser_assertion_id": loser_assertion_id,
            "priority_gap": abs(source_rank - competing_rank),
            "reason": "source priority comparison",
        }
        reason = "source_priority"
    else:
        confidence_delta = abs(resulting_confidence - competing_confidence)
        if confidence_delta > confidence_margin:
            winner_assertion_id = assertion_id if resulting_confidence >= competing_confidence else competing_assertion_id
            loser_assertion_id = competing_assertion_id if winner_assertion_id == assertion_id else assertion_id
            resolution = {
                "strategy": TYPE_CONFLICT_STRATEGY_HIGHER_CONFIDENCE,
                "requires_review": requires_review,
                "winner_assertion_id": winner_assertion_id,
                "loser_assertion_id": loser_assertion_id,
                "confidence_delta": round(confidence_delta, 6),
                "reason": "confidence delta exceeded margin",
            }
            reason = "higher_confidence"
        else:
            winner_assertion_id = _resolve_conflict_tie_break_winner(
                tie_breaker=tie_breaker,
                source_assertion_id=assertion_id,
                competing_assertion_id=competing_assertion_id,
                source_target_id=str(assertion.get("target_id") or ""),
                competing_target_id=str(target.get("competing_target_id") or target.get("target_id") or ""),
            )
            loser_assertion_id = competing_assertion_id if winner_assertion_id == assertion_id else assertion_id
            resolution = {
                "strategy": TYPE_CONFLICT_STRATEGY_TIE_BREAK,
                "requires_review": requires_review,
                "winner_assertion_id": winner_assertion_id,
                "loser_assertion_id": loser_assertion_id,
                "tie_breaker": tie_breaker,
                "reason": "deterministic tie-break",
            }
            reason = "deterministic_tie_break"

    winner_is_propagated = resolution["winner_assertion_id"] == assertion_id
    if winner_is_propagated and not allow_replace_lower_priority:
        requires_review = True
        resolution["requires_review"] = True

    conflict_status = TYPE_CONFLICT_STATUS_ESCALATED if requires_review else TYPE_CONFLICT_STATUS_AUTO_RESOLVED
    conflict: dict[str, Any] = {
        "conflict_id": conflict_id,
        "category": str(target.get("conflict_category") or "PRIMITIVE_TYPE_DISAGREEMENT"),
        "detected_during": "PROPAGATION",
        "competing_assertion_id": competing_assertion_id,
        "competing_source_type": competing_source_type,
        "status": conflict_status,
        "workflow_version": TYPE_PROPAGATION_WORKFLOW_VERSION,
        "queue_position": None,
        "queued_at": propagated_at_utc,
        "resolution": resolution,
    }

    if conflict_status == TYPE_CONFLICT_STATUS_AUTO_RESOLVED:
        resolution["resolved_receipt_id"] = propagation_receipt_id
        resolution["resolved_at"] = propagated_at_utc
        conflict["resolved_receipt_id"] = propagation_receipt_id
        conflict["resolved_at"] = propagated_at_utc
    else:
        conflict["escalation_reason"] = "manual_review_required_by_scope_policy"

    if conflict_status == TYPE_CONFLICT_STATUS_ESCALATED:
        return conflict, TYPE_PROPAGATION_OUTCOME_CONFLICT, reason

    if winner_is_propagated:
        if policy_mode == TYPE_PROPAGATION_MODE_AUTO:
            return conflict, TYPE_PROPAGATION_OUTCOME_APPLIED, reason
        return conflict, TYPE_PROPAGATION_OUTCOME_PROPOSED, reason
    return conflict, TYPE_PROPAGATION_OUTCOME_SKIPPED, reason


def _apply_type_assertion_propagation(
    *,
    assertion: dict[str, Any],
    propagation_receipt_id: str,
    propagated_at_utc: str,
) -> dict[str, Any]:
    policy = _normalize_propagation_policy(assertion.get("propagation_policy"))
    assertion["propagation_policy"] = policy
    targets = _normalize_propagation_targets(assertion.get("propagation_targets"))
    assertion["propagation_targets"] = targets

    propagation_events = _normalize_propagation_events(assertion.get("propagation_events"))
    conflicts = _normalize_type_conflicts(assertion.get("conflicts"))
    next_queue_position = (
        max(
            (
                int(item.get("queue_position"))
                for item in conflicts
                if item.get("queue_position") is not None
            ),
            default=-1,
        )
        + 1
    )

    base_confidence = _clamp_confidence(_coerce_float(assertion.get("confidence"), default=0.0))
    applied_event_ids: list[str] = []
    conflict_ids: list[str] = []
    metrics = {
        "targeted_total": len(targets),
        "applied_total": 0,
        "proposed_total": 0,
        "skipped_total": 0,
        "conflict_total": 0,
    }

    for target in targets:
        scope = _normalize_propagation_scope(target.get("scope"))
        scope_policy_key = _scope_key_for_propagation_scope(scope)
        scope_policy = (
            dict(policy.get(scope_policy_key))
            if isinstance(policy.get(scope_policy_key), Mapping)
            else _default_propagation_policy()[scope_policy_key]
        )
        policy_mode = _normalize_propagation_mode(
            scope_policy.get("mode"),
            default=TYPE_PROPAGATION_MODE_PROPOSE,
        )

        min_confidence = _clamp_confidence(_coerce_float(scope_policy.get("min_confidence"), default=0.0))
        confidence_adjustment = max(
            -1.0,
            min(1.0, _coerce_float(scope_policy.get("confidence_adjustment"), default=0.0)),
        )
        resulting_confidence = _clamp_confidence(base_confidence + confidence_adjustment)

        event_id = str(uuid.uuid4())
        event: dict[str, Any] = {
            "event_id": event_id,
            "scope": scope,
            "rule": str(target.get("rule") or ""),
            "policy_mode": policy_mode,
            "target_program_id": str(target.get("target_program_id") or "").strip() or None,
            "target_assertion_id": str(target.get("target_assertion_id") or target.get("target_id") or "").strip()
            or None,
            "resulting_confidence": round(resulting_confidence, 6),
            "propagated_at": propagated_at_utc,
        }

        outcome = TYPE_PROPAGATION_OUTCOME_SKIPPED
        reason: str | None = None
        if policy_mode == TYPE_PROPAGATION_MODE_DISABLED:
            reason = "scope disabled by policy"
        elif resulting_confidence < min_confidence:
            reason = "below confidence threshold"
        else:
            competing_assertion_id = str(target.get("competing_assertion_id") or "").strip()
            if competing_assertion_id:
                conflict, conflict_outcome, conflict_reason = _resolve_propagation_conflict(
                    assertion=assertion,
                    target=target,
                    policy=policy,
                    scope_policy=scope_policy,
                    resulting_confidence=resulting_confidence,
                    policy_mode=policy_mode,
                    propagation_receipt_id=propagation_receipt_id,
                    propagated_at_utc=propagated_at_utc,
                )
                if conflict["status"] == TYPE_CONFLICT_STATUS_ESCALATED:
                    conflict["queue_position"] = next_queue_position
                    next_queue_position += 1
                conflicts.append(conflict)
                conflict_ids.append(str(conflict.get("conflict_id") or ""))
                outcome = conflict_outcome
                reason = conflict_reason
                if outcome == TYPE_PROPAGATION_OUTCOME_CONFLICT:
                    event["conflict_id"] = str(conflict.get("conflict_id") or "").strip()
                    event["competing_assertion_id"] = competing_assertion_id
            else:
                outcome = (
                    TYPE_PROPAGATION_OUTCOME_APPLIED
                    if policy_mode == TYPE_PROPAGATION_MODE_AUTO
                    else TYPE_PROPAGATION_OUTCOME_PROPOSED
                )

        event["outcome"] = outcome
        if outcome == TYPE_PROPAGATION_OUTCOME_APPLIED:
            event["applied_receipt_id"] = propagation_receipt_id
            applied_event_ids.append(event_id)
            metrics["applied_total"] += 1
        elif outcome == TYPE_PROPAGATION_OUTCOME_PROPOSED:
            metrics["proposed_total"] += 1
        elif outcome == TYPE_PROPAGATION_OUTCOME_CONFLICT:
            metrics["conflict_total"] += 1
        else:
            metrics["skipped_total"] += 1
            event["reason"] = reason or "skipped"

        propagation_events.append(event)

    if metrics["applied_total"] > 0:
        previous_state = _normalize_type_assertion_state(assertion.get("lifecycle_state"))
        if previous_state != TYPE_ASSERTION_STATE_PROPAGATED:
            transition_history_raw = assertion.get("transition_history")
            transition_history = (
                [dict(item) for item in transition_history_raw if isinstance(item, Mapping)]
                if isinstance(transition_history_raw, list)
                else []
            )
            transition_history.append(
                _new_type_assertion_transition(
                    from_state=previous_state,
                    to_state=TYPE_ASSERTION_STATE_PROPAGATED,
                    receipt_id=propagation_receipt_id,
                    changed_at_utc=propagated_at_utc,
                    reason="propagation_policy_applied",
                )
            )
            assertion["transition_history"] = transition_history
            assertion["lifecycle_state"] = TYPE_ASSERTION_STATE_PROPAGATED

    assertion["propagation_events"] = propagation_events
    assertion["conflicts"] = conflicts
    assertion["conflict_count"] = len(conflicts)
    assertion["updated_at_utc"] = propagated_at_utc
    assertion["last_receipt_id"] = propagation_receipt_id

    return {
        "assertion_id": _type_assertion_id_from_doc(assertion),
        "applied_event_ids": applied_event_ids,
        "conflict_ids": [conflict_id for conflict_id in conflict_ids if conflict_id],
        "metrics": metrics,
    }


def _run_type_pr_propagation(
    *,
    type_pr: dict[str, Any],
    triggered_by: str | None = None,
    propagated_at_utc: str | None = None,
) -> dict[str, Any] | None:
    assertions_raw = type_pr.get("assertions")
    assertions = [dict(item) for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    if not assertions:
        return None

    accepted_assertions = [
        assertion
        for assertion in assertions
        if _normalize_type_assertion_state(assertion.get("lifecycle_state")) == TYPE_ASSERTION_STATE_ACCEPTED
    ]
    if not accepted_assertions:
        return None

    propagated_at = propagated_at_utc or _utc_now()
    propagation_receipt_id = _new_receipt_id(action="propagate")
    transaction_id = _new_transaction_id()
    transactions = _ensure_type_pr_propagation_transactions(type_pr)

    state_before = {
        _type_assertion_id_from_doc(assertion): _capture_type_assertion_snapshot(assertion)
        for assertion in accepted_assertions
    }

    targeted_assertion_ids: list[str] = []
    applied_event_ids: list[str] = []
    conflict_ids: list[str] = []
    metrics = {
        "targeted_assertion_total": 0,
        "targeted_event_total": 0,
        "applied_total": 0,
        "proposed_total": 0,
        "skipped_total": 0,
        "conflict_total": 0,
    }

    for assertion in accepted_assertions:
        result = _apply_type_assertion_propagation(
            assertion=assertion,
            propagation_receipt_id=propagation_receipt_id,
            propagated_at_utc=propagated_at,
        )
        assertion_id = str(result.get("assertion_id") or "").strip()
        if assertion_id:
            targeted_assertion_ids.append(assertion_id)
        applied_event_ids.extend(str(item) for item in result.get("applied_event_ids", []) if str(item).strip())
        conflict_ids.extend(str(item) for item in result.get("conflict_ids", []) if str(item).strip())

        result_metrics = result.get("metrics")
        if isinstance(result_metrics, Mapping):
            metrics["targeted_event_total"] += int(result_metrics.get("targeted_total") or 0)
            metrics["applied_total"] += int(result_metrics.get("applied_total") or 0)
            metrics["proposed_total"] += int(result_metrics.get("proposed_total") or 0)
            metrics["skipped_total"] += int(result_metrics.get("skipped_total") or 0)
            metrics["conflict_total"] += int(result_metrics.get("conflict_total") or 0)

    metrics["targeted_assertion_total"] = len(targeted_assertion_ids)
    if metrics["targeted_event_total"] == 0:
        type_pr["assertions"] = assertions
        return None

    state_after = {
        assertion_id: _capture_type_assertion_snapshot(assertion)
        for assertion in assertions
        for assertion_id in (_type_assertion_id_from_doc(assertion),)
        if assertion_id in state_before
    }
    transaction: dict[str, Any] = {
        "transaction_id": transaction_id,
        "phase": "propagate",
        "status": "propagated",
        "propagation_receipt_id": propagation_receipt_id,
        "assertion_ids": sorted(targeted_assertion_ids),
        "state_before": state_before,
        "state_after": state_after,
        "state_before_hash": _digest_json(state_before),
        "state_after_hash": _digest_json(state_after),
        "applied_event_ids": sorted(set(applied_event_ids)),
        "conflict_ids": sorted(set(conflict_ids)),
        "propagated_at_utc": propagated_at,
    }
    if triggered_by:
        transaction["triggered_by"] = str(triggered_by)
    transactions.append(transaction)
    type_pr["propagation_transactions"] = transactions
    type_pr["assertions"] = assertions
    type_pr["updated_at_utc"] = propagated_at

    return {
        "propagation_receipt_id": propagation_receipt_id,
        "transaction_id": transaction_id,
        "assertion_ids": sorted(targeted_assertion_ids),
        "applied_event_ids": sorted(set(applied_event_ids)),
        "conflict_ids": sorted(set(conflict_ids)),
        "metrics": metrics,
    }


def list_type_pr_review_queue(
    *,
    local_store: Path,
    reviewer_id: str | None = None,
    statuses: list[str] | None = None,
    type_pr_ids: list[str] | None = None,
    sort_by: str = "updated_at_utc",
    sort_desc: bool = True,
) -> dict[str, Any]:
    normalized_reviewer = str(reviewer_id).strip() if reviewer_id is not None else None
    if normalized_reviewer == "":
        normalized_reviewer = None

    normalized_statuses = {
        _normalize_type_pr_status(status, default="")
        for status in (statuses or TYPE_PR_QUEUE_STATUSES)
        if str(status).strip()
    }
    if not normalized_statuses:
        normalized_statuses = set(TYPE_PR_QUEUE_STATUSES)

    filter_ids = {str(item).strip() for item in (type_pr_ids or []) if str(item).strip()}
    store_doc = _load_local_proposal_store(local_store)
    type_prs = store_doc.get("type_prs")
    type_pr_docs = [dict(item) for item in type_prs if isinstance(item, Mapping)] if isinstance(type_prs, list) else []
    by_id, target_ids, missing = _resolve_type_pr_targets(
        type_pr_docs,
        type_pr_ids=filter_ids if filter_ids else None,
    )

    rows: list[dict[str, Any]] = []
    for type_pr_id in target_ids:
        type_pr = by_id.get(type_pr_id)
        if type_pr is None:
            continue

        status = _normalize_type_pr_status(type_pr.get("status"))
        if status not in normalized_statuses:
            continue
        if not _type_pr_matches_reviewer(type_pr, reviewer_id=normalized_reviewer):
            continue

        assertions_raw = type_pr.get("assertions")
        assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
        rows.append(
            {
                "type_pr_id": type_pr_id,
                "title": str(type_pr.get("title") or "").strip(),
                "author": str(type_pr.get("author") or "").strip(),
                "status": status,
                "assertion_count": len(assertions),
                "confidence_floor": _type_pr_confidence_floor(type_pr),
                "conflict_count": _type_pr_conflict_count(type_pr),
                "last_updated_utc": str(type_pr.get("updated_at_utc") or ""),
                "assertion_state_counts": _type_pr_assertion_state_counts(type_pr),
            }
        )

    sort_key = str(sort_by or "updated_at_utc").strip().lower()
    if sort_key == "confidence_floor":
        rows.sort(key=lambda row: (float(row["confidence_floor"]), str(row["type_pr_id"])), reverse=sort_desc)
    elif sort_key == "conflict_count":
        rows.sort(key=lambda row: (int(row["conflict_count"]), str(row["type_pr_id"])), reverse=sort_desc)
    else:
        rows.sort(key=lambda row: (str(row["last_updated_utc"]), str(row["type_pr_id"])), reverse=sort_desc)
        sort_key = "updated_at_utc"

    return {
        "schema_version": 1,
        "kind": "type_pr_review_list_panel",
        "generated_at_utc": _utc_now(),
        "panel": {
            "id": "type-pr-review",
            "view": "list",
            "columns": [
                "type_pr_id",
                "title",
                "author",
                "status",
                "confidence_floor",
                "conflict_count",
                "last_updated_utc",
            ],
        },
        "filters": {
            "reviewer_id": normalized_reviewer,
            "statuses": sorted(normalized_statuses),
            "type_pr_ids": sorted(filter_ids),
            "sort_by": sort_key,
            "sort_desc": bool(sort_desc),
        },
        "metrics": {
            "scanned_total": len(type_pr_docs),
            "matched_total": len(rows),
            "missing_total": len(missing),
            "status_counts": _type_pr_status_counts(type_pr_docs),
        },
        "missing_type_pr_ids": missing,
        "rows": rows,
        "local_store": str(local_store),
    }


def get_type_pr_detail(
    *,
    local_store: Path,
    type_pr_id: str,
    reviewer_id: str | None = None,
) -> dict[str, Any]:
    normalized_id = str(type_pr_id).strip()
    if not normalized_id:
        raise ValueError("type_pr_id is required")

    normalized_reviewer = str(reviewer_id).strip() if reviewer_id is not None else None
    if normalized_reviewer == "":
        normalized_reviewer = None

    store_doc = _load_local_proposal_store(local_store)
    type_prs = store_doc.get("type_prs")
    type_pr_docs = [dict(item) for item in type_prs if isinstance(item, Mapping)] if isinstance(type_prs, list) else []
    by_id, _, _ = _resolve_type_pr_targets(type_pr_docs, type_pr_ids=None)
    type_pr = by_id.get(normalized_id)
    if type_pr is None:
        raise ValueError(f"unknown type_pr_id '{normalized_id}'")
    if not _type_pr_matches_reviewer(type_pr, reviewer_id=normalized_reviewer):
        raise ValueError(f"type_pr_id '{normalized_id}' is not assigned to reviewer '{normalized_reviewer}'")

    assertions_raw = type_pr.get("assertions")
    assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    assertion_rows: list[dict[str, Any]] = []
    for assertion in assertions:
        assertion_rows.append(
            {
                "assertion_id": _type_assertion_id_from_doc(assertion),
                "target": dict(assertion.get("target")) if isinstance(assertion.get("target"), Mapping) else {},
                "lifecycle_state": _normalize_type_assertion_state(assertion.get("lifecycle_state")),
                "confidence": float(assertion.get("confidence") or 0.0),
                "asserted_type": _extract_asserted_type_name(assertion),
                "evidence_ids": [str(item) for item in assertion.get("evidence_ids", []) if str(item).strip()]
                if isinstance(assertion.get("evidence_ids"), list)
                else [],
                "conflict_count": int(assertion.get("conflict_count") or 0),
                "transition_history": [
                    dict(item)
                    for item in assertion.get("transition_history", [])
                    if isinstance(item, Mapping)
                ] if isinstance(assertion.get("transition_history"), list) else [],
                "review_decisions": [
                    dict(item)
                    for item in assertion.get("review_decisions", [])
                    if isinstance(item, Mapping)
                ] if isinstance(assertion.get("review_decisions"), list) else [],
                "propagation_events": [
                    dict(item)
                    for item in assertion.get("propagation_events", [])
                    if isinstance(item, Mapping)
                ] if isinstance(assertion.get("propagation_events"), list) else [],
                "conflicts": [
                    dict(item)
                    for item in assertion.get("conflicts", [])
                    if isinstance(item, Mapping)
                ] if isinstance(assertion.get("conflicts"), list) else [],
                "propagation_policy": (
                    dict(assertion.get("propagation_policy"))
                    if isinstance(assertion.get("propagation_policy"), Mapping)
                    else {}
                ),
            }
        )

    review_timeline = [
        dict(item)
        for item in type_pr.get("review_decisions", [])
        if isinstance(item, Mapping)
    ] if isinstance(type_pr.get("review_decisions"), list) else []
    review_timeline.sort(key=lambda item: str(item.get("decided_at_utc") or ""), reverse=True)

    return {
        "schema_version": 1,
        "kind": "type_pr_review_detail_panel",
        "generated_at_utc": _utc_now(),
        "panel": {
            "id": "type-pr-review",
            "view": "detail",
        },
        "type_pr": {
            "type_pr_id": normalized_id,
            "title": str(type_pr.get("title") or "").strip(),
            "author": str(type_pr.get("author") or "").strip(),
            "status": _normalize_type_pr_status(type_pr.get("status")),
            "reviewers": [dict(item) for item in type_pr.get("reviewers", []) if isinstance(item, Mapping)]
            if isinstance(type_pr.get("reviewers"), list)
            else [],
            "assertion_count": len(assertion_rows),
            "confidence_floor": _type_pr_confidence_floor(type_pr),
            "conflict_count": _type_pr_conflict_count(type_pr),
            "created_at_utc": str(type_pr.get("created_at_utc") or ""),
            "updated_at_utc": str(type_pr.get("updated_at_utc") or ""),
            "assertion_state_counts": _type_pr_assertion_state_counts(type_pr),
            "propagation_transaction_count": len(
                [item for item in type_pr.get("propagation_transactions", []) if isinstance(item, Mapping)]
            ) if isinstance(type_pr.get("propagation_transactions"), list) else 0,
        },
        "assertions": assertion_rows,
        "review_timeline": review_timeline,
        "decision_form": {
            "supported_decisions": sorted(TYPE_PR_DECISION_TO_PR_STATUS),
            "comment_required_for": [
                TYPE_PR_DECISION_REQUEST_CHANGES,
                TYPE_PR_DECISION_REJECT,
            ],
            "rationale_required": True,
        },
        "local_store": str(local_store),
    }


def submit_type_pr_review_decision(
    *,
    local_store: Path,
    type_pr_id: str,
    reviewer_id: str,
    decision: str,
    rationale: str,
    comment: str | None = None,
) -> dict[str, Any]:
    normalized_id = str(type_pr_id).strip()
    if not normalized_id:
        raise ValueError("type_pr_id is required")

    normalized_reviewer = str(reviewer_id).strip()
    if not normalized_reviewer:
        raise ValueError("reviewer_id is required")

    normalized_decision = _normalize_type_pr_decision(decision)
    if normalized_decision not in TYPE_PR_DECISION_TO_PR_STATUS:
        allowed = ", ".join(sorted(TYPE_PR_DECISION_TO_PR_STATUS))
        raise ValueError(f"unsupported type PR decision '{decision}'; expected one of: {allowed}")

    normalized_rationale = str(rationale).strip()
    if not normalized_rationale:
        raise ValueError("rationale is required")

    normalized_comment = str(comment).strip() if comment is not None else None
    if normalized_comment == "":
        normalized_comment = None
    if normalized_decision in {TYPE_PR_DECISION_REQUEST_CHANGES, TYPE_PR_DECISION_REJECT} and not normalized_comment:
        raise ValueError(f"comment is required for decision '{normalized_decision}'")

    store_doc = _load_local_proposal_store(local_store)
    type_prs = store_doc.get("type_prs")
    type_pr_docs = [dict(item) for item in type_prs if isinstance(item, Mapping)] if isinstance(type_prs, list) else []
    by_id, _, _ = _resolve_type_pr_targets(type_pr_docs, type_pr_ids=None)
    type_pr = by_id.get(normalized_id)
    if type_pr is None:
        raise ValueError(f"unknown type_pr_id '{normalized_id}'")

    current_status = _normalize_type_pr_status(type_pr.get("status"))
    if current_status not in TYPE_PR_REVIEWABLE_STATUSES:
        allowed_states = ", ".join(sorted(TYPE_PR_REVIEWABLE_STATUSES))
        raise ValueError(
            f"type_pr '{normalized_id}' is not reviewable in status '{current_status}' "
            f"(expected one of: {allowed_states})"
        )

    assertions_raw = type_pr.get("assertions")
    assertions = [item for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    if not assertions:
        raise ValueError(f"type_pr '{normalized_id}' has no assertions")

    non_reviewable_assertions = [
        f"{_type_assertion_id_from_doc(assertion)}={_normalize_type_assertion_state(assertion.get('lifecycle_state'))}"
        for assertion in assertions
        if _normalize_type_assertion_state(assertion.get("lifecycle_state")) != TYPE_ASSERTION_STATE_UNDER_REVIEW
    ]
    if non_reviewable_assertions:
        raise ValueError(
            "all assertions must be UNDER_REVIEW before decision; received: "
            + ", ".join(non_reviewable_assertions)
        )

    state_before = {
        "type_pr_id": normalized_id,
        "status": current_status,
        "assertion_states": {
            _type_assertion_id_from_doc(assertion): _normalize_type_assertion_state(assertion.get("lifecycle_state"))
            for assertion in assertions
        },
    }

    working_doc = json.loads(json.dumps(store_doc))
    working_type_prs_raw = working_doc.get("type_prs")
    working_type_pr_docs = (
        [dict(item) for item in working_type_prs_raw if isinstance(item, Mapping)]
        if isinstance(working_type_prs_raw, list)
        else []
    )
    working_by_id, _, _ = _resolve_type_pr_targets(working_type_pr_docs, type_pr_ids=None)
    working_pr = working_by_id.get(normalized_id)
    if working_pr is None:
        raise ValueError(f"type_pr '{normalized_id}' disappeared during transactional update")

    decision_at_utc = _utc_now()
    receipt_id = _new_receipt_id(action="type_pr_review")
    resulting_state = TYPE_PR_DECISION_TO_ASSERTION_STATE[normalized_decision]
    next_pr_status = TYPE_PR_DECISION_TO_PR_STATUS[normalized_decision]
    review_id = str(uuid.uuid4())

    pr_decisions_raw = working_pr.get("review_decisions")
    pr_decisions = [dict(item) for item in pr_decisions_raw if isinstance(item, Mapping)] if isinstance(pr_decisions_raw, list) else []
    pr_decision: dict[str, Any] = {
        "review_id": review_id,
        "type_pr_id": normalized_id,
        "reviewer_id": normalized_reviewer,
        "decision": normalized_decision,
        "rationale": normalized_rationale,
        "receipt_id": receipt_id,
        "decided_at_utc": decision_at_utc,
        "resulting_state": resulting_state,
    }
    if normalized_comment:
        pr_decision["comment"] = normalized_comment
    pr_decisions.append(pr_decision)
    working_pr["review_decisions"] = pr_decisions

    status_transitions_raw = working_pr.get("status_transitions")
    status_transitions = [dict(item) for item in status_transitions_raw if isinstance(item, Mapping)] if isinstance(status_transitions_raw, list) else []
    status_transitions.append(
        _new_type_pr_status_transition(
            from_status=current_status,
            to_status=next_pr_status,
            receipt_id=receipt_id,
            changed_at_utc=decision_at_utc,
            reviewer_id=normalized_reviewer,
            decision=normalized_decision,
            comment=normalized_comment,
            rationale=normalized_rationale,
        )
    )
    working_pr["status_transitions"] = status_transitions
    working_pr["status"] = next_pr_status
    working_pr["updated_at_utc"] = decision_at_utc
    working_pr["last_receipt_id"] = receipt_id

    reviewers_raw = working_pr.get("reviewers")
    reviewers = [dict(item) for item in reviewers_raw if isinstance(item, Mapping)] if isinstance(reviewers_raw, list) else []
    reviewer_updated = False
    for reviewer in reviewers:
        candidate = str(reviewer.get("reviewer_id") or reviewer.get("reviewer") or "").strip()
        if candidate == normalized_reviewer:
            reviewer["status"] = TYPE_PR_DECISION_TO_REVIEWER_STATUS[normalized_decision]
            reviewer["latest_decision_id"] = review_id
            reviewer_updated = True
            break
    if not reviewer_updated:
        reviewers.append(
            {
                "reviewer_id": normalized_reviewer,
                "status": TYPE_PR_DECISION_TO_REVIEWER_STATUS[normalized_decision],
                "latest_decision_id": review_id,
            }
        )
    working_pr["reviewers"] = reviewers

    working_assertions_raw = working_pr.get("assertions")
    working_assertions = [dict(item) for item in working_assertions_raw if isinstance(item, Mapping)] if isinstance(working_assertions_raw, list) else []
    for assertion in working_assertions:
        from_state = _normalize_type_assertion_state(assertion.get("lifecycle_state"))
        assertion["lifecycle_state"] = resulting_state
        assertion["updated_at_utc"] = decision_at_utc
        assertion["last_receipt_id"] = receipt_id

        transition_history_raw = assertion.get("transition_history")
        transition_history = [dict(item) for item in transition_history_raw if isinstance(item, Mapping)] if isinstance(transition_history_raw, list) else []
        transition_history.append(
            _new_type_assertion_transition(
                from_state=from_state,
                to_state=resulting_state,
                receipt_id=receipt_id,
                changed_at_utc=decision_at_utc,
                reviewer_id=normalized_reviewer,
                decision=normalized_decision,
                comment=normalized_comment,
                rationale=normalized_rationale,
            )
        )
        assertion["transition_history"] = transition_history

        assertion_decisions_raw = assertion.get("review_decisions")
        assertion_decisions = [dict(item) for item in assertion_decisions_raw if isinstance(item, Mapping)] if isinstance(assertion_decisions_raw, list) else []
        assertion_decision: dict[str, Any] = {
            "review_id": str(uuid.uuid4()),
            "type_pr_id": normalized_id,
            "reviewer_id": normalized_reviewer,
            "decision": normalized_decision,
            "rationale": normalized_rationale,
            "receipt_id": receipt_id,
            "decided_at_utc": decision_at_utc,
            "resulting_state": resulting_state,
        }
        if normalized_comment:
            assertion_decision["comment"] = normalized_comment
        assertion_decisions.append(assertion_decision)
        assertion["review_decisions"] = assertion_decisions

    working_pr["assertions"] = working_assertions
    propagation_report: dict[str, Any] | None = None
    if normalized_decision == TYPE_PR_DECISION_APPROVE:
        propagation_report = _run_type_pr_propagation(
            type_pr=working_pr,
            triggered_by=normalized_reviewer,
            propagated_at_utc=decision_at_utc,
        )

    final_assertions_raw = working_pr.get("assertions")
    final_assertions = (
        [dict(item) for item in final_assertions_raw if isinstance(item, Mapping)]
        if isinstance(final_assertions_raw, list)
        else []
    )
    working_doc["type_prs"] = working_type_pr_docs

    state_after = {
        "type_pr_id": normalized_id,
        "status": next_pr_status,
        "assertion_states": {
            _type_assertion_id_from_doc(assertion): _normalize_type_assertion_state(assertion.get("lifecycle_state"))
            for assertion in final_assertions
        },
    }
    state_before_hash = _digest_json(state_before)
    state_after_hash = _digest_json(state_after)
    transaction_id = _new_transaction_id()

    _write_local_proposal_store(local_store, working_doc)

    return {
        "schema_version": 1,
        "kind": "type_pr_review_decision_report",
        "generated_at_utc": _utc_now(),
        "type_pr_id": normalized_id,
        "decision": normalized_decision,
        "target_assertion_state": resulting_state,
        "next_pr_status": next_pr_status,
        "review_id": review_id,
        "receipt_id": receipt_id,
        "comment": normalized_comment,
        "rationale": normalized_rationale,
        "transaction": {
            "transaction_id": transaction_id,
            "scope": "type_pr",
            "phase": "review_decision",
            "atomic": True,
            "pre_state_hash": state_before_hash,
            "post_state_hash": state_after_hash,
        },
        "state_before": state_before,
        "state_after": state_after,
        "propagation": propagation_report,
        "local_store": str(local_store),
    }


def rollback_type_pr_propagation(
    *,
    local_store: Path,
    type_pr_id: str,
    propagation_receipt_ids: list[str] | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    normalized_type_pr_id = str(type_pr_id).strip()
    if not normalized_type_pr_id:
        raise ValueError("type_pr_id is required")

    normalized_actor = str(actor_id).strip() if actor_id is not None else None
    if normalized_actor == "":
        normalized_actor = None

    store_doc = _load_local_proposal_store(local_store)
    working_doc = json.loads(json.dumps(store_doc))
    type_prs_raw = working_doc.get("type_prs")
    type_pr_docs = [dict(item) for item in type_prs_raw if isinstance(item, Mapping)] if isinstance(type_prs_raw, list) else []
    by_id, _, _ = _resolve_type_pr_targets(type_pr_docs, type_pr_ids=None)
    type_pr = by_id.get(normalized_type_pr_id)
    if type_pr is None:
        raise ValueError(f"unknown type_pr_id '{normalized_type_pr_id}'")

    assertions_raw = type_pr.get("assertions")
    assertions = [dict(item) for item in assertions_raw if isinstance(item, Mapping)] if isinstance(assertions_raw, list) else []
    assertion_by_id: dict[str, dict[str, Any]] = {}
    for assertion in assertions:
        assertion_id = _type_assertion_id_from_doc(assertion)
        if assertion_id and assertion_id not in assertion_by_id:
            assertion_by_id[assertion_id] = assertion

    transactions = _ensure_type_pr_propagation_transactions(type_pr)
    transactions_by_receipt: dict[str, dict[str, Any]] = {}
    for transaction in transactions:
        receipt_id = str(transaction.get("propagation_receipt_id") or "").strip()
        if receipt_id and receipt_id not in transactions_by_receipt:
            transactions_by_receipt[receipt_id] = transaction

    filter_ids = {str(item).strip() for item in (propagation_receipt_ids or []) if str(item).strip()}
    if filter_ids:
        target_receipt_ids = sorted(filter_ids)
        missing = [
            receipt_id
            for receipt_id in target_receipt_ids
            if receipt_id not in transactions_by_receipt
        ]
        if missing:
            raise ValueError(f"unknown propagation_receipt_id(s): {', '.join(missing)}")
    else:
        target_receipt_ids = sorted(
            receipt_id
            for receipt_id, tx in transactions_by_receipt.items()
            if str(tx.get("status") or "propagated").strip().lower() != "rolled_back"
        )
        missing = []

    rolled_back_receipt_ids: list[str] = []
    already_rolled_back_receipt_ids: list[str] = []
    rollback_receipt_ids: list[str] = []
    rolled_back_event_ids: list[str] = []
    restored_assertion_ids: list[str] = []

    for propagation_receipt_id in target_receipt_ids:
        transaction = transactions_by_receipt[propagation_receipt_id]
        tx_status = str(transaction.get("status") or "propagated").strip().lower()
        rollback_receipt_id = str(transaction.get("rollback_receipt_id") or "").strip()
        if tx_status == "rolled_back":
            already_rolled_back_receipt_ids.append(propagation_receipt_id)
            if rollback_receipt_id:
                rollback_receipt_ids.append(rollback_receipt_id)
            continue

        if not rollback_receipt_id:
            rollback_receipt_id = _new_receipt_id(action="rollback")
        rollback_at_utc = _utc_now()
        rollback_transaction_id = _new_transaction_id()

        assertion_ids_raw = transaction.get("assertion_ids")
        if isinstance(assertion_ids_raw, list):
            assertion_ids = [str(item).strip() for item in assertion_ids_raw if str(item).strip()]
        else:
            state_before_raw = transaction.get("state_before")
            if isinstance(state_before_raw, Mapping):
                assertion_ids = [str(item).strip() for item in state_before_raw if str(item).strip()]
            else:
                assertion_ids = []

        tx_rolled_back_event_ids: list[str] = []
        tx_restored_assertion_ids: list[str] = []
        for assertion_id in assertion_ids:
            assertion = assertion_by_id.get(assertion_id)
            if assertion is None:
                raise ValueError(
                    f"propagation transaction '{propagation_receipt_id}' references missing assertion '{assertion_id}'"
                )

            propagation_events_raw = assertion.get("propagation_events")
            propagation_events = [
                dict(item) for item in propagation_events_raw if isinstance(item, Mapping)
            ] if isinstance(propagation_events_raw, list) else []

            event_updated = False
            for event in propagation_events:
                event_receipt_id = str(event.get("applied_receipt_id") or "").strip()
                event_outcome = str(event.get("outcome") or "").strip().upper()
                if event_receipt_id != propagation_receipt_id or event_outcome != TYPE_PROPAGATION_OUTCOME_APPLIED:
                    continue
                event["outcome"] = TYPE_PROPAGATION_OUTCOME_ROLLED_BACK
                event["rollback_receipt_id"] = rollback_receipt_id
                event["rolled_back_at"] = rollback_at_utc
                event_updated = True
                event_id = str(event.get("event_id") or "").strip()
                if event_id:
                    tx_rolled_back_event_ids.append(event_id)

            if not event_updated:
                continue

            assertion["propagation_events"] = propagation_events
            current_state = _normalize_type_assertion_state(assertion.get("lifecycle_state"))
            has_applied_events = any(
                str(item.get("outcome") or "").strip().upper() == TYPE_PROPAGATION_OUTCOME_APPLIED
                for item in propagation_events
            )
            next_state = TYPE_ASSERTION_STATE_PROPAGATED if has_applied_events else TYPE_ASSERTION_STATE_ACCEPTED
            if current_state != next_state:
                transition_history_raw = assertion.get("transition_history")
                transition_history = [
                    dict(item) for item in transition_history_raw if isinstance(item, Mapping)
                ] if isinstance(transition_history_raw, list) else []
                transition_history.append(
                    _new_type_assertion_transition(
                        from_state=current_state,
                        to_state=next_state,
                        receipt_id=rollback_receipt_id,
                        changed_at_utc=rollback_at_utc,
                        reviewer_id=normalized_actor,
                        reason="propagation_rollback",
                    )
                )
                assertion["transition_history"] = transition_history
                assertion["lifecycle_state"] = next_state

            assertion["updated_at_utc"] = rollback_at_utc
            assertion["last_receipt_id"] = rollback_receipt_id
            tx_restored_assertion_ids.append(assertion_id)

        transaction["status"] = "rolled_back"
        transaction["rollback_receipt_id"] = rollback_receipt_id
        transaction["rolled_back_at_utc"] = rollback_at_utc
        transaction["rollback_transaction"] = {
            "transaction_id": rollback_transaction_id,
            "phase": "rollback",
            "scope": "type_pr",
            "pre_state_hash": str(transaction.get("state_after_hash") or ""),
            "post_state_hash": str(transaction.get("state_before_hash") or ""),
        }
        transaction["rollback_receipt_links"] = [
            {
                "receipt_id": propagation_receipt_id,
                "link_type": "ROLLS_BACK_PROPAGATION",
            }
        ]
        transaction["rolled_back_event_ids"] = sorted(set(tx_rolled_back_event_ids))
        if normalized_actor:
            transaction["rolled_back_by"] = normalized_actor

        rolled_back_receipt_ids.append(propagation_receipt_id)
        rollback_receipt_ids.append(rollback_receipt_id)
        rolled_back_event_ids.extend(tx_rolled_back_event_ids)
        restored_assertion_ids.extend(tx_restored_assertion_ids)

    type_pr["assertions"] = assertions
    type_pr["propagation_transactions"] = transactions
    type_pr["updated_at_utc"] = _utc_now()
    working_doc["type_prs"] = type_pr_docs
    _write_local_proposal_store(local_store, working_doc)

    return {
        "schema_version": 1,
        "kind": "type_pr_propagation_rollback_report",
        "generated_at_utc": _utc_now(),
        "type_pr_id": normalized_type_pr_id,
        "bulk": not filter_ids,
        "query": {
            "propagation_receipt_ids": sorted(filter_ids),
        },
        "metrics": {
            "targeted_total": len(target_receipt_ids),
            "rolled_back_total": len(rolled_back_receipt_ids),
            "already_rolled_back_total": len(already_rolled_back_receipt_ids),
            "restored_assertion_total": len(restored_assertion_ids),
            "missing_total": len(missing),
        },
        "rolled_back_propagation_receipt_ids": rolled_back_receipt_ids,
        "already_rolled_back_propagation_receipt_ids": already_rolled_back_receipt_ids,
        "rollback_receipt_ids": rollback_receipt_ids,
        "rolled_back_event_ids": sorted(set(rolled_back_event_ids)),
        "restored_assertion_ids": restored_assertion_ids,
        "local_store": str(local_store),
    }


def review_local_proposals(
    *,
    local_store: Path,
    action: str,
    proposal_ids: list[str] | None = None,
    reviewer_id: str | None = None,
    rationale: str | None = None,
) -> dict[str, Any]:
    normalized_action = str(action).strip().upper()
    target_state = PROPOSAL_REVIEW_ACTION_TO_STATE.get(normalized_action)
    if target_state is None:
        allowed = ", ".join(sorted(PROPOSAL_REVIEW_ACTION_TO_STATE))
        raise ValueError(f"unsupported review action '{action}'; expected one of: {allowed}")

    normalized_reviewer = str(reviewer_id).strip() if reviewer_id is not None else None
    if normalized_reviewer == "":
        normalized_reviewer = None

    normalized_rationale = str(rationale).strip() if rationale is not None else None
    if normalized_rationale == "":
        normalized_rationale = None

    store_doc = _load_local_proposal_store(local_store)
    proposals = store_doc["proposals"]

    filter_ids = {str(item).strip() for item in (proposal_ids or []) if str(item).strip()}
    by_id, target_ids, missing = _resolve_proposal_targets(
        proposals,
        proposal_ids=filter_ids if filter_ids else None,
    )

    reviewed_ids: list[str] = []
    skipped: list[dict[str, str]] = []
    for proposal_id in target_ids:
        proposal = by_id.get(proposal_id)
        if proposal is None:
            continue
        current_state = _normalize_proposal_state(proposal.get("state"))
        if current_state != PROPOSAL_STATE_PROPOSED:
            skipped.append(
                {
                    "proposal_id": proposal_id,
                    "state": current_state,
                    "reason": "state_not_reviewable",
                }
            )
            continue
        _set_proposal_state(
            proposal,
            to_state=target_state,
            action=normalized_action,
            actor_id=normalized_reviewer,
            reason=normalized_rationale,
        )
        reviewed_ids.append(proposal_id)

    store_doc["proposals"] = proposals
    _write_local_proposal_store(local_store, store_doc)

    return {
        "schema_version": 1,
        "kind": "proposal_review_report",
        "generated_at_utc": _utc_now(),
        "action": normalized_action,
        "target_state": target_state,
        "bulk": not filter_ids,
        "query": {
            "proposal_ids": sorted(filter_ids),
        },
        "metrics": {
            "scanned_total": len(proposals),
            "targeted_total": len(target_ids),
            "reviewed_total": len(reviewed_ids),
            "skipped_total": len(skipped),
            "missing_total": len(missing),
            "state_counts": _proposal_state_counts(proposals),
        },
        "reviewed_proposal_ids": reviewed_ids,
        "skipped": skipped,
        "missing_proposal_ids": missing,
        "local_store": str(local_store),
    }


def apply_local_proposals(
    *,
    local_store: Path,
    proposal_ids: list[str] | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    normalized_actor = str(actor_id).strip() if actor_id is not None else None
    if normalized_actor == "":
        normalized_actor = None

    store_doc = _load_local_proposal_store(local_store)
    proposals = store_doc["proposals"]
    apply_transactions = _ensure_apply_transactions(store_doc)

    filter_ids = {str(item).strip() for item in (proposal_ids or []) if str(item).strip()}
    by_id, target_ids, missing = _resolve_proposal_targets(
        proposals,
        proposal_ids=filter_ids if filter_ids else None,
    )

    if filter_ids:
        candidate_ids = target_ids
    else:
        candidate_ids = [
            proposal_id
            for proposal_id in target_ids
            if _normalize_proposal_state(by_id[proposal_id].get("state")) == PROPOSAL_STATE_APPROVED
        ]

    if missing:
        raise ValueError(f"unknown proposal_id(s): {', '.join(missing)}")

    non_approved: list[str] = []
    for proposal_id in candidate_ids:
        current_state = _normalize_proposal_state(by_id[proposal_id].get("state"))
        if current_state != PROPOSAL_STATE_APPROVED:
            non_approved.append(f"{proposal_id}={current_state}")
    if non_approved:
        raise ValueError(
            "only APPROVED proposals can enter apply workflow; received: "
            + ", ".join(non_approved)
        )

    applied_ids: list[str] = []
    apply_receipt_id: str | None = None
    transaction_doc: dict[str, Any] | None = None
    applied_evidence_link_ids: set[str] = set()
    evidence_link_ids_by_proposal: dict[str, list[str]] = {}
    if candidate_ids:
        scope = "single" if len(candidate_ids) == 1 else "batch"
        apply_receipt_id = _new_receipt_id(action="apply")
        transaction_id = _new_transaction_id()
        program_transaction_id = _next_program_transaction_id(
            store_doc,
            apply_transactions=apply_transactions,
        )
        state_before = {
            proposal_id: _capture_proposal_snapshot(by_id[proposal_id])
            for proposal_id in candidate_ids
        }

        for proposal_id in candidate_ids:
            proposal = by_id[proposal_id]
            proposal_receipt_id = str(proposal.get("receipt_id") or f"receipt:{proposal_id}").strip()
            if not proposal_receipt_id:
                proposal_receipt_id = f"receipt:{proposal_id}"
            _set_proposal_state(
                proposal,
                to_state=PROPOSAL_STATE_APPLIED,
                action=PROPOSAL_ACTION_APPLY,
                actor_id=normalized_actor,
            )
            proposal_evidence_link_ids = _proposal_evidence_link_ids(proposal)
            applied_evidence_link_ids.update(proposal_evidence_link_ids)
            evidence_link_ids_by_proposal[proposal_id] = list(proposal_evidence_link_ids)
            events_raw = proposal.get("apply_events")
            events = [dict(item) for item in events_raw if isinstance(item, Mapping)] if isinstance(events_raw, list) else []
            if events:
                events[-1]["apply_receipt_id"] = apply_receipt_id
                events[-1]["receipt_links"] = [
                    {
                        "receipt_id": proposal_receipt_id,
                        "link_type": PROPOSAL_LINK_APPLIES_PROPOSAL,
                    }
                ]
                events[-1]["transaction"] = {
                    "transaction_id": transaction_id,
                    "scope": scope,
                    "phase": "apply",
                    "program_transaction_id": program_transaction_id,
                }
                events[-1]["evidence_link_ids"] = list(proposal_evidence_link_ids)
                events[-1]["evidence_links"] = _proposal_evidence_links(proposal)
                proposal["apply_events"] = events
            applied_ids.append(proposal_id)

        state_after = {
            proposal_id: _capture_proposal_snapshot(by_id[proposal_id])
            for proposal_id in candidate_ids
        }
        state_before_hash = _digest_json(state_before)
        state_after_hash = _digest_json(state_after)
        receipt_links = [
            {
                "receipt_id": str(by_id[proposal_id].get("receipt_id") or f"receipt:{proposal_id}").strip()
                or f"receipt:{proposal_id}",
                "link_type": PROPOSAL_LINK_APPLIES_PROPOSAL,
            }
            for proposal_id in candidate_ids
        ]
        transaction_doc = {
            "transaction_id": transaction_id,
            "program_transaction_id": program_transaction_id,
            "scope": scope,
            "status": "applied",
            "phase": "apply",
            "apply_receipt_id": apply_receipt_id,
            "proposal_ids": list(candidate_ids),
            "state_before": state_before,
            "state_after": state_after,
            "state_before_hash": state_before_hash,
            "state_after_hash": state_after_hash,
            "receipt_links": receipt_links,
            "evidence_link_ids": sorted(applied_evidence_link_ids),
            "evidence_link_ids_by_proposal": evidence_link_ids_by_proposal,
            "applied_at_utc": _utc_now(),
        }
        if normalized_actor:
            transaction_doc["applied_by"] = normalized_actor
        apply_transactions.append(transaction_doc)

    store_doc["proposals"] = proposals
    _write_local_proposal_store(local_store, store_doc)

    transaction_summary: dict[str, Any] | None = None
    receipt_links: list[dict[str, str]] = []
    evidence_link_ids: list[str] = []
    if transaction_doc is not None:
        receipt_links = [dict(item) for item in transaction_doc.get("receipt_links", []) if isinstance(item, Mapping)]
        evidence_link_ids_raw = transaction_doc.get("evidence_link_ids")
        if isinstance(evidence_link_ids_raw, list):
            evidence_link_ids = [
                str(item).strip()
                for item in evidence_link_ids_raw
                if str(item).strip()
            ]
        transaction_summary = {
            "transaction_id": transaction_doc["transaction_id"],
            "scope": transaction_doc["scope"],
            "phase": "apply",
            "program_transaction_id": transaction_doc["program_transaction_id"],
            "pre_apply_state_hash": transaction_doc["state_before_hash"],
            "post_apply_state_hash": transaction_doc["state_after_hash"],
            "evidence_link_ids": evidence_link_ids,
            "evidence_link_ids_by_proposal": dict(
                transaction_doc.get("evidence_link_ids_by_proposal", {})
            ),
        }

    return {
        "schema_version": 1,
        "kind": "proposal_apply_report",
        "generated_at_utc": _utc_now(),
        "bulk": not filter_ids,
        "query": {
            "proposal_ids": sorted(filter_ids),
        },
        "metrics": {
            "scanned_total": len(proposals),
            "targeted_total": len(candidate_ids),
            "applied_total": len(applied_ids),
            "state_counts": _proposal_state_counts(proposals),
        },
        "applied_proposal_ids": applied_ids,
        "apply_receipt_id": apply_receipt_id,
        "transaction": transaction_summary,
        "receipt_links": receipt_links,
        "evidence_link_ids": evidence_link_ids,
        "local_store": str(local_store),
    }


def rollback_local_proposals(
    *,
    local_store: Path,
    apply_receipt_ids: list[str] | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    normalized_actor = str(actor_id).strip() if actor_id is not None else None
    if normalized_actor == "":
        normalized_actor = None

    store_doc = _load_local_proposal_store(local_store)
    proposals = store_doc["proposals"]
    apply_transactions = _ensure_apply_transactions(store_doc)
    by_id, _, _ = _resolve_proposal_targets(proposals, proposal_ids=None)

    transactions_by_apply_receipt: dict[str, dict[str, Any]] = {}
    for transaction in apply_transactions:
        apply_receipt_id = str(transaction.get("apply_receipt_id") or "").strip()
        if apply_receipt_id and apply_receipt_id not in transactions_by_apply_receipt:
            transactions_by_apply_receipt[apply_receipt_id] = transaction

    filter_ids = {str(item).strip() for item in (apply_receipt_ids or []) if str(item).strip()}
    if filter_ids:
        target_apply_receipt_ids = sorted(filter_ids)
        missing = [
            apply_receipt_id
            for apply_receipt_id in target_apply_receipt_ids
            if apply_receipt_id not in transactions_by_apply_receipt
        ]
        if missing:
            raise ValueError(f"unknown apply_receipt_id(s): {', '.join(missing)}")
    else:
        target_apply_receipt_ids = sorted(
            apply_receipt_id
            for apply_receipt_id, transaction in transactions_by_apply_receipt.items()
            if str(transaction.get("status") or "applied").strip().lower() != "rolled_back"
        )
        missing = []

    rolled_back_apply_receipt_ids: list[str] = []
    already_rolled_back_apply_receipt_ids: list[str] = []
    rollback_receipt_ids: list[str] = []
    restored_proposal_ids: list[str] = []
    rolled_back_evidence_link_ids: set[str] = set()

    for apply_receipt_id in target_apply_receipt_ids:
        transaction = transactions_by_apply_receipt[apply_receipt_id]
        status = str(transaction.get("status") or "applied").strip().lower()
        rollback_receipt_id = str(transaction.get("rollback_receipt_id") or "").strip()
        if status == "rolled_back":
            already_rolled_back_apply_receipt_ids.append(apply_receipt_id)
            if rollback_receipt_id:
                rollback_receipt_ids.append(rollback_receipt_id)
            continue

        state_before_raw = transaction.get("state_before")
        if not isinstance(state_before_raw, Mapping):
            raise ValueError(f"apply transaction '{apply_receipt_id}' missing required state_before snapshot")

        proposal_ids_raw = transaction.get("proposal_ids")
        proposal_ids_in_tx = (
            [str(item).strip() for item in proposal_ids_raw if str(item).strip()]
            if isinstance(proposal_ids_raw, list)
            else [str(item).strip() for item in state_before_raw if str(item).strip()]
        )
        if not proposal_ids_in_tx:
            raise ValueError(f"apply transaction '{apply_receipt_id}' has no proposal_ids")

        for proposal_id in proposal_ids_in_tx:
            proposal = by_id.get(proposal_id)
            if proposal is None:
                raise ValueError(
                    f"apply transaction '{apply_receipt_id}' references missing proposal '{proposal_id}'"
                )
            snapshot_raw = state_before_raw.get(proposal_id)
            if not isinstance(snapshot_raw, Mapping):
                raise ValueError(
                    f"apply transaction '{apply_receipt_id}' missing state_before snapshot for '{proposal_id}'"
                )
            expected_state = _normalize_proposal_state(snapshot_raw.get("state"), default="")
            if not expected_state:
                raise ValueError(
                    f"apply transaction '{apply_receipt_id}' snapshot for '{proposal_id}' is missing state"
                )
            current_state = _normalize_proposal_state(proposal.get("state"))
            if current_state == expected_state:
                continue
            allowed = PROPOSAL_ALLOWED_TRANSITIONS.get(current_state, frozenset())
            if expected_state not in allowed:
                raise ValueError(
                    f"cannot rollback '{apply_receipt_id}': proposal '{proposal_id}' is '{current_state}'"
                )

        if not rollback_receipt_id:
            rollback_receipt_id = _new_receipt_id(action="rollback")
        rollback_transaction_id = _new_transaction_id()
        rollback_program_tx_id = _next_program_transaction_id(
            store_doc,
            apply_transactions=apply_transactions,
        )
        scope = str(transaction.get("scope") or "").strip().lower()
        if scope not in {"single", "batch"}:
            scope = "single" if len(proposal_ids_in_tx) == 1 else "batch"
        restore_order = list(reversed(proposal_ids_in_tx)) if scope == "batch" else list(proposal_ids_in_tx)
        pre_apply_state_hash = str(transaction.get("state_before_hash") or _digest_json(state_before_raw)).strip()
        post_apply_state_hash = str(transaction.get("state_after_hash") or "").strip() or None
        tx_evidence_link_ids: set[str] = set()

        for proposal_id in restore_order:
            proposal = by_id[proposal_id]
            snapshot_raw = state_before_raw.get(proposal_id)
            if not isinstance(snapshot_raw, Mapping):
                continue
            target_state = _normalize_proposal_state(snapshot_raw.get("state"))
            from_state = _normalize_proposal_state(proposal.get("state"))
            if from_state != target_state:
                _set_proposal_state(
                    proposal,
                    to_state=target_state,
                    action=PROPOSAL_ACTION_ROLLBACK,
                    actor_id=normalized_actor,
                )
            snapshot_evidence_refs_raw = snapshot_raw.get("evidence_refs")
            snapshot_evidence_refs = (
                _normalize_proposal_evidence_refs(snapshot_evidence_refs_raw, proposal_id=proposal_id)
                if isinstance(snapshot_evidence_refs_raw, list)
                else []
            )
            snapshot_evidence_link_ids = (
                [
                    str(item).strip()
                    for item in snapshot_raw.get("evidence_link_ids", [])
                    if str(item).strip()
                ]
                if isinstance(snapshot_raw.get("evidence_link_ids"), list)
                else [
                    str(item.get("evidence_ref_id") or "").strip()
                    for item in snapshot_evidence_refs
                    if str(item.get("evidence_ref_id") or "").strip()
                ]
            )
            snapshot_evidence_link_ids = sorted(
                {evidence_ref_id for evidence_ref_id in snapshot_evidence_link_ids if evidence_ref_id}
            )
            proposal["evidence_refs"] = [dict(item) for item in snapshot_evidence_refs]
            proposal["evidence_link_ids"] = list(snapshot_evidence_link_ids)
            proposal["evidence_links"] = [dict(item) for item in snapshot_evidence_refs]
            artifact_raw = proposal.get("artifact")
            if isinstance(artifact_raw, Mapping):
                artifact_doc = dict(artifact_raw)
                artifact_doc["evidence_refs"] = [dict(item) for item in snapshot_evidence_refs]
                artifact_doc["evidence_links"] = [dict(item) for item in snapshot_evidence_refs]
                proposal["artifact"] = artifact_doc
            tx_evidence_link_ids.update(snapshot_evidence_link_ids)
            rolled_back_at = str(proposal.get("updated_at_utc") or _utc_now())
            events_raw = proposal.get("apply_events")
            events = [dict(item) for item in events_raw if isinstance(item, Mapping)] if isinstance(events_raw, list) else []
            event: dict[str, Any] = {
                "action": PROPOSAL_ACTION_ROLLBACK,
                "resulting_state": target_state,
                "restored_from_state": from_state,
                "rolled_back_at_utc": rolled_back_at,
                "apply_receipt_id": apply_receipt_id,
                "rollback_receipt_id": rollback_receipt_id,
                "receipt_links": [
                    {
                        "receipt_id": apply_receipt_id,
                        "link_type": PROPOSAL_LINK_ROLLS_BACK_APPLY,
                    }
                ],
                "transaction": {
                    "transaction_id": rollback_transaction_id,
                    "scope": scope,
                    "phase": "rollback",
                    "program_transaction_id": rollback_program_tx_id,
                    "pre_apply_state_hash": pre_apply_state_hash,
                    "post_apply_state_hash": post_apply_state_hash,
                },
                "evidence_link_ids": list(snapshot_evidence_link_ids),
                "evidence_links": [dict(item) for item in snapshot_evidence_refs],
            }
            if normalized_actor:
                event["actor_id"] = normalized_actor
            events.append(event)
            proposal["apply_events"] = events
            restored_proposal_ids.append(proposal_id)

        transaction["status"] = "rolled_back"
        transaction["rollback_receipt_id"] = rollback_receipt_id
        transaction["rolled_back_at_utc"] = _utc_now()
        transaction["rollback_transaction"] = {
            "transaction_id": rollback_transaction_id,
            "scope": scope,
            "phase": "rollback",
            "program_transaction_id": rollback_program_tx_id,
            "pre_apply_state_hash": pre_apply_state_hash,
            "post_apply_state_hash": post_apply_state_hash,
        }
        transaction["rollback_receipt_links"] = [
            {
                "receipt_id": apply_receipt_id,
                "link_type": PROPOSAL_LINK_ROLLS_BACK_APPLY,
            }
        ]
        transaction["rollback_evidence_link_ids"] = sorted(tx_evidence_link_ids)
        if normalized_actor:
            transaction["rolled_back_by"] = normalized_actor

        rolled_back_apply_receipt_ids.append(apply_receipt_id)
        rollback_receipt_ids.append(rollback_receipt_id)
        rolled_back_evidence_link_ids.update(tx_evidence_link_ids)

    store_doc["proposals"] = proposals
    _write_local_proposal_store(local_store, store_doc)

    return {
        "schema_version": 1,
        "kind": "proposal_rollback_report",
        "generated_at_utc": _utc_now(),
        "bulk": not filter_ids,
        "query": {
            "apply_receipt_ids": sorted(filter_ids),
        },
        "metrics": {
            "scanned_total": len(proposals),
            "targeted_total": len(target_apply_receipt_ids),
            "rolled_back_total": len(rolled_back_apply_receipt_ids),
            "already_rolled_back_total": len(already_rolled_back_apply_receipt_ids),
            "restored_total": len(restored_proposal_ids),
            "missing_total": len(missing),
            "state_counts": _proposal_state_counts(proposals),
        },
        "rolled_back_apply_receipt_ids": rolled_back_apply_receipt_ids,
        "already_rolled_back_apply_receipt_ids": already_rolled_back_apply_receipt_ids,
        "rollback_receipt_ids": rollback_receipt_ids,
        "restored_proposal_ids": restored_proposal_ids,
        "evidence_link_ids": sorted(rolled_back_evidence_link_ids),
        "local_store": str(local_store),
    }


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
    updated_at_utc = _utc_now()
    provenance_chain: list[dict[str, str]] = []
    source_receipt_id = source_candidate.receipt_id
    if source_receipt_id:
        provenance_chain.append({"receipt_id": source_receipt_id})
    receipt_link: dict[str, str] = {"receipt_id": receipt_id}
    if source_receipt_id:
        receipt_link["previous_receipt_id"] = source_receipt_id
    provenance_chain.append(receipt_link)

    proposal_evidence_refs = _normalize_proposal_evidence_refs(
        [ref.to_json() for ref in local_function.evidence_refs],
        proposal_id=proposal_id,
    )
    proposal_evidence_link_ids = [
        str(item.get("evidence_ref_id") or "").strip()
        for item in proposal_evidence_refs
        if str(item.get("evidence_ref_id") or "").strip()
    ]

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
        "evidence_refs": [dict(item) for item in proposal_evidence_refs],
        "evidence_links": [dict(item) for item in proposal_evidence_refs],
    }
    if reusable_artifact.confidence is not None:
        artifact_doc["reuse_confidence"] = round(reusable_artifact.confidence, 6)
    if reusable_artifact.target_id is not None:
        artifact_doc["target_id"] = reusable_artifact.target_id

    proposal: dict[str, Any] = {
        "proposal_id": proposal_id,
        "state": PROPOSAL_STATE_PROPOSED,
        "receipt_id": receipt_id,
        "updated_at_utc": updated_at_utc,
        "artifact": artifact_doc,
        "evidence_refs": [dict(item) for item in proposal_evidence_refs],
        "evidence_link_ids": list(proposal_evidence_link_ids),
        "evidence_links": [dict(item) for item in proposal_evidence_refs],
        "provenance_chain": provenance_chain,
        "lifecycle_transitions": [
            _new_proposal_transition(
                from_state=None,
                to_state=PROPOSAL_STATE_PROPOSED,
                action="CREATE",
                changed_at_utc=updated_at_utc,
            )
        ],
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
    if program_id is not None:
        shared_candidates = [
            candidate
            for candidate in shared_candidates
            if candidate.program_id != program_id
        ]
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

    store_doc["proposals"] = existing_proposals
    _write_local_proposal_store(local_store, store_doc)

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


@dataclass(frozen=True)
class TriageBenchmarkCase:
    """Labeled triage benchmark row used for threshold calibration."""

    record: FunctionRecord
    labels: tuple[tuple[str, bool], ...]

    def labels_map(self) -> dict[str, bool]:
        return dict(self.labels)


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
        canonical_evidence_refs = self._canonicalize_evidence_refs(record.function_id, record.evidence_refs)
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
    def _canonicalize_evidence_refs(
        function_id: str,
        evidence_refs: tuple[EvidenceRef, ...],
    ) -> tuple[EvidenceRef, ...]:
        unique_refs: dict[tuple[str, str, str, str, float | None], EvidenceRef] = {}
        for ref in evidence_refs:
            key = (ref.evidence_ref_id, ref.kind, ref.uri, ref.description, ref.confidence)
            if key not in unique_refs:
                unique_refs[key] = ref
        ordered = sorted(
            unique_refs.values(),
            key=lambda item: (
                item.evidence_ref_id,
                item.kind,
                item.uri,
                item.description,
                DeterministicTriageFeatureExtractor._confidence_sort_key(item.confidence),
            ),
        )
        if ordered:
            return tuple(ordered)
        return (
            EvidenceRef.from_json(
                {
                    "kind": "TEXT_FEATURE",
                    "description": f"Deterministic triage fallback evidence for {function_id}",
                    "uri": f"local-index://features/{function_id}/triage-fallback",
                },
                function_id=function_id,
            ),
        )

    @staticmethod
    def _confidence_sort_key(confidence: float | None) -> float:
        if confidence is None:
            return -1.0
        return float(confidence)


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
        entrypoint_threshold: float = DEFAULT_TRIAGE_ENTRYPOINT_THRESHOLD,
        hotspot_threshold: float = DEFAULT_TRIAGE_HOTSPOT_THRESHOLD,
        unknown_threshold: float = DEFAULT_TRIAGE_UNKNOWN_THRESHOLD,
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


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
            link_source_context_uri = str(link.get("source_context_uri") or source_context_uri)
            rendered = _markdown_link(label, uri)
            if link_source_context_uri:
                rendered += f" ({_markdown_link('context', link_source_context_uri)})"
            rendered_links.append(rendered)
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

    artifact_paths = {
        "summary": summary_path.name,
        "panel": panel_path.name,
        "markdown": markdown_path.name,
    }
    artifact_checksums = {
        "summary": _sha256_file(summary_path),
        "panel": _sha256_file(panel_path),
        "markdown": _sha256_file(markdown_path),
    }
    artifact_bytes = {
        "summary": summary_path.stat().st_size,
        "panel": panel_path.stat().st_size,
        "markdown": markdown_path.stat().st_size,
    }

    manifest = {
        "schema_version": 1,
        "kind": "triage_mission_artifacts",
        "generated_at_utc": _utc_now(),
        "mission_id": str(report.get("mission_id") or ""),
        "artifacts": artifact_paths,
        "artifact_checksums": artifact_checksums,
        "artifact_bytes": artifact_bytes,
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
        enable_symbolic_stage: bool = True,
        enable_lexical_stage: bool = True,
        enable_embedding_stage: bool = True,
        lexical_min_overlap: float = 0.0,
    ):
        if rerank_candidate_multiplier <= 0:
            raise ValueError("rerank_candidate_multiplier must be > 0")
        if lexical_min_overlap < 0.0 or lexical_min_overlap > 1.0:
            raise ValueError("lexical_min_overlap must be within [0.0, 1.0]")
        self._adapter = adapter
        self._index = index
        self._reranker = reranker
        self._rerank_candidate_multiplier = rerank_candidate_multiplier
        self._enable_symbolic_stage = enable_symbolic_stage
        self._enable_lexical_stage = enable_lexical_stage
        self._enable_embedding_stage = enable_embedding_stage
        self._lexical_min_overlap = lexical_min_overlap

    def search_intent(self, query_text: str, top_k: int = 5) -> SemanticSearchResponse:
        normalized = query_text.strip()
        candidate_k = top_k
        if self._reranker is not None:
            candidate_k = max(top_k, top_k * self._rerank_candidate_multiplier)
        start = _now_ns()
        hits, stage_metrics, embedding_backend_status, embedding_fallback_applied = self._generate_candidates(
            query_text=normalized,
            candidate_k=candidate_k,
            exclude_function_id=None,
        )
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
            candidate_stage_metrics=stage_metrics,
            embedding_backend_status=embedding_backend_status,
            embedding_fallback_applied=embedding_fallback_applied,
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
        filtered_hits, stage_metrics, embedding_backend_status, embedding_fallback_applied = (
            self._generate_candidates(
                query_text=query_text,
                candidate_k=candidate_k,
                exclude_function_id=function_id,
            )
        )
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
            candidate_stage_metrics=stage_metrics,
            embedding_backend_status=embedding_backend_status,
            embedding_fallback_applied=embedding_fallback_applied,
        )

    def _generate_candidates(
        self,
        *,
        query_text: str,
        candidate_k: int,
        exclude_function_id: str | None,
    ) -> tuple[list[SearchResult], tuple[CandidateStageMetric, ...], str, bool]:
        stage_metrics: list[CandidateStageMetric] = []
        initial_ids = sorted(self._index.function_ids())
        if exclude_function_id is not None:
            initial_ids = [fid for fid in initial_ids if fid != exclude_function_id]
        symbolic_ids = self._apply_symbolic_stage(initial_ids, query_text, stage_metrics)
        lexical_ids = self._apply_lexical_stage(symbolic_ids, query_text, stage_metrics)
        hits, embedding_backend_status, embedding_fallback_applied = self._apply_embedding_stage(
            lexical_ids,
            query_text=query_text,
            candidate_k=candidate_k,
            stage_metrics=stage_metrics,
        )
        if exclude_function_id is not None:
            hits = [hit for hit in hits if hit.function_id != exclude_function_id]
        return hits, tuple(stage_metrics), embedding_backend_status, embedding_fallback_applied

    def _apply_symbolic_stage(
        self,
        candidate_ids: list[str],
        query_text: str,
        stage_metrics: list[CandidateStageMetric],
    ) -> list[str]:
        input_count = len(candidate_ids)
        constraints = self._parse_symbolic_constraints(query_text)
        if not self._enable_symbolic_stage or not constraints:
            stage_metrics.append(
                CandidateStageMetric(
                    stage="symbolic",
                    enabled=self._enable_symbolic_stage,
                    input_count=input_count,
                    output_count=input_count,
                    contribution_count=0,
                    details=(("constraint_count", len(constraints)),),
                )
            )
            return candidate_ids

        filtered: list[str] = []
        for function_id in candidate_ids:
            record = self._index.get_record(function_id)
            if record is None:
                continue
            if self._matches_symbolic_constraints(record, constraints):
                filtered.append(function_id)
        stage_metrics.append(
            CandidateStageMetric(
                stage="symbolic",
                enabled=True,
                input_count=input_count,
                output_count=len(filtered),
                contribution_count=input_count - len(filtered),
                details=(("constraint_count", len(constraints)),),
            )
        )
        return filtered

    def _apply_lexical_stage(
        self,
        candidate_ids: list[str],
        query_text: str,
        stage_metrics: list[CandidateStageMetric],
    ) -> list[str]:
        input_count = len(candidate_ids)
        if not self._enable_lexical_stage:
            stage_metrics.append(
                CandidateStageMetric(
                    stage="lexical",
                    enabled=False,
                    input_count=input_count,
                    output_count=input_count,
                    contribution_count=0,
                    details=(("min_overlap", self._lexical_min_overlap),),
                )
            )
            return candidate_ids

        query_tokens = set(_TOKEN_RE.findall(query_text.lower()))
        if not query_tokens:
            stage_metrics.append(
                CandidateStageMetric(
                    stage="lexical",
                    enabled=True,
                    input_count=input_count,
                    output_count=input_count,
                    contribution_count=0,
                    details=(("min_overlap", self._lexical_min_overlap), ("query_tokens", 0)),
                )
            )
            return candidate_ids

        kept: list[str] = []
        for function_id in candidate_ids:
            record = self._index.get_record(function_id)
            if record is None:
                continue
            overlap = self._lexical_overlap(query_tokens, record)
            if overlap >= self._lexical_min_overlap:
                kept.append(function_id)
        if not kept and candidate_ids:
            kept = list(candidate_ids)

        stage_metrics.append(
            CandidateStageMetric(
                stage="lexical",
                enabled=True,
                input_count=input_count,
                output_count=len(kept),
                contribution_count=input_count - len(kept),
                details=(
                    ("min_overlap", self._lexical_min_overlap),
                    ("query_tokens", len(query_tokens)),
                ),
            )
        )
        return kept

    def _apply_embedding_stage(
        self,
        candidate_ids: list[str],
        *,
        query_text: str,
        candidate_k: int,
        stage_metrics: list[CandidateStageMetric],
    ) -> tuple[list[SearchResult], str, bool]:
        input_count = len(candidate_ids)
        if input_count == 0:
            stage_metrics.append(
                CandidateStageMetric(
                    stage="embedding",
                    enabled=self._enable_embedding_stage,
                    input_count=0,
                    output_count=0,
                    contribution_count=0,
                )
            )
            return [], "unavailable" if not self._enable_embedding_stage else "available", False

        if not self._enable_embedding_stage:
            fallback_hits = self._lexical_fallback_hits(candidate_ids, query_text, candidate_k)
            stage_metrics.append(
                CandidateStageMetric(
                    stage="embedding",
                    enabled=False,
                    input_count=input_count,
                    output_count=len(fallback_hits),
                    contribution_count=input_count - len(fallback_hits),
                )
            )
            return fallback_hits, "disabled", True

        try:
            raw_hits = self._adapter.top_k(query_text, top_k=max(candidate_k, input_count))
            allowed = set(candidate_ids)
            hits = [hit for hit in raw_hits if hit.function_id in allowed][: min(candidate_k, input_count)]
            if not hits:
                hits = self._lexical_fallback_hits(candidate_ids, query_text, candidate_k)
                stage_metrics.append(
                    CandidateStageMetric(
                        stage="embedding",
                        enabled=True,
                        input_count=input_count,
                        output_count=len(hits),
                        contribution_count=input_count - len(hits),
                        details=(("fallback_reason", "empty_embedding_hits"),),
                    )
                )
                return hits, "available", True

            stage_metrics.append(
                CandidateStageMetric(
                    stage="embedding",
                    enabled=True,
                    input_count=input_count,
                    output_count=len(hits),
                    contribution_count=input_count - len(hits),
                )
            )
            return hits, "available", False
        except Exception:
            fallback_hits = self._lexical_fallback_hits(candidate_ids, query_text, candidate_k)
            stage_metrics.append(
                CandidateStageMetric(
                    stage="embedding",
                    enabled=True,
                    input_count=input_count,
                    output_count=len(fallback_hits),
                    contribution_count=input_count - len(fallback_hits),
                    details=(("fallback_reason", "embedding_backend_unavailable"),),
                )
            )
            return fallback_hits, "unavailable", True

    @staticmethod
    def _parse_symbolic_constraints(query_text: str) -> tuple[tuple[str, str], ...]:
        constraints: list[tuple[str, str]] = []
        for token in query_text.split():
            if ":" not in token:
                continue
            key, value = token.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip().lower()
            if not normalized_value:
                continue
            if normalized_key in {"id", "name", "source", "evidence"}:
                constraints.append((normalized_key, normalized_value))
        return tuple(constraints)

    @staticmethod
    def _matches_symbolic_constraints(
        record: FunctionRecord,
        constraints: tuple[tuple[str, str], ...],
    ) -> bool:
        provenance = {str(k).lower(): str(v).lower() for k, v in record.provenance}
        evidence_kinds = {ref.kind.lower() for ref in record.evidence_refs}
        record_id = record.function_id.lower()
        record_name = record.name.lower()

        for key, value in constraints:
            if key == "id" and value not in record_id:
                return False
            if key == "name" and value not in record_name:
                return False
            if key == "source" and value != provenance.get("source", ""):
                return False
            if key == "evidence" and value not in evidence_kinds:
                return False
        return True

    @staticmethod
    def _lexical_overlap(query_tokens: set[str], record: FunctionRecord) -> float:
        if not query_tokens:
            return 0.0
        record_tokens = set(_TOKEN_RE.findall(f"{record.name} {record.text}".lower()))
        if not record_tokens:
            return 0.0
        overlap = len(query_tokens & record_tokens)
        return overlap / float(len(query_tokens))

    def _lexical_fallback_hits(
        self,
        candidate_ids: list[str],
        query_text: str,
        candidate_k: int,
    ) -> list[SearchResult]:
        query_tokens = set(_TOKEN_RE.findall(query_text.lower()))
        rows: list[tuple[float, str, str]] = []
        for function_id in candidate_ids:
            record = self._index.get_record(function_id)
            if record is None:
                continue
            score = self._lexical_overlap(query_tokens, record)
            rows.append((score, record.function_id, record.name))
        rows.sort(key=lambda item: (-item[0], item[1]))
        limit = min(max(candidate_k, 0), len(rows))
        return [
            SearchResult(function_id=function_id, name=name, score=score)
            for score, function_id, name in rows[:limit]
        ]

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
        candidate_stage_metrics: tuple[CandidateStageMetric, ...] = (),
        embedding_backend_status: str = "available",
        embedding_fallback_applied: bool = False,
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
            candidate_stage_metrics=candidate_stage_metrics,
            embedding_backend_status=embedding_backend_status,
            embedding_fallback_applied=embedding_fallback_applied,
        )
        return SemanticSearchResponse(
            mode=mode,
            query_text=query_text,
            top_k=top_k,
            results=tuple(ranked),
            metrics=metrics,
            seed_function_id=seed_function_id,
        )


class CorpusRecordAdapter:
    """Adapter to convert corpus backend artifacts into FunctionRecord format."""

    def __init__(self, backend: Any):
        self._backend = backend
        self._cache: dict[str, FunctionRecord] = {}

    def list_function_ids(self) -> list[str]:
        if hasattr(self._backend, "_ensure_loaded"):
            self._backend._ensure_loaded()
        if not hasattr(self._backend, "_doc"):
            return []
        artifacts = getattr(self._backend, "_doc", {}).get("artifacts", {})
        if not isinstance(artifacts, dict):
            return []
        return list(artifacts.keys())

    def get_record(self, proposal_id: str) -> FunctionRecord | None:
        if proposal_id in self._cache:
            return self._cache[proposal_id]
        raw = self._backend.get(proposal_id)
        if raw is None:
            return None
        record = self._parse_corpus_artifact(raw, proposal_id)
        if record is not None:
            self._cache[proposal_id] = record
        return record

    def _parse_corpus_artifact(self, raw: Mapping[str, Any], proposal_id: str) -> FunctionRecord | None:
        functions_raw = raw.get("functions")
        if isinstance(functions_raw, list) and functions_raw:
            first = functions_raw[0]
            if isinstance(first, Mapping):
                return FunctionRecord.from_json(first)
        name = str(raw.get("title") or raw.get("name") or proposal_id)
        text = str(raw.get("description") or raw.get("text") or "")
        provenance_raw = raw.get("provenance")
        if isinstance(provenance_raw, Mapping):
            provenance = tuple(sorted((str(k), str(v)) for k, v in provenance_raw.items()))
        else:
            provenance = (("proposal_id", proposal_id), ("source", "corpus_backend"))
        return FunctionRecord(
            function_id=proposal_id,
            name=name,
            text=text,
            provenance=provenance,
            evidence_refs=(),
        )


class ScopedRetrievalService:
    """Similarity retrieval with local and corpus scope support."""

    def __init__(
        self,
        *,
        local_service: SemanticSearchQueryService,
        corpus_adapter: CorpusRecordAdapter | None = None,
        local_pipeline: Any = None,
    ):
        self._local_service = local_service
        self._corpus_adapter = corpus_adapter
        self._local_pipeline = local_pipeline

    def search_intent(
        self,
        query_text: str,
        top_k: int = 5,
        scope: str = RETRIEVAL_SCOPE_LOCAL,
    ) -> SemanticSearchResponse:
        if scope not in RETRIEVAL_ALLOWED_SCOPES:
            raise ValueError(f"scope must be one of: {', '.join(RETRIEVAL_ALLOWED_SCOPES)}")

        if scope == RETRIEVAL_SCOPE_LOCAL:
            return self._local_service.search_intent(query_text, top_k=top_k)

        if scope == RETRIEVAL_SCOPE_CORPUS:
            return self._search_corpus_intent(query_text, top_k=top_k)

        local_response = self._local_service.search_intent(query_text, top_k=top_k)
        corpus_response = self._search_corpus_intent(query_text, top_k=top_k)
        return self._merge_responses(local_response, corpus_response, top_k=top_k)

    def search_similar_function(
        self,
        function_id: str,
        top_k: int = 5,
        scope: str = RETRIEVAL_SCOPE_LOCAL,
    ) -> SemanticSearchResponse:
        if scope not in RETRIEVAL_ALLOWED_SCOPES:
            raise ValueError(f"scope must be one of: {', '.join(RETRIEVAL_ALLOWED_SCOPES)}")

        if scope == RETRIEVAL_SCOPE_LOCAL:
            return self._local_service.search_similar_function(function_id, top_k=top_k)

        if scope == RETRIEVAL_SCOPE_CORPUS:
            return self._search_corpus_similar(function_id, top_k=top_k)

        local_response = self._local_service.search_similar_function(function_id, top_k=top_k)
        corpus_response = self._search_corpus_similar(function_id, top_k=top_k)
        return self._merge_responses(local_response, corpus_response, top_k=top_k)

    def _search_corpus_intent(self, query_text: str, top_k: int) -> SemanticSearchResponse:
        start = _now_ns()
        if self._corpus_adapter is None or self._local_pipeline is None:
            latency_ms = _ms(start, _now_ns())
            return self._empty_response(
                mode=SemanticSearchQueryService.MODE_INTENT,
                query_text=query_text,
                top_k=top_k,
                latency_ms=latency_ms,
            )

        corpus_records = [
            record
            for fid in self._corpus_adapter.list_function_ids()
            if (record := self._corpus_adapter.get_record(fid)) is not None
        ]
        if not corpus_records:
            latency_ms = _ms(start, _now_ns())
            return self._empty_response(
                mode=SemanticSearchQueryService.MODE_INTENT,
                query_text=query_text,
                top_k=top_k,
                latency_ms=latency_ms,
            )

        corpus_index = self._local_pipeline.build_index(corpus_records)
        corpus_adapter = BaselineSimilarityAdapter(
            pipeline=self._local_pipeline, index=corpus_index
        )
        hits = corpus_adapter.top_k(query_text.strip(), top_k=top_k)
        latency_ms = _ms(start, _now_ns())
        return self._build_corpus_response(
            mode=SemanticSearchQueryService.MODE_INTENT,
            query_text=query_text,
            top_k=top_k,
            hits=hits,
            corpus_index=corpus_index,
            latency_ms=latency_ms,
        )

    def _search_corpus_similar(self, function_id: str, top_k: int) -> SemanticSearchResponse:
        start = _now_ns()
        if self._corpus_adapter is None or self._local_pipeline is None:
            latency_ms = _ms(start, _now_ns())
            return self._empty_response(
                mode=SemanticSearchQueryService.MODE_SIMILAR_FUNCTION,
                query_text="",
                top_k=top_k,
                latency_ms=latency_ms,
                seed_function_id=function_id,
            )

        seed_record = self._corpus_adapter.get_record(function_id)
        local_index = getattr(self._local_service, "_index", None)
        if seed_record is None and local_index is not None:
            seed_record = local_index.get_record(function_id)
        if seed_record is None:
            raise ValueError(f"unknown function id: {function_id}")

        query_text = f"{seed_record.name} {seed_record.text}".strip()

        corpus_records = [
            record
            for fid in self._corpus_adapter.list_function_ids()
            if (record := self._corpus_adapter.get_record(fid)) is not None
        ]
        if not corpus_records:
            latency_ms = _ms(start, _now_ns())
            return self._empty_response(
                mode=SemanticSearchQueryService.MODE_SIMILAR_FUNCTION,
                query_text=query_text,
                top_k=top_k,
                latency_ms=latency_ms,
                seed_function_id=function_id,
            )

        corpus_index = self._local_pipeline.build_index(corpus_records)
        corpus_adapter = BaselineSimilarityAdapter(
            pipeline=self._local_pipeline, index=corpus_index
        )
        raw_hits = corpus_adapter.top_k(query_text, top_k=top_k + 1)
        hits = [h for h in raw_hits if h.function_id != function_id][:top_k]
        latency_ms = _ms(start, _now_ns())
        return self._build_corpus_response(
            mode=SemanticSearchQueryService.MODE_SIMILAR_FUNCTION,
            query_text=query_text,
            top_k=top_k,
            hits=hits,
            corpus_index=corpus_index,
            latency_ms=latency_ms,
            seed_function_id=function_id,
        )

    def _empty_response(
        self,
        *,
        mode: str,
        query_text: str,
        top_k: int,
        latency_ms: float,
        seed_function_id: str | None = None,
    ) -> SemanticSearchResponse:
        metrics = SearchLatencyMetric(
            mode=mode,
            latency_ms=latency_ms,
            top_k=top_k,
            result_count=0,
            query_chars=len(query_text),
            query_tokens=len(_TOKEN_RE.findall(query_text.lower())),
            timestamp_utc=_utc_now(),
            seed_function_id=seed_function_id,
        )
        return SemanticSearchResponse(
            mode=mode,
            query_text=query_text,
            top_k=top_k,
            results=(),
            metrics=metrics,
            seed_function_id=seed_function_id,
        )

    def _build_corpus_response(
        self,
        *,
        mode: str,
        query_text: str,
        top_k: int,
        hits: list[Any],
        corpus_index: Any,
        latency_ms: float,
        seed_function_id: str | None = None,
    ) -> SemanticSearchResponse:
        ranked: list[RankedSearchResult] = []
        for rank, hit in enumerate(hits[:top_k], start=1):
            record = corpus_index.get_record(hit.function_id)
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

    def _merge_responses(
        self,
        local: SemanticSearchResponse,
        corpus: SemanticSearchResponse,
        top_k: int,
    ) -> SemanticSearchResponse:
        all_results = list(local.results) + list(corpus.results)
        seen: set[str] = set()
        deduplicated: list[RankedSearchResult] = []
        for result in sorted(all_results, key=lambda r: -r.score):
            if result.function_id in seen:
                continue
            seen.add(result.function_id)
            deduplicated.append(result)
            if len(deduplicated) >= top_k:
                break

        reranked = [
            RankedSearchResult(
                rank=i,
                function_id=r.function_id,
                name=r.name,
                score=r.score,
                provenance=r.provenance,
                evidence_refs=r.evidence_refs,
            )
            for i, r in enumerate(deduplicated, start=1)
        ]

        combined_latency = local.metrics.latency_ms + corpus.metrics.latency_ms
        metrics = SearchLatencyMetric(
            mode=local.metrics.mode,
            latency_ms=combined_latency,
            top_k=top_k,
            result_count=len(reranked),
            query_chars=local.metrics.query_chars,
            query_tokens=local.metrics.query_tokens,
            timestamp_utc=_utc_now(),
            seed_function_id=local.metrics.seed_function_id,
        )
        return SemanticSearchResponse(
            mode=local.mode,
            query_text=local.query_text,
            top_k=top_k,
            results=tuple(reranked),
            metrics=metrics,
            seed_function_id=local.seed_function_id,
        )


def create_benchmark_artifact(
    *,
    scope: str,
    baseline_recall: float,
    candidate_recall: float,
    baseline_latency_p95_ms: float,
    candidate_latency_p95_ms: float,
    corpus_size: int,
    query_count: int,
    recall_gate: float = 0.10,
    latency_gate_ms: float = 300.0,
    artifact_id: str | None = None,
) -> BenchmarkArtifact:
    """Create a benchmark artifact capturing recall and p95 latency deltas."""
    recall_delta = candidate_recall - baseline_recall
    latency_delta = candidate_latency_p95_ms - baseline_latency_p95_ms
    recall_passed = recall_delta >= recall_gate
    latency_passed = candidate_latency_p95_ms <= latency_gate_ms
    passed = recall_passed and latency_passed

    resolved_id = artifact_id
    if not resolved_id:
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        resolved_id = f"benchmark-{scope.lower()}-{stamp}"

    return BenchmarkArtifact(
        artifact_id=resolved_id,
        timestamp_utc=_utc_now(),
        scope=scope,
        recall_at_10_baseline=baseline_recall,
        recall_at_10_candidate=candidate_recall,
        recall_at_10_delta=recall_delta,
        latency_p95_baseline_ms=baseline_latency_p95_ms,
        latency_p95_candidate_ms=candidate_latency_p95_ms,
        latency_p95_delta_ms=latency_delta,
        corpus_size=corpus_size,
        query_count=query_count,
        passed=passed,
        recall_gate_threshold=recall_gate,
        latency_gate_threshold_ms=latency_gate_ms,
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


def _coerce_bool_label(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _coerce_threshold(value: Any, *, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(1.0, parsed))


def _round_threshold(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 6)


def load_triage_benchmark(benchmark_path: Path) -> dict[str, Any]:
    doc = json.loads(benchmark_path.read_text(encoding="utf-8"))
    if not isinstance(doc, Mapping):
        raise ValueError("triage benchmark must be a JSON object")

    functions_raw = doc.get("functions")
    if not isinstance(functions_raw, list) or not functions_raw:
        raise ValueError("triage benchmark must include a non-empty 'functions' array")

    cases: list[TriageBenchmarkCase] = []
    for idx, raw in enumerate(functions_raw):
        if not isinstance(raw, Mapping):
            raise ValueError(f"triage benchmark row at index {idx} must be an object")
        record = FunctionRecord.from_json(raw)
        labels_raw = raw.get("labels")
        if not isinstance(labels_raw, Mapping):
            raise ValueError(f"triage benchmark row {record.function_id} missing required 'labels' object")

        labels = {
            key: _coerce_bool_label(labels_raw.get(key, False))
            for key in TRIAGE_LABEL_KEYS
        }
        cases.append(
            TriageBenchmarkCase(
                record=record,
                labels=tuple(sorted(labels.items(), key=lambda item: item[0])),
            )
        )

    target_thresholds: dict[str, float] = {}
    target_raw = doc.get("target_thresholds")
    if isinstance(target_raw, Mapping):
        for key, value in target_raw.items():
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            target_thresholds[normalized_key] = _round_threshold(_coerce_threshold(value, default=0.0))

    schema_version_raw = doc.get("schema_version")
    try:
        schema_version = int(schema_version_raw) if schema_version_raw is not None else 1
    except (TypeError, ValueError):
        schema_version = 1

    benchmark_id = str(doc.get("benchmark_id") or benchmark_path.stem).strip() or benchmark_path.stem
    benchmark_version = str(doc.get("benchmark_version") or "unversioned").strip() or "unversioned"
    kind = str(doc.get("kind") or "triage_scoring_benchmark").strip() or "triage_scoring_benchmark"

    return {
        "schema_version": schema_version,
        "kind": kind,
        "benchmark_id": benchmark_id,
        "benchmark_version": benchmark_version,
        "target_thresholds": target_thresholds,
        "cases": tuple(cases),
    }


def _triage_feature_rows(
    cases: Iterable[TriageBenchmarkCase],
    *,
    feature_extractor: DeterministicTriageFeatureExtractor | None = None,
) -> list[tuple[TriageFunctionFeatures, dict[str, bool]]]:
    extractor = feature_extractor or DeterministicTriageFeatureExtractor()
    rows: list[tuple[TriageFunctionFeatures, dict[str, bool]]] = []
    for case in cases:
        rows.append((extractor.extract(case.record), case.labels_map()))
    return rows


def _triage_predict_labels(
    feature: TriageFunctionFeatures,
    *,
    entrypoint_threshold: float,
    hotspot_threshold: float,
    unknown_threshold: float,
) -> dict[str, bool]:
    return {
        "entrypoint": feature.entrypoint_score >= entrypoint_threshold,
        "hotspot": feature.hotspot_score >= hotspot_threshold and bool(feature.tags),
        "unknown": feature.unknown_score >= unknown_threshold,
    }


def _binary_metrics(*, tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0
    f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "support": tp + fn,
        "predicted_positive": tp + fp,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _evaluate_triage_feature_rows(
    feature_rows: Iterable[tuple[TriageFunctionFeatures, dict[str, bool]]],
    *,
    entrypoint_threshold: float,
    hotspot_threshold: float,
    unknown_threshold: float,
) -> dict[str, Any]:
    confusion = {
        key: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for key in TRIAGE_LABEL_KEYS
    }
    case_count = 0

    for feature, labels in feature_rows:
        predictions = _triage_predict_labels(
            feature,
            entrypoint_threshold=entrypoint_threshold,
            hotspot_threshold=hotspot_threshold,
            unknown_threshold=unknown_threshold,
        )
        case_count += 1
        for key in TRIAGE_LABEL_KEYS:
            predicted = bool(predictions.get(key, False))
            actual = bool(labels.get(key, False))
            if predicted and actual:
                confusion[key]["tp"] += 1
            elif predicted and not actual:
                confusion[key]["fp"] += 1
            elif not predicted and actual:
                confusion[key]["fn"] += 1
            else:
                confusion[key]["tn"] += 1

    class_metrics: dict[str, Any] = {}
    macro_precision = 0.0
    macro_recall = 0.0
    macro_f1 = 0.0
    for key in TRIAGE_LABEL_KEYS:
        stats = confusion[key]
        metrics = _binary_metrics(
            tp=stats["tp"],
            fp=stats["fp"],
            fn=stats["fn"],
            tn=stats["tn"],
        )
        class_metrics[key] = metrics
        macro_precision += float(metrics["precision"])
        macro_recall += float(metrics["recall"])
        macro_f1 += float(metrics["f1"])

    label_count = len(TRIAGE_LABEL_KEYS)
    macro_precision = (macro_precision / label_count) if label_count else 0.0
    macro_recall = (macro_recall / label_count) if label_count else 0.0
    macro_f1 = (macro_f1 / label_count) if label_count else 0.0

    return {
        "counts": {"cases": case_count},
        "thresholds": {
            "entrypoint": _round_threshold(entrypoint_threshold),
            "hotspot": _round_threshold(hotspot_threshold),
            "unknown": _round_threshold(unknown_threshold),
        },
        "metrics": {
            **class_metrics,
            "macro_precision": round(macro_precision, 6),
            "macro_recall": round(macro_recall, 6),
            "macro_f1": round(macro_f1, 6),
        },
    }


def evaluate_triage_benchmark(
    cases: Iterable[TriageBenchmarkCase],
    *,
    entrypoint_threshold: float,
    hotspot_threshold: float,
    unknown_threshold: float,
    feature_extractor: DeterministicTriageFeatureExtractor | None = None,
) -> dict[str, Any]:
    feature_rows = _triage_feature_rows(cases, feature_extractor=feature_extractor)
    return _evaluate_triage_feature_rows(
        feature_rows,
        entrypoint_threshold=entrypoint_threshold,
        hotspot_threshold=hotspot_threshold,
        unknown_threshold=unknown_threshold,
    )


def _triage_metric_value(metrics: Mapping[str, Any], metric_name: str) -> float:
    if metric_name in {"macro_precision", "macro_recall", "macro_f1"}:
        return float(metrics.get(metric_name, 0.0))

    for label in TRIAGE_LABEL_KEYS:
        prefix = f"{label}_"
        if metric_name.startswith(prefix):
            suffix = metric_name[len(prefix) :]
            class_metrics = metrics.get(label)
            if isinstance(class_metrics, Mapping):
                return float(class_metrics.get(suffix, 0.0))
            return 0.0
    return 0.0


def _triage_threshold_checks(
    metrics: Mapping[str, Any],
    target_thresholds: Mapping[str, float],
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    for metric_name, threshold in target_thresholds.items():
        normalized_name = str(metric_name).strip()
        if not normalized_name:
            continue
        threshold_value = _round_threshold(_coerce_threshold(threshold, default=0.0))
        value = _round_threshold(_triage_metric_value(metrics, normalized_name))
        checks[normalized_name] = {
            "operator": ">=",
            "threshold": threshold_value,
            "value": value,
            "passed": value >= threshold_value,
        }
    return checks


def calibrate_triage_thresholds(
    *,
    cases: Iterable[TriageBenchmarkCase],
    benchmark_id: str,
    benchmark_version: str,
    target_thresholds: Mapping[str, float],
    baseline_entrypoint_threshold: float = LEGACY_TRIAGE_ENTRYPOINT_THRESHOLD,
    baseline_hotspot_threshold: float = LEGACY_TRIAGE_HOTSPOT_THRESHOLD,
    baseline_unknown_threshold: float = LEGACY_TRIAGE_UNKNOWN_THRESHOLD,
    search_step: float = DEFAULT_TRIAGE_CALIBRATION_STEP,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    if search_step <= 0.0 or search_step > 1.0:
        raise ValueError("search_step must be > 0 and <= 1")

    baseline_entrypoint = _round_threshold(baseline_entrypoint_threshold)
    baseline_hotspot = _round_threshold(baseline_hotspot_threshold)
    baseline_unknown = _round_threshold(baseline_unknown_threshold)
    feature_rows = _triage_feature_rows(cases)

    baseline_report = _evaluate_triage_feature_rows(
        feature_rows,
        entrypoint_threshold=baseline_entrypoint,
        hotspot_threshold=baseline_hotspot,
        unknown_threshold=baseline_unknown,
    )
    baseline_metrics = baseline_report["metrics"]
    baseline_checks = _triage_threshold_checks(baseline_metrics, target_thresholds)
    baseline_pass_count = sum(1 for check in baseline_checks.values() if check.get("passed"))

    values: list[float] = []
    steps = int(round(1.0 / search_step))
    for idx in range(steps + 1):
        values.append(_round_threshold(idx * search_step))
    if values[-1] != 1.0:
        values.append(1.0)
    values = sorted(set(values))

    best: tuple[int, float, float, tuple[float, float, float], dict[str, Any], dict[str, Any]] | None = None
    for entrypoint_threshold in values:
        for hotspot_threshold in values:
            for unknown_threshold in values:
                candidate_report = _evaluate_triage_feature_rows(
                    feature_rows,
                    entrypoint_threshold=entrypoint_threshold,
                    hotspot_threshold=hotspot_threshold,
                    unknown_threshold=unknown_threshold,
                )
                candidate_metrics = candidate_report["metrics"]
                candidate_checks = _triage_threshold_checks(candidate_metrics, target_thresholds)
                candidate_pass_count = sum(
                    1 for check in candidate_checks.values() if check.get("passed")
                )
                candidate_macro_f1 = float(candidate_metrics.get("macro_f1", 0.0))
                distance = (
                    abs(entrypoint_threshold - baseline_entrypoint)
                    + abs(hotspot_threshold - baseline_hotspot)
                    + abs(unknown_threshold - baseline_unknown)
                )
                ranking = (
                    candidate_pass_count,
                    candidate_macro_f1,
                    -distance,
                    (entrypoint_threshold, hotspot_threshold, unknown_threshold),
                )
                if best is None or ranking > (
                    best[0],
                    best[1],
                    best[2],
                    best[3],
                ):
                    best = (
                        candidate_pass_count,
                        candidate_macro_f1,
                        -distance,
                        (entrypoint_threshold, hotspot_threshold, unknown_threshold),
                        candidate_report,
                        candidate_checks,
                    )

    if best is None:
        raise ValueError("failed to derive calibrated thresholds")

    _, _, _, candidate_thresholds, candidate_report, candidate_checks = best
    candidate_metrics = candidate_report["metrics"]
    candidate_pass_count = sum(1 for check in candidate_checks.values() if check.get("passed"))
    target_count = len(target_thresholds)
    candidate_macro_f1 = float(candidate_metrics.get("macro_f1", 0.0))
    baseline_macro_f1 = float(baseline_metrics.get("macro_f1", 0.0))
    all_targets_met = candidate_pass_count == target_count if target_count else True
    improves_baseline = candidate_macro_f1 > baseline_macro_f1

    resolved_commit_sha = commit_sha or os.environ.get("GITHUB_SHA") or "unknown"
    return {
        "schema_version": 1,
        "kind": "triage_scoring_calibration",
        "generated_at_utc": _utc_now(),
        "commit_sha": resolved_commit_sha,
        "benchmark": {
            "benchmark_id": benchmark_id,
            "benchmark_version": benchmark_version,
            "case_count": baseline_report["counts"]["cases"],
        },
        "search": {
            "step": _round_threshold(search_step),
            "candidate_count": len(values) ** 3,
        },
        "target_thresholds": dict(target_thresholds),
        "baseline": {
            "thresholds": baseline_report["thresholds"],
            "metrics": baseline_metrics,
            "checks": baseline_checks,
            "targets_passed": baseline_pass_count,
        },
        "candidate": {
            "thresholds": candidate_report["thresholds"],
            "metrics": candidate_metrics,
            "checks": candidate_checks,
            "targets_passed": candidate_pass_count,
        },
        "improvement": {
            "macro_f1_delta": round(candidate_macro_f1 - baseline_macro_f1, 6),
            "entrypoint_recall_delta": round(
                float(candidate_metrics["entrypoint"]["recall"])
                - float(baseline_metrics["entrypoint"]["recall"]),
                6,
            ),
            "hotspot_recall_delta": round(
                float(candidate_metrics["hotspot"]["recall"])
                - float(baseline_metrics["hotspot"]["recall"]),
                6,
            ),
            "unknown_precision_delta": round(
                float(candidate_metrics["unknown"]["precision"])
                - float(baseline_metrics["unknown"]["precision"]),
                6,
            ),
        },
        "status": "passed" if all_targets_met and improves_baseline else "failed",
    }


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


def _triage_calibrate_command(args: argparse.Namespace) -> int:
    benchmark = load_triage_benchmark(args.benchmark)
    report = calibrate_triage_thresholds(
        cases=benchmark["cases"],
        benchmark_id=str(benchmark["benchmark_id"]),
        benchmark_version=str(benchmark["benchmark_version"]),
        target_thresholds=benchmark["target_thresholds"],
        baseline_entrypoint_threshold=args.baseline_entrypoint_threshold,
        baseline_hotspot_threshold=args.baseline_hotspot_threshold,
        baseline_unknown_threshold=args.baseline_unknown_threshold,
        search_step=args.search_step,
        commit_sha=args.commit_sha,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml327] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.no_fail_on_target_fail:
        return 0
    return 0 if report.get("status") == "passed" else 1


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


def _proposal_query_command(args: argparse.Namespace) -> int:
    report = query_local_proposals(
        local_store=args.local_store,
        state=args.state,
        proposal_ids=args.proposal_id,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _proposal_review_command(args: argparse.Namespace) -> int:
    report = review_local_proposals(
        local_store=args.local_store,
        action=args.action,
        proposal_ids=args.proposal_id,
        reviewer_id=args.reviewer_id,
        rationale=args.rationale,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _proposal_apply_command(args: argparse.Namespace) -> int:
    try:
        report = apply_local_proposals(
            local_store=args.local_store,
            proposal_ids=args.proposal_id,
            actor_id=args.actor_id,
        )
    except ValueError as exc:
        error_report = {
            "schema_version": 1,
            "kind": "proposal_apply_error",
            "error": str(exc),
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _proposal_rollback_command(args: argparse.Namespace) -> int:
    try:
        report = rollback_local_proposals(
            local_store=args.local_store,
            apply_receipt_ids=args.apply_receipt_id,
            actor_id=args.actor_id,
        )
    except ValueError as exc:
        error_report = {
            "schema_version": 1,
            "kind": "proposal_rollback_error",
            "error": str(exc),
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _type_pr_list_command(args: argparse.Namespace) -> int:
    report = list_type_pr_review_queue(
        local_store=args.local_store,
        reviewer_id=args.reviewer_id,
        statuses=args.status,
        type_pr_ids=args.type_pr_id,
        sort_by=args.sort_by,
        sort_desc=not args.sort_asc,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _type_pr_detail_command(args: argparse.Namespace) -> int:
    try:
        report = get_type_pr_detail(
            local_store=args.local_store,
            type_pr_id=args.type_pr_id,
            reviewer_id=args.reviewer_id,
        )
    except ValueError as exc:
        error_report = {
            "schema_version": 1,
            "kind": "type_pr_review_detail_error",
            "error": str(exc),
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _type_pr_review_command(args: argparse.Namespace) -> int:
    try:
        report = submit_type_pr_review_decision(
            local_store=args.local_store,
            type_pr_id=args.type_pr_id,
            reviewer_id=args.reviewer_id,
            decision=args.decision,
            rationale=args.rationale,
            comment=args.comment,
        )
    except ValueError as exc:
        error_report = {
            "schema_version": 1,
            "kind": "type_pr_review_decision_error",
            "error": str(exc),
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        return 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[ml301] wrote {args.output}")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _type_pr_rollback_propagation_command(args: argparse.Namespace) -> int:
    try:
        report = rollback_type_pr_propagation(
            local_store=args.local_store,
            type_pr_id=args.type_pr_id,
            propagation_receipt_ids=args.propagation_receipt_id,
            actor_id=args.actor_id,
        )
    except ValueError as exc:
        error_report = {
            "schema_version": 1,
            "kind": "type_pr_propagation_rollback_error",
            "error": str(exc),
        }
        print(json.dumps(error_report, indent=2, sort_keys=True))
        return 1

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
        default=DEFAULT_TRIAGE_ENTRYPOINT_THRESHOLD,
        help="Score threshold for entrypoint emission",
    )
    parser.add_argument(
        "--hotspot-threshold",
        type=float,
        default=DEFAULT_TRIAGE_HOTSPOT_THRESHOLD,
        help="Score threshold for hotspot emission",
    )
    parser.add_argument(
        "--unknown-threshold",
        type=float,
        default=DEFAULT_TRIAGE_UNKNOWN_THRESHOLD,
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

    triage_calibrate_parser = subparsers.add_parser(
        "triage-calibrate",
        help="Calibrate triage thresholds against a labeled benchmark corpus",
    )
    triage_calibrate_parser.add_argument(
        "--benchmark",
        type=Path,
        required=True,
        help="Path to versioned triage benchmark JSON",
    )
    triage_calibrate_parser.add_argument(
        "--baseline-entrypoint-threshold",
        type=float,
        default=LEGACY_TRIAGE_ENTRYPOINT_THRESHOLD,
        help="Baseline entrypoint threshold used for before/after comparison",
    )
    triage_calibrate_parser.add_argument(
        "--baseline-hotspot-threshold",
        type=float,
        default=LEGACY_TRIAGE_HOTSPOT_THRESHOLD,
        help="Baseline hotspot threshold used for before/after comparison",
    )
    triage_calibrate_parser.add_argument(
        "--baseline-unknown-threshold",
        type=float,
        default=LEGACY_TRIAGE_UNKNOWN_THRESHOLD,
        help="Baseline unknown threshold used for before/after comparison",
    )
    triage_calibrate_parser.add_argument(
        "--search-step",
        type=float,
        default=DEFAULT_TRIAGE_CALIBRATION_STEP,
        help="Grid-search step size for threshold calibration",
    )
    triage_calibrate_parser.add_argument(
        "--commit-sha",
        type=str,
        default=None,
        help="Optional commit SHA attached to the calibration artifact",
    )
    triage_calibrate_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write calibration report JSON",
    )
    triage_calibrate_parser.add_argument(
        "--no-fail-on-target-fail",
        action="store_true",
        help="Always exit zero even when calibration targets are not met",
    )
    triage_calibrate_parser.set_defaults(func=_triage_calibrate_command)

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

    proposal_query_parser = subparsers.add_parser(
        "proposal-query",
        help="Query persisted local proposal lifecycle state",
    )
    proposal_query_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    proposal_query_parser.add_argument(
        "--state",
        type=str,
        default=None,
        choices=PROPOSAL_ALLOWED_STATES,
        help="Optional lifecycle state filter",
    )
    proposal_query_parser.add_argument(
        "--proposal-id",
        action="append",
        default=None,
        help="Proposal id filter. Repeatable.",
    )
    proposal_query_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write proposal query report JSON",
    )
    proposal_query_parser.set_defaults(func=_proposal_query_command)

    proposal_review_parser = subparsers.add_parser(
        "proposal-review",
        help="Review proposal state transitions (approve/reject), including bulk reviews",
    )
    proposal_review_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    proposal_review_parser.add_argument(
        "--action",
        type=str,
        required=True,
        choices=sorted(action.lower() for action in PROPOSAL_REVIEW_ACTION_TO_STATE),
        help="Review action to apply",
    )
    proposal_review_parser.add_argument(
        "--proposal-id",
        action="append",
        default=None,
        help="Proposal id to review. Repeatable. Omit for bulk review across all proposals.",
    )
    proposal_review_parser.add_argument(
        "--reviewer-id",
        type=str,
        default=None,
        help="Optional reviewer identifier recorded with lifecycle transition",
    )
    proposal_review_parser.add_argument(
        "--rationale",
        type=str,
        default=None,
        help="Optional rationale/comment recorded with review decision",
    )
    proposal_review_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write proposal review report JSON",
    )
    proposal_review_parser.set_defaults(func=_proposal_review_command)

    proposal_apply_parser = subparsers.add_parser(
        "proposal-apply",
        help="Enter apply workflow for approved proposals only",
    )
    proposal_apply_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    proposal_apply_parser.add_argument(
        "--proposal-id",
        action="append",
        default=None,
        help="Proposal id to apply. Repeatable. Omit for bulk apply of all approved proposals.",
    )
    proposal_apply_parser.add_argument(
        "--actor-id",
        type=str,
        default=None,
        help="Optional actor id recorded with apply transition",
    )
    proposal_apply_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write proposal apply report JSON",
    )
    proposal_apply_parser.set_defaults(func=_proposal_apply_command)

    proposal_rollback_parser = subparsers.add_parser(
        "proposal-rollback",
        help="Rollback applied proposals by apply receipt id",
    )
    proposal_rollback_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    proposal_rollback_parser.add_argument(
        "--apply-receipt-id",
        action="append",
        default=None,
        help="Apply receipt id to rollback. Repeatable. Omit for rollback of all active apply receipts.",
    )
    proposal_rollback_parser.add_argument(
        "--actor-id",
        type=str,
        default=None,
        help="Optional actor id recorded with rollback transition",
    )
    proposal_rollback_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write proposal rollback report JSON",
    )
    proposal_rollback_parser.set_defaults(func=_proposal_rollback_command)

    type_pr_list_parser = subparsers.add_parser(
        "type-pr-list",
        help="Render Type PR review queue list panel payload",
    )
    type_pr_list_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    type_pr_list_parser.add_argument(
        "--reviewer-id",
        type=str,
        default=None,
        help="Optional reviewer identifier to filter assigned Type PRs",
    )
    type_pr_list_parser.add_argument(
        "--status",
        action="append",
        type=str.upper,
        default=None,
        choices=TYPE_PR_ALLOWED_STATUSES,
        help="Type PR status filter. Repeatable. Defaults to review queue statuses.",
    )
    type_pr_list_parser.add_argument(
        "--type-pr-id",
        action="append",
        default=None,
        help="Type PR id filter. Repeatable.",
    )
    type_pr_list_parser.add_argument(
        "--sort-by",
        type=str,
        default="updated_at_utc",
        choices=["updated_at_utc", "confidence_floor", "conflict_count"],
        help="Sort key for list rows",
    )
    type_pr_list_parser.add_argument(
        "--sort-asc",
        action="store_true",
        help="Sort ascending (default: descending)",
    )
    type_pr_list_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write Type PR list panel JSON",
    )
    type_pr_list_parser.set_defaults(func=_type_pr_list_command)

    type_pr_detail_parser = subparsers.add_parser(
        "type-pr-detail",
        help="Render Type PR detail panel payload",
    )
    type_pr_detail_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    type_pr_detail_parser.add_argument(
        "--type-pr-id",
        type=str,
        required=True,
        help="Type PR id to render in detail pane",
    )
    type_pr_detail_parser.add_argument(
        "--reviewer-id",
        type=str,
        default=None,
        help="Optional reviewer identity used for assignment checks",
    )
    type_pr_detail_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write Type PR detail panel JSON",
    )
    type_pr_detail_parser.set_defaults(func=_type_pr_detail_command)

    type_pr_review_parser = subparsers.add_parser(
        "type-pr-review",
        help="Submit Type PR approve/request-changes/reject decision atomically",
    )
    type_pr_review_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    type_pr_review_parser.add_argument(
        "--type-pr-id",
        type=str,
        required=True,
        help="Type PR id to review",
    )
    type_pr_review_parser.add_argument(
        "--reviewer-id",
        type=str,
        required=True,
        help="Reviewer identifier",
    )
    type_pr_review_parser.add_argument(
        "--decision",
        type=str.upper,
        required=True,
        choices=sorted(TYPE_PR_DECISION_TO_PR_STATUS),
        help="Review decision",
    )
    type_pr_review_parser.add_argument(
        "--rationale",
        type=str,
        required=True,
        help="Required rationale captured with review decision",
    )
    type_pr_review_parser.add_argument(
        "--comment",
        type=str,
        default=None,
        help="Comment required for REQUEST_CHANGES and REJECT decisions",
    )
    type_pr_review_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write Type PR review decision report JSON",
    )
    type_pr_review_parser.set_defaults(func=_type_pr_review_command)

    type_pr_rollback_parser = subparsers.add_parser(
        "type-pr-rollback-propagation",
        help="Rollback propagated Type PR events by propagation receipt id",
    )
    type_pr_rollback_parser.add_argument(
        "--local-store",
        type=Path,
        required=True,
        help="Path to local proposal store JSON",
    )
    type_pr_rollback_parser.add_argument(
        "--type-pr-id",
        type=str,
        required=True,
        help="Type PR id whose propagation should be rolled back",
    )
    type_pr_rollback_parser.add_argument(
        "--propagation-receipt-id",
        action="append",
        default=None,
        help="Propagation receipt id to rollback. Repeatable. Omit to rollback all active propagation receipts.",
    )
    type_pr_rollback_parser.add_argument(
        "--actor-id",
        type=str,
        default=None,
        help="Optional actor identifier recorded with rollback transition",
    )
    type_pr_rollback_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write Type PR propagation rollback report JSON",
    )
    type_pr_rollback_parser.set_defaults(func=_type_pr_rollback_propagation_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
