from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any


class SpecType(str, Enum):
    SCHEMA = "schema"
    API = "api"
    STATE_MACHINE = "state_machine"


class ArtifactType(str, Enum):
    SYMBOL = "symbol"
    DATA_TYPE = "data_type"
    COMMENT = "comment"
    FUNCTION_SIG = "function_sig"
    MEMORY_REF = "memory_ref"
    BOOKMARK = "bookmark"
    EQUATE = "equate"


class DeltaSource(str, Enum):
    HUMAN = "human"
    ML_MODEL = "ml_model"
    IMPORT = "import"
    SCRIPT = "script"


class ReviewAction(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    REQUEST_CHANGES = "request_changes"


class ReviewVerdict(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    OPEN = "open"


@dataclass(frozen=True)
class AnalystIdentity:
    id: str
    actor_type: DeltaSource
    display_name: str


@dataclass(frozen=True)
class EvidenceRef:
    id: str
    kind: str
    summary: str
    refs: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Hypothesis:
    id: str
    spec_type: SpecType
    name: str
    confidence: float
    description: str = ""
    evidence: list[EvidenceRef] = field(default_factory=list)


@dataclass(frozen=True)
class AnnotationDelta:
    id: str
    artifact_type: ArtifactType
    address: str | None
    old_value: Any
    new_value: Any
    confidence: float
    source: DeltaSource
    rationale: str = ""
    evidence_link_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AnnotationChangeset:
    id: str
    author: AnalystIdentity
    title: str
    description: str
    deltas: list[AnnotationDelta]


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _content_hash(payload: Any) -> str:
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SpecPacket:
    schema_version: int
    program_name: str
    program_sha256: str
    analysis_sha256: str
    hypotheses: list[Hypothesis]
    changeset: AnnotationChangeset
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def compute_content_hash(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "program_name": self.program_name,
            "program_sha256": self.program_sha256,
            "analysis_sha256": self.analysis_sha256,
            "hypotheses": [asdict(h) for h in self.hypotheses],
            "changeset": asdict(self.changeset),
        }
        return _content_hash(payload)


@dataclass(frozen=True)
class DeltaReview:
    delta_id: str
    action: ReviewAction
    rationale: str


@dataclass(frozen=True)
class ReviewPacket:
    schema_version: int
    spec_packet_hash: str
    reviewer: AnalystIdentity
    overall_verdict: ReviewVerdict
    summary: str
    delta_reviews: list[DeltaReview]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def compute_content_hash(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "spec_packet_hash": self.spec_packet_hash,
            "reviewer": asdict(self.reviewer),
            "overall_verdict": self.overall_verdict.value,
            "summary": self.summary,
            "delta_reviews": [asdict(dr) for dr in self.delta_reviews],
        }
        return _content_hash(payload)


def _enum_value(enum_cls: type[Enum], raw: object, *, field: str) -> Enum:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} must be a non-empty string")
    try:
        return enum_cls(raw)  # type: ignore[call-arg]
    except ValueError as exc:
        allowed = [e.value for e in enum_cls]  # type: ignore[attr-defined]
        raise ValueError(f"{field} must be one of {allowed} (got {raw!r})") from exc


def analyst_identity_from_dict(doc: dict[str, Any]) -> AnalystIdentity:
    return AnalystIdentity(
        id=str(doc.get("id", "")),
        actor_type=_enum_value(DeltaSource, doc.get("actor_type"), field="analyst.actor_type"),  # type: ignore[arg-type]
        display_name=str(doc.get("display_name", "")),
    )


def evidence_ref_from_dict(doc: dict[str, Any]) -> EvidenceRef:
    refs = doc.get("refs") or []
    if not isinstance(refs, list):
        refs = []
    detail = doc.get("detail") if isinstance(doc.get("detail"), dict) else {}
    return EvidenceRef(
        id=str(doc.get("id", "")),
        kind=str(doc.get("kind", "")),
        summary=str(doc.get("summary", "")),
        refs=[str(r) for r in refs if isinstance(r, (str, int, float))],
        detail=detail,
    )


def hypothesis_from_dict(doc: dict[str, Any]) -> Hypothesis:
    ev_raw = doc.get("evidence") or []
    if not isinstance(ev_raw, list):
        ev_raw = []
    evidence = [evidence_ref_from_dict(e) for e in ev_raw if isinstance(e, dict)]
    return Hypothesis(
        id=str(doc.get("id", "")),
        spec_type=_enum_value(SpecType, doc.get("spec_type"), field="hypothesis.spec_type"),  # type: ignore[arg-type]
        name=str(doc.get("name", "")),
        confidence=float(doc.get("confidence", 0.0) or 0.0),
        description=str(doc.get("description", "") or ""),
        evidence=evidence,
    )


def annotation_delta_from_dict(doc: dict[str, Any]) -> AnnotationDelta:
    ev_ids = doc.get("evidence_link_ids") or []
    if not isinstance(ev_ids, list):
        ev_ids = []
    return AnnotationDelta(
        id=str(doc.get("id", "")),
        artifact_type=_enum_value(ArtifactType, doc.get("artifact_type"), field="delta.artifact_type"),  # type: ignore[arg-type]
        address=str(doc.get("address")) if doc.get("address") is not None else None,
        old_value=doc.get("old_value"),
        new_value=doc.get("new_value"),
        confidence=float(doc.get("confidence", 0.0) or 0.0),
        source=_enum_value(DeltaSource, doc.get("source"), field="delta.source"),  # type: ignore[arg-type]
        rationale=str(doc.get("rationale", "") or ""),
        evidence_link_ids=[str(eid) for eid in ev_ids if isinstance(eid, (str, int, float))],
    )


def annotation_changeset_from_dict(doc: dict[str, Any]) -> AnnotationChangeset:
    deltas_raw = doc.get("deltas") or []
    if not isinstance(deltas_raw, list):
        deltas_raw = []
    return AnnotationChangeset(
        id=str(doc.get("id", "")),
        author=analyst_identity_from_dict(doc.get("author") or {}),
        title=str(doc.get("title", "")),
        description=str(doc.get("description", "")),
        deltas=[annotation_delta_from_dict(d) for d in deltas_raw if isinstance(d, dict)],
    )


def spec_packet_from_dict(doc: dict[str, Any]) -> SpecPacket:
    hypotheses_raw = doc.get("hypotheses") or []
    if not isinstance(hypotheses_raw, list):
        hypotheses_raw = []
    changeset_raw = doc.get("changeset") if isinstance(doc.get("changeset"), dict) else {}
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    return SpecPacket(
        schema_version=int(doc.get("schema_version", 0) or 0),
        program_name=str(doc.get("program_name", "")),
        program_sha256=str(doc.get("program_sha256", "")),
        analysis_sha256=str(doc.get("analysis_sha256", "")),
        hypotheses=[hypothesis_from_dict(h) for h in hypotheses_raw if isinstance(h, dict)],
        changeset=annotation_changeset_from_dict(changeset_raw),
        metadata=metadata,
    )


def delta_review_from_dict(doc: dict[str, Any]) -> DeltaReview:
    return DeltaReview(
        delta_id=str(doc.get("delta_id", "")),
        action=_enum_value(ReviewAction, doc.get("action"), field="delta_review.action"),  # type: ignore[arg-type]
        rationale=str(doc.get("rationale", "")),
    )


def review_packet_from_dict(doc: dict[str, Any]) -> ReviewPacket:
    reviews_raw = doc.get("delta_reviews") or []
    if not isinstance(reviews_raw, list):
        reviews_raw = []
    metadata = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    return ReviewPacket(
        schema_version=int(doc.get("schema_version", 0) or 0),
        spec_packet_hash=str(doc.get("spec_packet_hash", "")),
        reviewer=analyst_identity_from_dict(doc.get("reviewer") or {}),
        overall_verdict=_enum_value(ReviewVerdict, doc.get("overall_verdict"), field="review.overall_verdict"),  # type: ignore[arg-type]
        summary=str(doc.get("summary", "")),
        delta_reviews=[delta_review_from_dict(dr) for dr in reviews_raw if isinstance(dr, dict)],
        metadata=metadata,
    )
