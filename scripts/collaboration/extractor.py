from __future__ import annotations

import json
from dataclasses import asdict
from hashlib import sha256
from typing import Any

from .models import (
    AnnotationChangeset,
    AnnotationDelta,
    ArtifactType,
    AnalystIdentity,
    DeltaSource,
    EvidenceRef,
    Hypothesis,
    SpecPacket,
    SpecType,
)


def _sha256_text(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _stable_evidence_id(kind: str, summary: str, refs: list[str]) -> str:
    material = {"kind": kind, "summary": summary, "refs": sorted(refs)}
    return "ev-" + sha256(json.dumps(material, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _stable_changeset_id(program_sha256: str) -> str:
    return "cs-" + sha256(f"spec-extract:{program_sha256}".encode("utf-8")).hexdigest()[:16]


def _stable_delta_id(hypothesis_id: str) -> str:
    return "delta-" + hypothesis_id


def _schema_hypotheses(doc: dict[str, Any]) -> list[tuple[Hypothesis, AnnotationDelta]]:
    results: list[tuple[Hypothesis, AnnotationDelta]] = []
    for entry in doc.get("data_types") or []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        hid = f"schema-{name.lower()}"

        fields = entry.get("fields") or []
        field_names = [str(f.get("name", "")).strip() for f in fields if str(f.get("name", "")).strip()]
        source_addresses = sorted({str(a) for a in (entry.get("source_addresses") or []) if str(a).strip()})
        evidence = [
            EvidenceRef(
                id=_stable_evidence_id("datatype", f"struct {name}", source_addresses),
                kind="datatype",
                summary=f"Struct definition for {name}",
                refs=source_addresses,
                detail={"fields": field_names, "size": entry.get("size"), "category": entry.get("category")},
            )
        ]

        hypothesis = Hypothesis(
            id=hid,
            spec_type=SpecType.SCHEMA,
            name=name,
            confidence=0.95,
            description=f"Recovered struct schema for `{name}` with {len(field_names)} fields.",
            evidence=evidence,
        )

        delta = AnnotationDelta(
            id=_stable_delta_id(hid),
            artifact_type=ArtifactType.DATA_TYPE,
            address=source_addresses[0] if source_addresses else None,
            old_value=None,
            new_value={
                "name": name,
                "kind": "struct",
                "fields": field_names,
                "definition": entry,
            },
            confidence=hypothesis.confidence,
            source=DeltaSource.SCRIPT,
            rationale="Data type entry present in analysis output with source addresses.",
            evidence_link_ids=[ev.id for ev in evidence],
        )
        results.append((hypothesis, delta))
    return results


def _api_hypotheses(doc: dict[str, Any]) -> list[tuple[Hypothesis, AnnotationDelta]]:
    results: list[tuple[Hypothesis, AnnotationDelta]] = []
    functions = {str(fn.get("address")): fn for fn in (doc.get("functions") or []) if fn.get("address")}
    for exp in doc.get("exports") or []:
        name = str(exp.get("name", "")).strip()
        address = str(exp.get("address", "")).strip() or None
        if not name or not address:
            continue

        hid = "api-" + name.replace("_", "-")
        fn = functions.get(address) or {}
        signature = fn.get("signature") or ""
        callers = sorted({str(a) for a in (fn.get("callers") or []) if str(a).strip()})

        refs = [address, *callers]
        evidence = [
            EvidenceRef(
                id=_stable_evidence_id("export", f"export {name}", refs),
                kind="export",
                summary=f"Exported function `{name}` at {address}",
                refs=sorted({r for r in refs if r}),
                detail={"signature": signature},
            )
        ]

        hypothesis = Hypothesis(
            id=hid,
            spec_type=SpecType.API,
            name=name,
            confidence=0.9,
            description=f"Exported API surface `{name}` with recovered signature.",
            evidence=evidence,
        )

        delta = AnnotationDelta(
            id=_stable_delta_id(hid),
            artifact_type=ArtifactType.FUNCTION_SIG,
            address=address,
            old_value=None,
            new_value={
                "name": name,
                "address": address,
                "signature": signature,
            },
            confidence=hypothesis.confidence,
            source=DeltaSource.SCRIPT,
            rationale="Function is exported; signature provided by analysis output.",
            evidence_link_ids=[ev.id for ev in evidence],
        )
        results.append((hypothesis, delta))
    return results


def _state_machine_hypotheses(doc: dict[str, Any]) -> list[tuple[Hypothesis, AnnotationDelta]]:
    functions = doc.get("functions") or []
    handler_fns = [fn for fn in functions if str(fn.get("name", "")).startswith("handle_")]
    if len(handler_fns) < 2:
        return []

    entry_points = sorted({str(a) for a in (doc.get("entry_points") or []) if str(a).strip()})
    refs = entry_points[:1] or [str(handler_fns[0].get("address", "")).strip()]
    refs = [r for r in refs if r]

    evidence = [
        EvidenceRef(
            id=_stable_evidence_id("callgraph", "handler call chain", refs),
            kind="callgraph",
            summary="Handler functions appear chained via calls; may indicate a request lifecycle.",
            refs=sorted(refs),
            detail={
                "handlers": sorted({str(fn.get("name")) for fn in handler_fns if fn.get("name")}),
                "entry_points": entry_points,
            },
        )
    ]

    hid = "state-machine-handlers"
    hypothesis = Hypothesis(
        id=hid,
        spec_type=SpecType.STATE_MACHINE,
        name="handlers",
        confidence=0.4,
        description="Potential request-handling lifecycle inferred from handler naming and call edges (low confidence).",
        evidence=evidence,
    )

    delta = AnnotationDelta(
        id=_stable_delta_id(hid),
        artifact_type=ArtifactType.BOOKMARK,
        address=refs[0] if refs else None,
        old_value=None,
        new_value={
            "name": "STATE_MACHINE_CANDIDATE",
            "handlers": sorted({str(fn.get("name")) for fn in handler_fns if fn.get("name")}),
        },
        confidence=hypothesis.confidence,
        source=DeltaSource.SCRIPT,
        rationale="Heuristic inference from handler naming; requires analyst confirmation.",
        evidence_link_ids=[ev.id for ev in evidence],
    )

    return [(hypothesis, delta)]


def extract_from_doc(doc: dict[str, Any], reviewer: AnalystIdentity) -> SpecPacket:
    """Extract a versioned spec packet from analysis doc.

    Deterministic: stable ids, stable ordering, and no wall-clock timestamps.
    """
    program_name = str(doc.get("program_name", "")).strip() or "unknown_program"
    program_sha256 = str(doc.get("program_sha256", "")).strip() or _sha256_text(program_name)
    analysis_sha256 = _sha256_text(json.dumps(doc, sort_keys=True))

    pairs: list[tuple[Hypothesis, AnnotationDelta]] = []
    pairs.extend(_schema_hypotheses(doc))
    pairs.extend(_api_hypotheses(doc))
    pairs.extend(_state_machine_hypotheses(doc))

    pairs.sort(key=lambda pair: (pair[0].spec_type.value, pair[0].id))
    hypotheses = [h for h, _ in pairs]
    deltas = [d for _, d in pairs]

    changeset = AnnotationChangeset(
        id=_stable_changeset_id(program_sha256),
        author=reviewer,
        title=f"Spec extraction for {program_name}",
        description="Automatically extracted spec hypotheses with evidence links.",
        deltas=deltas,
    )

    return SpecPacket(
        schema_version=1,
        program_name=program_name,
        program_sha256=program_sha256,
        analysis_sha256=analysis_sha256,
        hypotheses=hypotheses,
        changeset=changeset,
        metadata={"extraction": "scripts/collaboration/extractor.extract_from_doc", "reviewer": asdict(reviewer)},
    )


def extract_from_json(analysis_json: str, reviewer: AnalystIdentity) -> SpecPacket:
    return extract_from_doc(json.loads(analysis_json), reviewer=reviewer)

