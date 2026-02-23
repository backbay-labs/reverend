#!/usr/bin/env python3
"""Append-only receipt store with hash-chain integrity verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
ENTITY_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "static": re.compile(r"^evs_[a-z0-9][a-z0-9._:-]*$"),
    "dynamic": re.compile(r"^evd_[a-z0-9][a-z0-9._:-]*$"),
    "symbolic": re.compile(r"^evy_[a-z0-9][a-z0-9._:-]*$"),
    "taint": re.compile(r"^evt_[a-z0-9][a-z0-9._:-]*$"),
    "proposal": re.compile(r"^evp_[a-z0-9][a-z0-9._:-]*$"),
    "receipt": re.compile(r"^evr_[a-z0-9][a-z0-9._:-]*$"),
}
EDGE_CONTRACTS: dict[str, set[tuple[str, str]]] = {
    "supports": {
        ("static", "proposal"),
        ("dynamic", "proposal"),
        ("symbolic", "proposal"),
        ("taint", "proposal"),
        ("receipt", "proposal"),
    },
    "derived_from": {
        ("proposal", "static"),
        ("proposal", "dynamic"),
        ("proposal", "symbolic"),
        ("proposal", "taint"),
    },
    "corroborates": {
        ("static", "dynamic"),
        ("dynamic", "static"),
        ("symbolic", "taint"),
        ("taint", "symbolic"),
    },
    "supersedes": {
        ("proposal", "proposal"),
        ("receipt", "receipt"),
    },
}
RAW_SIGNAL_ENTITY_TYPES = frozenset({"static", "dynamic", "symbolic", "taint"})


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _required_string(value: Any, *, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"receipt missing required {field}")
    return normalized


def _validate_entity_id(entity_type: str, entity_id: str, *, field: str) -> None:
    pattern = ENTITY_ID_PATTERNS.get(entity_type)
    if pattern is None:
        allowed = ", ".join(sorted(ENTITY_ID_PATTERNS.keys()))
        raise ValueError(f"{field} has unsupported entity_type '{entity_type}' (allowed: {allowed})")
    if not pattern.match(entity_id):
        raise ValueError(f"{field} '{entity_id}' is invalid for entity_type '{entity_type}'")


def _validate_canonical_evidence_contract(item: Mapping[str, Any], *, index: int) -> None:
    canonical_present = any(
        key in item for key in ("entity_type", "entity_id", "entity_schema_version", "edge")
    )
    if not canonical_present:
        return

    entity_type = _required_string(item.get("entity_type"), field=f"evidence[{index}].entity_type")
    entity_id = _required_string(item.get("entity_id"), field=f"evidence[{index}].entity_id")
    _validate_entity_id(entity_type, entity_id, field=f"evidence[{index}].entity_id")

    version_raw = item.get("entity_schema_version")
    try:
        entity_schema_version = int(version_raw)
    except (TypeError, ValueError):
        raise ValueError(f"evidence[{index}].entity_schema_version must be an integer") from None
    if entity_schema_version != 1:
        raise ValueError(
            f"evidence[{index}].entity_schema_version '{version_raw}' is unsupported (expected 1)"
        )

    edge_raw = item.get("edge")
    if edge_raw is None:
        return
    if not isinstance(edge_raw, Mapping):
        raise ValueError(f"evidence[{index}].edge must be an object")

    edge_type = _required_string(edge_raw.get("edge_type"), field=f"evidence[{index}].edge.edge_type")
    target_entity_type = _required_string(
        edge_raw.get("target_entity_type"),
        field=f"evidence[{index}].edge.target_entity_type",
    )
    target_entity_id = _required_string(
        edge_raw.get("target_entity_id"),
        field=f"evidence[{index}].edge.target_entity_id",
    )
    _validate_entity_id(target_entity_type, target_entity_id, field=f"evidence[{index}].edge.target_entity_id")

    target_version_raw = edge_raw.get("target_entity_schema_version")
    try:
        target_entity_schema_version = int(target_version_raw)
    except (TypeError, ValueError):
        raise ValueError(f"evidence[{index}].edge.target_entity_schema_version must be an integer") from None
    if target_entity_schema_version != 1:
        raise ValueError(
            f"evidence[{index}].edge.target_entity_schema_version "
            f"'{target_version_raw}' is unsupported (expected 1)"
        )

    allowed_contracts = EDGE_CONTRACTS.get(edge_type)
    if allowed_contracts is None:
        allowed_edges = ", ".join(sorted(EDGE_CONTRACTS.keys()))
        raise ValueError(
            f"evidence[{index}].edge.edge_type '{edge_type}' is unsupported (allowed: {allowed_edges})"
        )

    pair = (entity_type, target_entity_type)
    if pair not in allowed_contracts:
        raise ValueError(
            f"evidence[{index}].edge '{edge_type}' does not allow "
            f"{entity_type} -> {target_entity_type}"
        )


def _validate_receipt_linkage(receipt: Mapping[str, Any]) -> None:
    actor_raw = receipt.get("actor")
    if not isinstance(actor_raw, Mapping):
        raise ValueError("receipt actor must be an object")
    _required_string(actor_raw.get("actor"), field="actor.actor")
    _required_string(actor_raw.get("actor_type"), field="actor.actor_type")

    _required_string(receipt.get("action"), field="action")

    target_raw = receipt.get("target")
    if not isinstance(target_raw, Mapping):
        raise ValueError("receipt target must be an object")
    _required_string(target_raw.get("target_type"), field="target.target_type")
    _required_string(target_raw.get("target_id"), field="target.target_id")

    evidence_raw = receipt.get("evidence")
    if not isinstance(evidence_raw, list):
        raise ValueError("receipt evidence must be an array")
    for idx, item in enumerate(evidence_raw):
        if not isinstance(item, Mapping):
            raise ValueError(f"receipt evidence[{idx}] must be an object")
        _required_string(item.get("evidence_type"), field=f"evidence[{idx}].evidence_type")
        source_type = str(item.get("source_type") or "").strip()
        source_id = str(item.get("source_id") or "").strip()
        if source_type and not source_id:
            raise ValueError(f"receipt evidence[{idx}] source_type requires source_id")
        if source_id and not source_type:
            raise ValueError(f"receipt evidence[{idx}] source_id requires source_type")
        _validate_canonical_evidence_contract(item, index=idx)


def compute_receipt_hash(receipt: Mapping[str, Any]) -> str:
    payload = dict(receipt)
    payload.pop("hash", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class ReceiptIntegrityIssue:
    index: int
    receipt_id: str | None
    reason: str


@dataclass(frozen=True)
class ReceiptIntegrityReport:
    ok: bool
    issues: tuple[ReceiptIntegrityIssue, ...]

    @property
    def issue_count(self) -> int:
        return len(self.issues)


@dataclass(frozen=True)
class ProvenanceChainIssue:
    proposal_id: str | None
    receipt_id: str | None
    reason: str


@dataclass(frozen=True)
class ProvenanceChainReport:
    ok: bool
    issues: tuple[ProvenanceChainIssue, ...]
    explainability_packet: Mapping[str, Any]

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "provenance_chain_verification_report",
            "ok": self.ok,
            "issue_count": self.issue_count,
            "issues": [
                {
                    "proposal_id": issue.proposal_id,
                    "receipt_id": issue.receipt_id,
                    "reason": issue.reason,
                }
                for issue in self.issues
            ],
            "explainability_packet": _json_copy(self.explainability_packet),
        }


class ReceiptStoreIntegrityError(ValueError):
    """Raised when receipt history fails integrity verification."""


class AppendOnlyViolationError(ValueError):
    """Raised when an append operation would mutate existing history."""


def verify_receipt_history(receipts: Sequence[Mapping[str, Any]]) -> ReceiptIntegrityReport:
    issues: list[ReceiptIntegrityIssue] = []
    previous_receipt_id: str | None = None
    previous_hash: str | None = None
    seen_ids: set[str] = set()

    for idx, receipt in enumerate(receipts):
        receipt_id_raw = receipt.get("receipt_id")
        receipt_id = str(receipt_id_raw).strip() if receipt_id_raw is not None else ""
        resolved_receipt_id = receipt_id or None

        if not receipt_id:
            issues.append(ReceiptIntegrityIssue(index=idx, receipt_id=None, reason="missing receipt_id"))
        elif receipt_id in seen_ids:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=receipt_id,
                    reason=f"duplicate receipt_id '{receipt_id}'",
                )
            )
        else:
            seen_ids.add(receipt_id)

        chain_raw = receipt.get("chain")
        if not isinstance(chain_raw, Mapping):
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason="missing chain object")
            )
            chain_raw = {}

        sequence_number_raw = chain_raw.get("sequence_number")
        try:
            sequence_number = int(sequence_number_raw)
        except (TypeError, ValueError):
            sequence_number = -1
        if sequence_number != idx:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=f"invalid sequence_number '{sequence_number_raw}' (expected {idx})",
                )
            )

        expected_previous_receipt_id = previous_receipt_id
        previous_receipt_id_raw = chain_raw.get("previous_receipt_id")
        resolved_previous_receipt_id = (
            str(previous_receipt_id_raw).strip() if previous_receipt_id_raw is not None else ""
        )
        expected_previous_receipt_id_norm = expected_previous_receipt_id or ""
        if resolved_previous_receipt_id != expected_previous_receipt_id_norm:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=(
                        "invalid previous_receipt_id "
                        f"'{resolved_previous_receipt_id or None}' "
                        f"(expected '{expected_previous_receipt_id or None}')"
                    ),
                )
            )

        expected_previous_hash = previous_hash
        previous_hash_raw = chain_raw.get("previous_hash")
        resolved_previous_hash = str(previous_hash_raw).strip() if previous_hash_raw is not None else ""
        expected_previous_hash_norm = expected_previous_hash or ""
        if resolved_previous_hash != expected_previous_hash_norm:
            issues.append(
                ReceiptIntegrityIssue(
                    index=idx,
                    receipt_id=resolved_receipt_id,
                    reason=(
                        f"invalid previous_hash '{resolved_previous_hash or None}' "
                        f"(expected '{expected_previous_hash or None}')"
                    ),
                )
            )

        receipt_hash = str(receipt.get("hash") or "").strip()
        if not HEX64_RE.match(receipt_hash):
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason="receipt hash must be hex64")
            )
        else:
            expected_hash = compute_receipt_hash(receipt)
            if receipt_hash != expected_hash:
                issues.append(
                    ReceiptIntegrityIssue(
                        index=idx,
                        receipt_id=resolved_receipt_id,
                        reason=f"receipt hash mismatch (expected '{expected_hash}')",
                    )
                )

        try:
            _validate_receipt_linkage(receipt)
        except ValueError as exc:
            issues.append(
                ReceiptIntegrityIssue(index=idx, receipt_id=resolved_receipt_id, reason=str(exc))
            )

        if receipt_id:
            previous_receipt_id = receipt_id
        if receipt_hash:
            previous_hash = receipt_hash

    return ReceiptIntegrityReport(ok=not issues, issues=tuple(issues))


def _extract_applied_proposal_id(receipt: Mapping[str, Any]) -> str:
    target_raw = receipt.get("target")
    if isinstance(target_raw, Mapping):
        target_type = str(target_raw.get("target_type") or "").strip().lower()
        target_id = str(target_raw.get("target_id") or "").strip()
        if target_type == "proposal" and target_id:
            return target_id

    metadata_raw = receipt.get("metadata")
    if isinstance(metadata_raw, Mapping):
        for key in ("applied_proposal_id", "proposal_id"):
            proposal_id = str(metadata_raw.get(key) or "").strip()
            if proposal_id:
                return proposal_id
    return ""


def _oriented_provenance_edges(item: Mapping[str, Any]) -> tuple[tuple[tuple[str, str], tuple[str, str], str], ...]:
    source_entity_type = str(item.get("entity_type") or "").strip()
    source_entity_id = str(item.get("entity_id") or "").strip()
    edge_raw = item.get("edge")
    if not source_entity_type or not source_entity_id or not isinstance(edge_raw, Mapping):
        return ()

    edge_type = str(edge_raw.get("edge_type") or "").strip()
    target_entity_type = str(edge_raw.get("target_entity_type") or "").strip()
    target_entity_id = str(edge_raw.get("target_entity_id") or "").strip()
    if not edge_type or not target_entity_type or not target_entity_id:
        return ()

    source = (source_entity_type, source_entity_id)
    target = (target_entity_type, target_entity_id)

    if edge_type == "derived_from":
        return ((target, source, edge_type),)
    if edge_type == "corroborates":
        return (
            (source, target, edge_type),
            (target, source, edge_type),
        )
    return ((source, target, edge_type),)


def _resolve_canonical_signal_chain(
    *,
    raw_signal_nodes: set[tuple[str, str]],
    proposal_node: tuple[str, str],
    adjacency: Mapping[tuple[str, str], Sequence[tuple[tuple[str, str], str]]],
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]] | None:
    if not raw_signal_nodes:
        return None

    queue: deque[tuple[str, str]] = deque(sorted(raw_signal_nodes))
    parents: dict[tuple[str, str], tuple[str, str] | None] = {node: None for node in raw_signal_nodes}
    inbound_edges: dict[tuple[str, str], str] = {}

    while queue:
        node = queue.popleft()
        if node == proposal_node:
            break
        neighbors = sorted(
            adjacency.get(node, ()),
            key=lambda item: (item[0][0], item[0][1], item[1]),
        )
        for next_node, edge_type in neighbors:
            if next_node in parents:
                continue
            parents[next_node] = node
            inbound_edges[next_node] = edge_type
            queue.append(next_node)

    if proposal_node not in parents:
        return None

    nodes: list[tuple[str, str]] = []
    edges: list[str] = []
    cursor = proposal_node
    while True:
        nodes.append(cursor)
        parent = parents[cursor]
        if parent is None:
            break
        edges.append(inbound_edges[cursor])
        cursor = parent

    nodes.reverse()
    edges.reverse()
    return (tuple(nodes), tuple(edges))


def _build_canonical_explainability_chain(
    *,
    path_nodes: Sequence[tuple[str, str]],
    path_edges: Sequence[str],
    proposal_id: str,
    receipt: Mapping[str, Any],
) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for idx, node in enumerate(path_nodes):
        entry: dict[str, Any] = {
            "step_index": idx,
            "kind": "entity",
            "entity_type": node[0],
            "entity_id": node[1],
        }
        if idx > 0:
            entry["edge_type"] = path_edges[idx - 1]
        chain.append(entry)

    chain_raw = receipt.get("chain")
    if isinstance(chain_raw, Mapping):
        sequence_number = chain_raw.get("sequence_number")
        previous_receipt_id = chain_raw.get("previous_receipt_id")
    else:
        sequence_number = None
        previous_receipt_id = None

    receipt_id = str(receipt.get("receipt_id") or "").strip()
    receipt_step: dict[str, Any] = {
        "step_index": len(chain),
        "kind": "receipt",
        "receipt_id": receipt_id,
        "link_type": "APPLIED_BY_RECEIPT",
    }
    if sequence_number is not None:
        receipt_step["sequence_number"] = sequence_number
    if previous_receipt_id is not None:
        receipt_step["previous_receipt_id"] = previous_receipt_id
    chain.append(receipt_step)

    target_raw = receipt.get("target")
    if isinstance(target_raw, Mapping):
        target_type = str(target_raw.get("target_type") or "").strip()
        target_id = str(target_raw.get("target_id") or "").strip()
        if target_type and target_id:
            if target_type.lower() != "proposal" or target_id != proposal_id:
                chain.append(
                    {
                        "step_index": len(chain),
                        "kind": "annotation",
                        "target_type": target_type,
                        "target_id": target_id,
                        "link_type": "APPLIES_ANNOTATION",
                    }
                )

    return chain


def verify_provenance_chain(receipts: Sequence[Mapping[str, Any]]) -> ProvenanceChainReport:
    issues: list[ProvenanceChainIssue] = []
    integrity_report = verify_receipt_history(receipts)
    if not integrity_report.ok:
        for issue in integrity_report.issues:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=None,
                    receipt_id=issue.receipt_id,
                    reason=f"receipt_integrity: {issue.reason}",
                )
            )

    explainability_by_proposal: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        proposal_id = _extract_applied_proposal_id(receipt)
        if not proposal_id:
            continue

        receipt_id = str(receipt.get("receipt_id") or "").strip() or None
        try:
            _validate_entity_id("proposal", proposal_id, field="proposal_id")
        except ValueError as exc:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason=str(exc),
                )
            )
            continue

        chain_raw = receipt.get("chain")
        previous_receipt_id = (
            str(chain_raw.get("previous_receipt_id") or "").strip()
            if isinstance(chain_raw, Mapping)
            else ""
        )
        if not previous_receipt_id:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="applied proposal receipt is missing previous_receipt_id provenance link",
                )
            )

        evidence_raw = receipt.get("evidence")
        evidence_items = [item for item in evidence_raw if isinstance(item, Mapping)] if isinstance(evidence_raw, list) else []
        if not evidence_items:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="applied proposal receipt has no canonical evidence entries",
                )
            )
            continue

        raw_signal_nodes: set[tuple[str, str]] = set()
        seen_nodes: set[tuple[str, str]] = set()
        adjacency: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
        for item in evidence_items:
            source_entity_type = str(item.get("entity_type") or "").strip()
            source_entity_id = str(item.get("entity_id") or "").strip()
            if source_entity_type and source_entity_id:
                source = (source_entity_type, source_entity_id)
                seen_nodes.add(source)
                if source_entity_type in RAW_SIGNAL_ENTITY_TYPES:
                    raw_signal_nodes.add(source)

            edge_raw = item.get("edge")
            if isinstance(edge_raw, Mapping):
                target_entity_type = str(edge_raw.get("target_entity_type") or "").strip()
                target_entity_id = str(edge_raw.get("target_entity_id") or "").strip()
                if target_entity_type and target_entity_id:
                    target = (target_entity_type, target_entity_id)
                    seen_nodes.add(target)
                    if target_entity_type in RAW_SIGNAL_ENTITY_TYPES:
                        raw_signal_nodes.add(target)

            for src, dst, edge_type in _oriented_provenance_edges(item):
                adjacency.setdefault(src, []).append((dst, edge_type))

        proposal_node = ("proposal", proposal_id)
        if proposal_node not in seen_nodes:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="missing proposal evidence node in canonical evidence chain",
                )
            )
            continue
        if not raw_signal_nodes:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="missing raw-signal evidence chain to proposal",
                )
            )
            continue

        canonical_path = _resolve_canonical_signal_chain(
            raw_signal_nodes=raw_signal_nodes,
            proposal_node=proposal_node,
            adjacency=adjacency,
        )
        if canonical_path is None:
            issues.append(
                ProvenanceChainIssue(
                    proposal_id=proposal_id,
                    receipt_id=receipt_id,
                    reason="no canonical provenance path from raw signals to applied proposal",
                )
            )
            continue

        path_nodes, path_edges = canonical_path
        explainability_by_proposal[proposal_id] = {
            "proposal_id": proposal_id,
            "applied_receipt_id": receipt_id,
            "canonical_chain": _build_canonical_explainability_chain(
                path_nodes=path_nodes,
                path_edges=path_edges,
                proposal_id=proposal_id,
                receipt=receipt,
            ),
        }

    explainability_packet = {
        "schema_version": 1,
        "kind": "applied_proposal_explainability_packet",
        "generated_at_utc": _utc_now(),
        "applied_proposals": [
            _json_copy(explainability_by_proposal[proposal_id])
            for proposal_id in sorted(explainability_by_proposal)
        ],
    }

    return ProvenanceChainReport(
        ok=not issues,
        issues=tuple(issues),
        explainability_packet=explainability_packet,
    )


class ReceiptStore:
    """JSON-backed append-only receipt store."""

    def __init__(self, path: Path):
        self._path = path
        self._loaded = False
        self._doc: dict[str, Any] = {}

    def append(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(receipt, Mapping):
            raise ValueError("receipt must be a JSON object")

        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")

        report = verify_receipt_history(history)
        if not report.ok:
            first_issue = report.issues[0]
            raise ReceiptStoreIntegrityError(
                "receipt history integrity check failed before append: "
                f"index={first_issue.index} reason={first_issue.reason}"
            )

        receipt_id = _required_string(receipt.get("receipt_id"), field="receipt_id")
        if any(str(item.get("receipt_id") or "").strip() == receipt_id for item in history):
            raise AppendOnlyViolationError(f"receipt_id '{receipt_id}' already exists")

        _validate_receipt_linkage(receipt)

        previous_receipt_id: str | None = None
        previous_hash: str | None = None
        if history:
            previous = history[-1]
            previous_receipt_id = _required_string(previous.get("receipt_id"), field="receipt_id")
            previous_hash = _required_string(previous.get("hash"), field="hash")

        expected_chain = {
            "sequence_number": len(history),
            "previous_receipt_id": previous_receipt_id,
            "previous_hash": previous_hash,
        }
        provided_chain = receipt.get("chain")
        if provided_chain is not None:
            if not isinstance(provided_chain, Mapping):
                raise ValueError("receipt chain must be an object")
            for key, expected_value in expected_chain.items():
                provided_value = provided_chain.get(key)
                normalized_provided = str(provided_value).strip() if provided_value is not None else None
                normalized_expected = str(expected_value).strip() if expected_value is not None else None
                if key == "sequence_number":
                    try:
                        provided_sequence = int(provided_value)
                    except (TypeError, ValueError):
                        raise ValueError("receipt chain sequence_number must be an integer") from None
                    try:
                        expected_sequence = int(expected_value)
                    except (TypeError, ValueError):
                        raise ValueError("internal receipt chain sequence_number is invalid") from None
                    if provided_sequence != expected_sequence:
                        raise ValueError(
                            f"receipt chain sequence_number '{provided_value}' "
                            f"does not match expected '{expected_value}'"
                        )
                elif normalized_provided != normalized_expected:
                    raise ValueError(
                        f"receipt chain {key} '{provided_value}' does not match expected '{expected_value}'"
                    )

        stored = _json_copy(receipt)
        if not isinstance(stored, dict):
            raise ValueError("receipt must encode as a JSON object")

        stored["receipt_id"] = receipt_id
        stored["timestamp"] = _required_string(stored.get("timestamp") or _utc_now(), field="timestamp")
        stored["chain"] = expected_chain

        expected_hash = compute_receipt_hash(stored)
        provided_hash = str(receipt.get("hash") or "").strip()
        if provided_hash and provided_hash != expected_hash:
            raise ValueError("provided receipt hash does not match canonical hash")
        stored["hash"] = expected_hash

        history.append(stored)
        self._flush()
        return _json_copy(stored)

    def list_receipts(self) -> tuple[Mapping[str, Any], ...]:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        return tuple(_json_copy(item) for item in history if isinstance(item, Mapping))

    def verify_integrity(self) -> ReceiptIntegrityReport:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        normalized: list[Mapping[str, Any]] = []
        for idx, item in enumerate(history):
            if not isinstance(item, Mapping):
                return ReceiptIntegrityReport(
                    ok=False,
                    issues=(
                        ReceiptIntegrityIssue(
                            index=idx,
                            receipt_id=None,
                            reason="receipt entry must be an object",
                        ),
                    ),
                )
            normalized.append(item)
        return verify_receipt_history(normalized)

    def verify_provenance(self) -> ProvenanceChainReport:
        self._ensure_loaded()
        history = self._doc["receipts"]
        if not isinstance(history, list):
            raise ValueError("receipt store 'receipts' must be an array")
        normalized: list[Mapping[str, Any]] = []
        for idx, item in enumerate(history):
            if not isinstance(item, Mapping):
                return ProvenanceChainReport(
                    ok=False,
                    issues=(
                        ProvenanceChainIssue(
                            proposal_id=None,
                            receipt_id=None,
                            reason=f"receipt entry at index {idx} must be an object",
                        ),
                    ),
                    explainability_packet={
                        "schema_version": 1,
                        "kind": "applied_proposal_explainability_packet",
                        "generated_at_utc": _utc_now(),
                        "applied_proposals": [],
                    },
                )
            normalized.append(item)
        return verify_provenance_chain(normalized)

    def build_explainability_packet(self) -> Mapping[str, Any]:
        report = self.verify_provenance()
        return _json_copy(report.explainability_packet)

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        if not self._path.exists():
            self._doc = {
                "schema_version": 1,
                "kind": "receipt_store",
                "receipts": [],
            }
            self._loaded = True
            return

        raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("receipt store file must be a JSON object")
        receipts = raw.get("receipts")
        if receipts is None:
            raw["receipts"] = []
        elif not isinstance(receipts, list):
            raise ValueError("receipt store 'receipts' must be an array")
        self._doc = raw
        self._loaded = True

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._path)


def _verify_provenance_command(args: argparse.Namespace) -> int:
    store = ReceiptStore(args.store)
    report = store.verify_provenance()
    payload = report.as_dict()
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if report.ok else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Receipt-store provenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify-provenance",
        help="Verify applied-proposal provenance links and emit explainability packet JSON",
    )
    verify_parser.add_argument(
        "--store",
        type=Path,
        required=True,
        help="Path to receipt store JSON file",
    )
    verify_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write machine-readable verifier report JSON",
    )
    verify_parser.set_defaults(func=_verify_provenance_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
