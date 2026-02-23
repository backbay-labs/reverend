#!/usr/bin/env python3
"""Append-only receipt store with hash-chain integrity verification."""

from __future__ import annotations

import hashlib
import json
import re
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
